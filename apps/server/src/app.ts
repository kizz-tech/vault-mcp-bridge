import Fastify, { type FastifyInstance, type FastifyReply, type FastifyRequest } from "fastify";
import { z } from "zod";
import { assertSourceHash, PairDeviceRequestSchema, SnapshotSchema, OpaqueIdSchema, computeSnapshotDigest, canonicalSignedRequestPayload, sha256Base64Url } from "@vault-mcp-bridge/contracts";
import { assertProductionConfig, loadConfig, type ServerConfig } from "./config.js";
import { decodeEd25519PublicKey, generatePairingCode, verifyEd25519 } from "./crypto.js";
import { McpAuthenticator, McpEdgeAttestor, enforceHostAndOrigin, protectedResourceMetadata, PrincipalGuard, PublisherEdgeAttestor, sendAuthError } from "./auth.js";
import { createMcpHandler, type McpHandler } from "./mcp.js";
import { PairingError, SnapshotError, VaultStore } from "./store.js";
import type { PairingConsumeInput, Snapshot, SnapshotUploadEnvelope } from "./types.js";

const pairingSchema = PairDeviceRequestSchema;

const snapshotSchema = SnapshotSchema;

const uploadSchema = z.object({
  deviceId: OpaqueIdSchema,
  vaultId: OpaqueIdSchema,
  timestamp: z.number().int(),
  nonce: z.string().regex(/^[A-Za-z0-9._~-]{16,128}$/u),
  signature: z.string().regex(/^[A-Za-z0-9_-]{80,128}$/u),
  snapshot: snapshotSchema,
});

const statusSchema = z.object({
  deviceId: OpaqueIdSchema,
  vaultId: OpaqueIdSchema,
  timestamp: z.number().int(),
  nonce: z.string().regex(/^[A-Za-z0-9._~-]{16,128}$/u),
  signature: z.string().regex(/^[A-Za-z0-9_-]{80,128}$/u),
});

const bodyAsObject = (request: FastifyRequest): unknown => request.body && typeof request.body === "object" ? request.body : {};

const bodyBytes = (value: unknown): number => Buffer.byteLength(JSON.stringify(value), "utf8");

const isDateWithinSkew = (timestamp: number, skewSeconds: number): boolean => Math.abs(Math.floor(Date.now() / 1000) - timestamp) <= skewSeconds;

const verifyPublisherRequest = (store: VaultStore, config: ServerConfig, input: { deviceId: string; vaultId: string; timestamp: number; nonce: string; signature: string }, method: string, path: string, digest: string): { statusCode: number; message: string } | null => {
  if (!isDateWithinSkew(input.timestamp, config.maxClockSkewSeconds)) return { statusCode: 401, message: "publisher authentication failed" };
  const device = store.getDevice(input.deviceId);
  if (!device || device.revokedAt !== null || device.vaultId !== input.vaultId) return { statusCode: 403, message: "publisher authentication failed" };
  try {
    const publicKey = decodeEd25519PublicKey(device.publicKey.toString("base64url"));
    const signedPayload = canonicalSignedRequestPayload({ method, path, timestamp: input.timestamp, nonce: input.nonce, digest });
    if (!verifyEd25519(signedPayload, input.signature, publicKey)) return { statusCode: 401, message: "publisher authentication failed" };
    if (!store.consumeNonce(input.deviceId, input.nonce)) return { statusCode: 409, message: "publisher request replayed" };
    return null;
  } catch {
    return { statusCode: 401, message: "publisher authentication failed" };
  }
};

const validateSnapshot = (snapshot: Snapshot, config: ServerConfig): void => {
  const bytes = bodyBytes(snapshot);
  if (bytes > config.maxSnapshotBytes) throw new SnapshotError("snapshot exceeds body limit", 413);
  const seen = new Set<string>();
  for (const document of snapshot.documents) {
    if (seen.has(document.id)) throw new SnapshotError("snapshot contains duplicate document id", 400);
    seen.add(document.id);
    if (Buffer.byteLength(document.text, "utf8") > config.maxDocumentBytes) throw new SnapshotError("document exceeds size limit", 413);
    try { assertSourceHash(document); } catch { throw new SnapshotError("document source hash mismatch", 400); }
    if (document.metadata && Buffer.byteLength(JSON.stringify(document.metadata), "utf8") > 64 * 1024) throw new SnapshotError("document metadata exceeds size limit", 413);
  }
  if (computeSnapshotDigest(snapshot) !== snapshot.digest) throw new SnapshotError("snapshot digest mismatch", 400);
}

export type VaultBridgeApp = {
  app: FastifyInstance;
  store: VaultStore;
  config: ServerConfig;
  close: () => Promise<void>;
};

export type CreateAppOptions = {
  config?: ServerConfig;
  store?: VaultStore;
  mcpHandler?: McpHandler;
};

export const createApp = async (options: CreateAppOptions = {}): Promise<VaultBridgeApp> => {
  const config = options.config ?? loadConfig();
  assertProductionConfig(config);
  const storageLimits = {
    maxVaultBytes: config.maxVaultBytes,
    maxDatabaseBytes: config.maxDatabaseBytes,
    maxIndexBytes: config.maxIndexBytes,
    maxTempBytes: config.maxTempBytes,
    minFreeBytes: config.minFreeBytes,
    maxRetainedGenerations: config.maxRetainedGenerations,
  };
  const store = options.store ?? new VaultStore(config.databasePath, config.nonceRetentionSeconds, storageLimits);
  store.configureStorageLimits(storageLimits);
  if (config.maxClockSkewSeconds >= store.nonceRetentionSeconds) throw new Error("MAX_CLOCK_SKEW_SECONDS must be below store nonce retention");
  const fastify = Fastify({ bodyLimit: config.maxBodyBytes, logger: false, requestTimeout: config.maxRequestSeconds * 1000 });
  const authenticator = new McpAuthenticator(config);
  const mcpEdgeAttestor = new McpEdgeAttestor(config);
  const publisherAttestor = new PublisherEdgeAttestor(config);
  const guard = new PrincipalGuard(config);
  const mcpHandler = options.mcpHandler ?? await createMcpHandler(store, config);

  fastify.setErrorHandler((error, _request, reply) => {
    const candidate = error as { statusCode?: unknown };
    const statusCode = typeof candidate.statusCode === "number" && candidate.statusCode >= 400 && candidate.statusCode < 500 ? candidate.statusCode : 500;
    reply.code(statusCode).send({ error: statusCode === 500 ? "internal error" : "invalid request" });
  });

  fastify.addHook("onSend", async (_request, reply, payload) => {
    reply.header("cache-control", "no-store").header("x-content-type-options", "nosniff").header("referrer-policy", "no-referrer");
    return payload;
  });

  fastify.addHook("onRequest", async (request, reply) => {
    const hostError = enforceHostAndOrigin(request, config);
    if (hostError) return reply.code(hostError.statusCode).send({ error: hostError.message });
  });

  const publisherGuard = async (request: FastifyRequest, reply: FastifyReply): Promise<void> => {
    const hostError = enforceHostAndOrigin(request, config, config.publisherHosts);
    if (hostError) {
      await reply.code(hostError.statusCode).send({ error: hostError.message });
      return;
    }
    if (config.publisherIngestDisabled) {
      await reply.code(503).send({ error: "publisher ingest is disabled" });
      return;
    }
    if (!publisherAttestor.verify(request)) await reply.code(401).send({ error: "publisher authentication failed" });
  };

  fastify.get("/healthz", async () => ({ ok: true }));
  fastify.get("/readyz", async (_request, reply) => {
    const storageReadiness = store.readiness();
    if (!storageReadiness.ok || !authenticator.readiness().ok) return reply.code(503).send({ ok: false });
    return { ok: true };
  });

  fastify.post("/v1/pairing/consume", { preHandler: publisherGuard }, async (request, reply) => {
    const parsed = pairingSchema.safeParse(bodyAsObject(request));
    if (!parsed.success) return reply.code(400).send({ error: "invalid pairing request" });
    try {
      decodeEd25519PublicKey(parsed.data.publicKey);
      const input: PairingConsumeInput = parsed.data;
      const result = store.consumePairingCodeResult(input);
      const protocol = request.headers["x-forwarded-proto"] === "https" ? "https" : "http";
      const serverUrl = config.publisherPublicUrl ?? `${protocol}://${request.headers.host ?? "127.0.0.1"}`;
      return reply.code(result.idempotent ? 200 : 201).send({ version: 1, deviceId: result.device.deviceId, vaultId: result.device.vaultId, serverUrl, expiresAt: null });
    } catch (error) {
      if (error instanceof PairingError) return reply.code(error.statusCode).send({ error: error.message });
      return reply.code(400).send({ error: "invalid pairing request" });
    }
  });

  fastify.post("/v1/snapshots", { preHandler: publisherGuard }, async (request, reply) => {
    const parsed = uploadSchema.safeParse(bodyAsObject(request));
    if (!parsed.success) return reply.code(400).send({ error: "invalid snapshot request" });
    const envelope = parsed.data as SnapshotUploadEnvelope;
    if (envelope.snapshot.vaultId !== envelope.vaultId) return reply.code(403).send({ error: "vault is not allowed" });
    try {
      const authError = verifyPublisherRequest(store, config, envelope, "POST", "/v1/snapshots", envelope.snapshot.digest);
      if (authError) return reply.code(authError.statusCode).send({ error: authError.message });
      validateSnapshot(envelope.snapshot, config);
      const result = store.activateSnapshot(envelope.snapshot, envelope.deviceId);
      return reply.code(result.idempotent ? 200 : 202).send({
        version: 1,
        accepted: result.accepted,
        idempotent: result.idempotent,
        snapshotId: result.snapshotId,
        vaultId: result.vaultId,
        generation: result.generation,
        documentCount: result.documentCount,
        digest: result.digest,
        receivedAt: new Date(result.receivedAt * 1000).toISOString(),
      });
    } catch (error) {
      if (error instanceof SnapshotError) return reply.code(error.statusCode).send({ error: error.message });
      return reply.code(400).send({ error: "invalid snapshot request" });
    }
  });

  fastify.get("/v1/status", { preHandler: publisherGuard }, async (request, reply) => {
    const queryVaultId = typeof request.query === "object" && request.query !== null && "vaultId" in request.query ? String((request.query as Record<string, unknown>).vaultId) : "";
    const parsed = statusSchema.safeParse({
      deviceId: request.headers["x-bridge-device-id"],
      vaultId: request.headers["x-bridge-vault-id"],
      timestamp: Number(request.headers["x-bridge-timestamp"]),
      nonce: request.headers["x-bridge-nonce"],
      signature: request.headers["x-bridge-signature"],
    });
    if (!parsed.success || parsed.data.vaultId !== queryVaultId) return reply.code(401).send({ error: "publisher authentication failed" });
    const authError = verifyPublisherRequest(store, config, parsed.data, "GET", "/v1/status", sha256Base64Url(parsed.data.vaultId));
    if (authError) return reply.code(authError.statusCode).send({ error: authError.message });
    return { vaultId: parsed.data.vaultId, ...store.status(parsed.data.vaultId) };
  });

  const mcpGuard = async (request: FastifyRequest, reply: FastifyReply): Promise<boolean> => {
    const hostError = enforceHostAndOrigin(request, config, config.mcpHosts);
    if (hostError) {
      await reply.code(hostError.statusCode).send({ error: hostError.message });
      return false;
    }
    if (config.mcpReadsDisabled) {
      await reply.code(503).send({ error: "MCP reads are disabled" });
      return false;
    }
    if (!mcpEdgeAttestor.verify(request)) {
      await reply.code(401).send({ error: "MCP edge authentication failed" });
      return false;
    }
    const auth = await authenticator.authenticate(request);
    if (!("principal" in auth)) {
      sendAuthError(reply, auth);
      return false;
    }
    const guardKey = [auth.principal.subject, auth.principal.clientId ?? "", auth.principal.vaultId ?? config.mcpVaultId ?? ""].join(":");
    if (!guard.enter(guardKey)) {
      await reply.code(429).header("Retry-After", "1").send({ error: "rate limit exceeded" });
      return false;
    }
    (request as FastifyRequest & { mcpPrincipal?: string; mcpGuardKey?: string }).mcpPrincipal = auth.principal.subject;
    (request as FastifyRequest & { mcpPrincipal?: string; mcpGuardKey?: string }).mcpGuardKey = guardKey;
    return true;
  };

  fastify.get("/.well-known/oauth-protected-resource", async (request, reply) => {
    const hostError = enforceHostAndOrigin(request, config, config.mcpHosts);
    if (hostError) return reply.code(hostError.statusCode).send({ error: hostError.message });
    return protectedResourceMetadata(request, config);
  });
  fastify.get("/.well-known/oauth-protected-resource/mcp", async (request, reply) => {
    const hostError = enforceHostAndOrigin(request, config, config.mcpHosts);
    if (hostError) return reply.code(hostError.statusCode).send({ error: hostError.message });
    return protectedResourceMetadata(request, config);
  });
  fastify.post("/mcp", { preHandler: mcpGuard }, async (request, reply) => {
    try {
      await mcpHandler(request, reply);
    } finally {
      const context = request as FastifyRequest & { mcpPrincipal?: string; mcpGuardKey?: string };
      if (context.mcpPrincipal) guard.leave(context.mcpGuardKey ?? context.mcpPrincipal);
    }
  });

  return { app: fastify, store, config, close: async () => { await fastify.close(); if (!options.store) store.close(); } };
};

export const createPairingCode = (store: VaultStore, vaultId: string, ttlSeconds: number): ReturnType<VaultStore["createPairingCode"]> => {
  const code = generatePairingCode();
  return store.createPairingCode(vaultId, ttlSeconds, code);
};
