import { generateKeyPairSync, sign } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { SignJWT } from "jose";
import { afterAll, afterEach, describe, expect, it, vi } from "vitest";
import { canonicalSignedRequestPayload } from "@vault-mcp-bridge/contracts";
import { createApp } from "../src/app.js";
import { loadConfig, assertConfigSafety, assertProductionConfig } from "../src/config.js";
import { PrincipalGuard, mcpEdgeAttestationForRequest, publisherEdgeAttestationForRequest } from "../src/auth.js";
import { oauthSecuritySchemes } from "../src/mcp.js";
import { sha256Base64Url } from "@vault-mcp-bridge/contracts";
import { VaultStore } from "../src/store.js";
import type { Snapshot, SnapshotUploadEnvelope } from "../src/types.js";

const runtimes: Array<{ close: () => Promise<void> }> = [];
const mcpEdgeSecretDirectory = mkdtempSync(join(tmpdir(), "vault-mcp-bridge-mcp-edge-"));
const mcpEdgeAttestationSecretFile = join(mcpEdgeSecretDirectory, "mcp-edge-attestation");
const mcpEdgeSecret = "synthetic-mcp-edge-attestation-secret-1234567890";
writeFileSync(mcpEdgeAttestationSecretFile, mcpEdgeSecret, { mode: 0o600 });
afterEach(async () => {
  while (runtimes.length > 0) await runtimes.pop()?.close();
});
afterAll(() => rmSync(mcpEdgeSecretDirectory, { recursive: true, force: true }));

const config = (overrides: Record<string, string> = {}) => loadConfig({
  NODE_ENV: "test",
  SERVER_DATABASE_PATH: ":memory:",
  MCP_DEV_TOKEN: "test-token",
  ALLOWED_HOSTS: "localhost,127.0.0.1",
  ALLOWED_ORIGINS: "http://localhost:8787",
  ...overrides,
});

const mcpEdgeHeaders = (host: string, url: string, bearerToken: string, secret = mcpEdgeSecret) => mcpEdgeAttestationForRequest({ method: "POST", url, headers: { host } }, secret, bearerToken);

const makeSnapshot = (vaultId: string, generation = 1, digestOverride?: string): Snapshot => {
  const text = "# Synthetic note\n\nA private fixture.";
  const document = { id: "doc_opaque_00001", title: "Synthetic note", mediaType: "text/markdown" as const, text, sourceHash: sha256Base64Url(text), modifiedAt: new Date().toISOString() };
  const base = { version: 1 as const, snapshotId: `00000000-0000-4000-8000-00000000000${generation}`, vaultId, generation, createdAt: new Date().toISOString(), documents: [document] };
  return { ...base, digest: digestOverride ?? VaultStore.makeSnapshotDigest(base) };
};

const pair = async (runtime: Awaited<ReturnType<typeof createApp>>, code: string, vaultId: string) => {
  const keyPair = generateKeyPairSync("ed25519");
  const publicKey = keyPair.publicKey.export({ format: "der", type: "spki" }).toString("base64url");
  const response = await runtime.app.inject({ method: "POST", url: "/v1/pairing/consume", payload: { version: 1, pairCode: code, agentId: "device_test_00001", publicKey, vaultId } });
  expect(response.statusCode).toBe(201);
  return { privateKey: keyPair.privateKey, deviceId: "device_test_00001", vaultId };
};

const signedUpload = (deviceId: string, vaultId: string, privateKey: ReturnType<typeof generateKeyPairSync>["privateKey"], snapshot: Snapshot, nonce = "nonce_test_123456") => {
  const envelopeWithoutSignature = { deviceId, vaultId, timestamp: Math.floor(Date.now() / 1000), nonce, snapshot };
  const signedPayload = canonicalSignedRequestPayload({ method: "POST", path: "/v1/snapshots", timestamp: envelopeWithoutSignature.timestamp, nonce, digest: snapshot.digest });
  return { ...envelopeWithoutSignature, signature: sign(null, Buffer.from(signedPayload), privateKey).toString("base64url") } satisfies SnapshotUploadEnvelope;
};

const signedStatus = (deviceId: string, vaultId: string, privateKey: ReturnType<typeof generateKeyPairSync>["privateKey"], nonce = "nonce_status_123456") => {
  const timestamp = Math.floor(Date.now() / 1000);
  const signedPayload = canonicalSignedRequestPayload({ method: "GET", path: "/v1/status", timestamp, nonce, digest: sha256Base64Url(vaultId) });
  return {
    "x-bridge-device-id": deviceId,
    "x-bridge-vault-id": vaultId,
    "x-bridge-timestamp": String(timestamp),
    "x-bridge-nonce": nonce,
    "x-bridge-signature": sign(null, Buffer.from(signedPayload), privateKey).toString("base64url"),
  };
};

describe("read-only server", () => {
  it("keeps the SQLite in-memory sentinel in tests and rejects it in production", () => {
    expect(loadConfig({ NODE_ENV: "test", SERVER_DATABASE_PATH: ":memory:" }).databasePath).toBe(":memory:");
    expect(() => assertProductionConfig(loadConfig({ NODE_ENV: "production", SERVER_DATABASE_PATH: ":memory:" }))).toThrow(/durable/u);
  });

  it("consumes pairing codes once and rejects bad/replayed signatures", async () => {
    const store = new VaultStore(":memory:");
    const runtime = await createApp({ config: config(), store, mcpHandler: async (_request, reply) => { await reply.send({ ok: true }); } });
    runtimes.push(runtime);
    const pairing = store.createPairingCode("vault_test_0000001", 600, "pairing_code_test_123456789012345678901234567890");
    const device = await pair(runtime, pairing.code, "vault_test_0000001");
    const snapshot = makeSnapshot("vault_test_0000001");
    const upload = signedUpload(device.deviceId, device.vaultId, device.privateKey, snapshot);
    const alteredSignature = `${upload.signature[0] === "A" ? "B" : "A"}${upload.signature.slice(1)}`;
    const bad = await runtime.app.inject({ method: "POST", url: "/v1/snapshots", payload: { ...upload, signature: alteredSignature } });
    expect(bad.statusCode).toBe(401);
    const accepted = await runtime.app.inject({ method: "POST", url: "/v1/snapshots", payload: upload });
    expect(accepted.statusCode).toBe(202);
    const replay = await runtime.app.inject({ method: "POST", url: "/v1/snapshots", payload: upload });
    expect(replay.statusCode).toBe(409);
  });

  it("resumes a pairing retry for the same identity while preserving conflicts and one-use codes", async () => {
    const store = new VaultStore(":memory:");
    const runtime = await createApp({ config: config(), store, mcpHandler: async (_request, reply) => { await reply.send({ ok: true }); } });
    runtimes.push(runtime);
    const keyPair = generateKeyPairSync("ed25519");
    const publicKey = keyPair.publicKey.export({ format: "der", type: "spki" }).toString("base64url");
    const deviceId = "device_pair_retry_0001";
    const vaultId = "vault_test_0000001";
    const consume = (pairCode: string, key = publicKey) => runtime.app.inject({
      method: "POST",
      url: "/v1/pairing/consume",
      payload: { version: 1, pairCode, agentId: deviceId, publicKey: key, vaultId },
    });

    const firstCode = store.createPairingCode(vaultId, 600, "pairing_retry_first_123456789012345678901234567890");
    const first = await consume(firstCode.code);
    expect(first.statusCode).toBe(201);
    const firstReplay = await consume(firstCode.code);
    expect(firstReplay.statusCode).toBe(400);

    // The desktop may crash after this successful response and retry with a
    // new one-use code before it has committed its local pairing state.
    const retryCode = store.createPairingCode(vaultId, 600, "pairing_retry_second_123456789012345678901234567890");
    const retry = await consume(retryCode.code);
    expect(retry.statusCode).toBe(200);
    expect(retry.json()).toMatchObject({ version: 1, deviceId, vaultId });
    const retryReplay = await consume(retryCode.code);
    expect(retryReplay.statusCode).toBe(400);

    const otherKeyPair = generateKeyPairSync("ed25519");
    const otherPublicKey = otherKeyPair.publicKey.export({ format: "der", type: "spki" }).toString("base64url");
    const mismatchCode = store.createPairingCode(vaultId, 600, "pairing_retry_mismatch_123456789012345678901234567890");
    const mismatch = await consume(mismatchCode.code, otherPublicKey);
    expect(mismatch.statusCode).toBe(409);
  });

  it("keeps active snapshot untouched when digest validation fails and rejects revoked devices", async () => {
    const store = new VaultStore(":memory:");
    const runtime = await createApp({ config: config(), store, mcpHandler: async (_request, reply) => { await reply.send({ ok: true }); } });
    runtimes.push(runtime);
    const pairing = store.createPairingCode("vault_test_0000001", 600, "pairing_code_test_123456789012345678901234567891");
    const device = await pair(runtime, pairing.code, "vault_test_0000001");
    const invalid = makeSnapshot("vault_test_0000001", 1, "invalid_digest_123456789012345678901234567890");
    const invalidResponse = await runtime.app.inject({ method: "POST", url: "/v1/snapshots", payload: signedUpload(device.deviceId, device.vaultId, device.privateKey, invalid, "nonce_invalid_123456") });
    expect(invalidResponse.statusCode).toBe(400);
    expect(store.getActive("vault_test_0000001")).toBeNull();
    expect(store.revokeDevice(device.deviceId)).toBe(true);
    const rejected = await runtime.app.inject({ method: "POST", url: "/v1/snapshots", payload: signedUpload(device.deviceId, device.vaultId, device.privateKey, makeSnapshot("vault_test_0000001"), "nonce_revoked_123456") });
    expect(rejected.statusCode).toBe(403);
  });

  it("searches and fetches only active documents without returning source paths", async () => {
    const store = new VaultStore(":memory:");
    const runtime = await createApp({ config: config(), store, mcpHandler: async (_request, reply) => { await reply.send({ ok: true }); } });
    runtimes.push(runtime);
    const pairing = store.createPairingCode("vault_test_0000001", 600, "pairing_code_test_123456789012345678901234567892");
    const device = await pair(runtime, pairing.code, "vault_test_0000001");
    const uploaded = await runtime.app.inject({ method: "POST", url: "/v1/snapshots", payload: signedUpload(device.deviceId, device.vaultId, device.privateKey, makeSnapshot("vault_test_0000001")) });
    expect(uploaded.statusCode).toBe(202);
    const search = store.search("vault_test_0000001", "private", 20);
    expect(search.results).toHaveLength(1);
    expect(search.results[0]?.url).toBe("");
    const fetched = store.fetch("vault_test_0000001", "doc_opaque_00001", 512);
    expect(fetched?.text).toContain("Synthetic");
    expect(fetched?.url).not.toContain("private");
  });

  it("requires production JWT configuration and has an explicit read kill switch", async () => {
    expect(() => assertProductionConfig(loadConfig({ NODE_ENV: "production" }))).toThrow(/authentication is not configured/u);
    expect(() => assertProductionConfig(loadConfig({
      NODE_ENV: "production",
      ALLOWED_HOSTS: "mcp.example.invalid,ingest.example.invalid",
      MCP_HOSTS: "mcp.example.invalid",
      PUBLISHER_HOSTS: "ingest.example.invalid",
      MCP_RESOURCE_URL: "https://mcp.example.invalid/mcp",
      PUBLISHER_PUBLIC_URL: "https://ingest.example.invalid",
      MCP_VAULT_ID: "vault_test_0000001",
      MCP_INSTALLATION_ID: "install_test_000001",
      PUBLISHER_EDGE_ATTESTATION_SECRET: "synthetic-edge-attestation-secret-1234567890",
      MCP_EDGE_ATTESTATION_SECRET_FILE: mcpEdgeAttestationSecretFile,
      JWT_ISSUER: "https://issuer.example.invalid/",
      JWT_AUDIENCE: "vault-mcp-bridge",
      JWT_JWKS_URL: "https://issuer.example.invalid/.well-known/jwks.json",
    }))).toThrow(/JWT_JWKS_FILE/u);
    expect(() => assertProductionConfig(loadConfig({
      NODE_ENV: "production",
      ALLOWED_HOSTS: "127.0.0.1,mcp.example.invalid,ingest.example.invalid",
      MCP_HOSTS: "mcp.example.invalid",
      PUBLISHER_HOSTS: "ingest.example.invalid",
      MCP_RESOURCE_URL: "https://mcp.example.invalid/mcp",
      PUBLISHER_PUBLIC_URL: "https://ingest.example.invalid",
      MCP_VAULT_ID: "vault_test_0000001",
      MCP_INSTALLATION_ID: "install_test_000001",
      PUBLISHER_EDGE_ATTESTATION_SECRET: "synthetic-edge-attestation-secret-1234567890",
      MCP_EDGE_ATTESTATION_SECRET_FILE: mcpEdgeAttestationSecretFile,
      JWT_ISSUER: "https://issuer.example.invalid/",
      JWT_AUDIENCE: "vault-mcp-bridge",
      JWT_JWKS_URL: "https://issuer.example.invalid/.well-known/jwks.json",
      JWT_ALLOW_REMOTE_JWKS: "true",
    }))).not.toThrow();
    const store = new VaultStore(":memory:");
    const runtime = await createApp({ config: config({ MCP_READS_DISABLED: "true" }), store, mcpHandler: async (_request, reply) => { await reply.send({ ok: true }); } });
    runtimes.push(runtime);
    const response = await runtime.app.inject({ method: "POST", url: "/mcp", headers: { authorization: "Bearer test-token", host: "localhost" }, payload: { jsonrpc: "2.0", id: 1, method: "tools/list" } });
    expect(response.statusCode).toBe(503);
  });

  it("requires a signed, non-replayed device request for status", async () => {
    const store = new VaultStore(":memory:");
    const runtime = await createApp({ config: config(), store, mcpHandler: async (_request, reply) => { await reply.send({ ok: true }); } });
    runtimes.push(runtime);
    const pairing = store.createPairingCode("vault_test_0000001", 600, "pairing_code_test_123456789012345678901234567893");
    const device = await pair(runtime, pairing.code, "vault_test_0000001");
    const unsigned = await runtime.app.inject({ method: "GET", url: `/v1/status?vaultId=${device.vaultId}` });
    expect(unsigned.statusCode).toBe(401);
    const headers = signedStatus(device.deviceId, device.vaultId, device.privateKey);
    const accepted = await runtime.app.inject({ method: "GET", url: `/v1/status?vaultId=${device.vaultId}`, headers });
    expect(accepted.statusCode).toBe(200);
    expect(accepted.json()).toMatchObject({ vaultId: device.vaultId, active: null, documentCount: 0 });
    const replay = await runtime.app.inject({ method: "GET", url: `/v1/status?vaultId=${device.vaultId}`, headers });
    expect(replay.statusCode).toBe(409);
  });

  it("rejects unexpected hosts and browser origins before route handling", async () => {
    const store = new VaultStore(":memory:");
    const runtime = await createApp({ config: config(), store, mcpHandler: async (_request, reply) => { await reply.send({ ok: true }); } });
    runtimes.push(runtime);
    const badHost = await runtime.app.inject({ method: "GET", url: "/healthz", headers: { host: "evil.invalid" } });
    expect(badHost.statusCode).toBe(403);
    const badOrigin = await runtime.app.inject({ method: "GET", url: "/healthz", headers: { host: "localhost", origin: "https://evil.invalid" } });
    expect(badOrigin.statusCode).toBe(403);
  });

  it("advertises RFC 9728 metadata in the MCP bearer challenge", async () => {
    const store = new VaultStore(":memory:");
    const runtime = await createApp({ config: config(), store, mcpHandler: async (_request, reply) => { await reply.send({ ok: true }); } });
    runtimes.push(runtime);
    const unauthorized = await runtime.app.inject({ method: "POST", url: "/mcp", headers: { host: "localhost" }, payload: { jsonrpc: "2.0", id: 1, method: "tools/list" } });
    expect(unauthorized.statusCode).toBe(401);
    expect(unauthorized.headers["www-authenticate"]).toContain('resource_metadata="http://localhost/.well-known/oauth-protected-resource/mcp"');
    const metadata = await runtime.app.inject({ method: "GET", url: "/.well-known/oauth-protected-resource/mcp", headers: { host: "localhost" } });
    expect(metadata.statusCode).toBe(200);
    expect(metadata.json()).toMatchObject({ resource: "http://localhost/mcp", scopes_supported: ["vault:read"] });
  });

  it("keeps MCP and publisher routes on separate configured hosts", async () => {
    const store = new VaultStore(":memory:");
    const scopedConfig = config({
      ALLOWED_HOSTS: "mcp.test,ingest.test",
      MCP_HOSTS: "mcp.test",
      PUBLISHER_HOSTS: "ingest.test",
      ALLOWED_ORIGINS: "http://mcp.test,http://ingest.test",
    });
    const runtime = await createApp({ config: scopedConfig, store, mcpHandler: async (_request, reply) => { await reply.send({ ok: true }); } });
    runtimes.push(runtime);
    const wrongPublisherHost = await runtime.app.inject({ method: "POST", url: "/v1/pairing/consume", headers: { host: "mcp.test" }, payload: {} });
    expect(wrongPublisherHost.statusCode).toBe(403);
    const wrongMcpHost = await runtime.app.inject({ method: "POST", url: "/mcp", headers: { host: "ingest.test", authorization: "Bearer test-token" }, payload: { jsonrpc: "2.0", id: 1, method: "tools/list" } });
    expect(wrongMcpHost.statusCode).toBe(403);
  });

  it("has an independent publisher kill switch", async () => {
    const store = new VaultStore(":memory:");
    const runtime = await createApp({ config: config({ PUBLISHER_INGEST_DISABLED: "true" }), store, mcpHandler: async (_request, reply) => { await reply.send({ ok: true }); } });
    runtimes.push(runtime);
    const response = await runtime.app.inject({ method: "POST", url: "/v1/pairing/consume", payload: {} });
    expect(response.statusCode).toBe(503);
  });

  it("bounds clock skew below nonce retention and rejects overlapping production surfaces", () => {
    const bounded = loadConfig({ NODE_ENV: "test", NONCE_RETENTION_SECONDS: "900", MAX_CLOCK_SKEW_SECONDS: "1200" });
    expect(bounded.maxClockSkewSeconds).toBe(899);
    expect(() => assertConfigSafety({ ...bounded, maxClockSkewSeconds: bounded.nonceRetentionSeconds })).toThrow(/below NONCE_RETENTION/u);
    expect(() => assertProductionConfig(loadConfig({
      NODE_ENV: "production",
      ALLOWED_HOSTS: "mcp.example.invalid,ingest.example.invalid",
      MCP_HOSTS: "mcp.example.invalid",
      PUBLISHER_HOSTS: "mcp.example.invalid",
      MCP_RESOURCE_URL: "https://mcp.example.invalid/mcp",
      PUBLISHER_PUBLIC_URL: "https://mcp.example.invalid",
      MCP_VAULT_ID: "vault_test_0000001",
      MCP_INSTALLATION_ID: "install_test_000001",
      PUBLISHER_EDGE_ATTESTATION_SECRET: "synthetic-edge-attestation-secret-1234567890",
      MCP_EDGE_ATTESTATION_SECRET_FILE: mcpEdgeAttestationSecretFile,
      JWT_ISSUER: "https://issuer.example.invalid/",
      JWT_AUDIENCE: "vault-mcp-bridge",
      JWT_JWKS_URL: "https://issuer.example.invalid/.well-known/jwks.json",
      JWT_ALLOW_REMOTE_JWKS: "true",
    }))).toThrow(/must not overlap/u);
  });

  it("keeps MCP edge attestation settings bounded and separate from publisher headers", () => {
    const configured = loadConfig({
      NODE_ENV: "test",
      MCP_EDGE_ATTESTATION_HEADER: "x-custom-mcp-attestation",
      MCP_EDGE_TIMESTAMP_HEADER: "x-custom-mcp-timestamp",
      MCP_EDGE_NONCE_HEADER: "x-custom-mcp-nonce",
      MAX_MCP_EDGE_ATTESTATION_ENTRIES: "7",
    });
    expect(configured.mcpEdgeAttestationHeader).toBe("x-custom-mcp-attestation");
    expect(configured.mcpEdgeTimestampHeader).toBe("x-custom-mcp-timestamp");
    expect(configured.mcpEdgeNonceHeader).toBe("x-custom-mcp-nonce");
    expect(configured.maxMcpEdgeAttestationEntries).toBe(7);
    expect(() => assertConfigSafety({ ...configured, mcpEdgeNonceHeader: configured.mcpEdgeAttestationHeader })).toThrow(/MCP edge attestation header names/u);
    expect(() => assertConfigSafety({ ...configured, mcpEdgeAttestationHeader: configured.publisherEdgeAttestationHeader })).toThrow(/publisher and MCP edge attestation header names/u);
    expect(() => assertConfigSafety({ ...configured, maxMcpEdgeAttestationEntries: 0 })).toThrow(/limits must be positive/u);
  });

  it("prevents generation regression across two VaultStore instances sharing SQLite", async () => {
    const directory = mkdtempSync(join(tmpdir(), "vault-mcp-bridge-server-"));
    const databasePath = join(directory, "state.sqlite");
    const first = new VaultStore(databasePath);
    const second = new VaultStore(databasePath);
    try {
      const keyPair = generateKeyPairSync("ed25519");
      const publicKey = keyPair.publicKey.export({ format: "der", type: "spki" }).toString("base64url");
      const vaultId = "vault_shared_000001";
      const deviceId = "device_shared_00001";
      const code = first.createPairingCode(vaultId, 600, "pairing_shared_code_123456789012345678901234567890");
      first.consumePairingCode({ version: 1, pairCode: code.code, agentId: deviceId, publicKey, vaultId });
      const generationOne = makeSnapshot(vaultId, 1);
      first.activateSnapshot(generationOne, deviceId);
      const generationTwo = makeSnapshot(vaultId, 2);
      const generationThree = makeSnapshot(vaultId, 3);
      first.activateSnapshot(generationTwo, deviceId);
      expect(() => first.activateSnapshot(generationOne, deviceId)).toThrow(/retained but inactive/u);
      const outcomes = await Promise.allSettled([
        Promise.resolve().then(() => second.activateSnapshot(generationThree, deviceId)),
        Promise.resolve().then(() => first.activateSnapshot(generationTwo, deviceId)),
      ]);
      expect(outcomes.filter((outcome) => outcome.status === "fulfilled")).toHaveLength(1);
      const rejected = outcomes.find((outcome): outcome is PromiseRejectedResult => outcome.status === "rejected");
      expect(rejected?.reason).toMatchObject({ statusCode: 409 });
      expect(first.getActive(vaultId)).toMatchObject({ generation: 3, snapshotId: generationThree.snapshotId });
      expect(() => first.activateSnapshot(generationTwo, deviceId)).toThrow(/retained but inactive|not newer/u);
    } finally {
      first.close();
      second.close();
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it("migrates legacy SQLite schema version 0 and rejects unsupported versions", () => {
    const directory = mkdtempSync(join(tmpdir(), "vault-mcp-bridge-schema-"));
    const databasePath = join(directory, "state.sqlite");
    try {
      const initial = new VaultStore(databasePath);
      initial.close();

      // A pre-versioned database is the legacy v0 shape. Opening it should
      // run the idempotent migration and record the supported version.
      const legacy = new DatabaseSync(databasePath);
      legacy.exec("PRAGMA user_version=0");
      legacy.close();
      const migrated = new VaultStore(databasePath);
      const migratedVersion = migrated.db.prepare("PRAGMA user_version").get() as Record<string, unknown>;
      expect(Number(migratedVersion.user_version)).toBe(1);
      migrated.close();

      const unsupported = new DatabaseSync(databasePath);
      unsupported.exec("PRAGMA user_version=99");
      unsupported.close();
      expect(() => new VaultStore(databasePath)).toThrow(/unsupported SQLite schema version/u);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it("verifies offline JWKS and binds every MCP token to installation, vault, and client", async () => {
    const keyPair = generateKeyPairSync("ed25519");
    const publicJwk = keyPair.publicKey.export({ format: "jwk" });
    const issuer = "https://issuer.example.invalid/";
    const audience = "vault-mcp-bridge";
    const vaultId = "vault_test_0000001";
    const installationId = "install_test_000001";
    const verificationIssuedAt = new Date(Date.now() - 60_000).toISOString();
    const verificationExpiresAt = new Date(Date.now() + 3_600_000).toISOString();
    const production = loadConfig({
      NODE_ENV: "production",
      ALLOWED_HOSTS: "mcp.example.invalid,ingest.example.invalid",
      MCP_HOSTS: "mcp.example.invalid",
      PUBLISHER_HOSTS: "ingest.example.invalid",
      MCP_RESOURCE_URL: "https://mcp.example.invalid/mcp",
      PUBLISHER_PUBLIC_URL: "https://ingest.example.invalid",
      MCP_VAULT_ID: vaultId,
      MCP_INSTALLATION_ID: installationId,
      PUBLISHER_EDGE_ATTESTATION_SECRET: "synthetic-edge-attestation-secret-1234567890",
      MCP_EDGE_ATTESTATION_SECRET_FILE: mcpEdgeAttestationSecretFile,
      JWT_ISSUER: issuer,
      JWT_AUDIENCE: audience,
      JWT_JWKS_JSON: JSON.stringify({ issuer, audience, issuedAt: verificationIssuedAt, expiresAt: verificationExpiresAt, keys: [{ ...publicJwk, kid: "synthetic", alg: "EdDSA", use: "sig" }] }),
    });
    const store = new VaultStore(":memory:");
    const runtime = await createApp({ config: production, store, mcpHandler: async (_request, reply) => { await reply.send({ ok: true }); } });
    runtimes.push(runtime);
    const token = await new SignJWT({ scope: "vault:read", installation_id: installationId, vault_id: vaultId, client_id: "chatgpt-client" })
      .setProtectedHeader({ alg: "EdDSA", kid: "synthetic" })
      .setIssuer(issuer)
      .setAudience(audience)
      .setSubject("owner-test")
      .setExpirationTime("5m")
      .sign(keyPair.privateKey);
    const accepted = await runtime.app.inject({ method: "POST", url: "/mcp", headers: { host: "mcp.example.invalid", authorization: `Bearer ${token}`, ...mcpEdgeHeaders("mcp.example.invalid", "/mcp", token) }, payload: { jsonrpc: "2.0", id: 1, method: "tools/list" } });
    expect(accepted.statusCode).toBe(200);
    const wrongVault = await new SignJWT({ scope: "vault:read", installation_id: installationId, vault_id: "vault_other_000001", client_id: "chatgpt-client" })
      .setProtectedHeader({ alg: "EdDSA", kid: "synthetic" }).setIssuer(issuer).setAudience(audience).setSubject("owner-test").setExpirationTime("5m").sign(keyPair.privateKey);
    const rejected = await runtime.app.inject({ method: "POST", url: "/mcp", headers: { host: "mcp.example.invalid", authorization: `Bearer ${wrongVault}`, ...mcpEdgeHeaders("mcp.example.invalid", "/mcp", wrongVault) }, payload: { jsonrpc: "2.0", id: 1, method: "tools/list" } });
    expect(rejected.statusCode).toBe(401);
    const expired = await createApp({ config: loadConfig({
      NODE_ENV: "production",
      ALLOWED_HOSTS: "mcp.example.invalid,ingest.example.invalid",
      MCP_HOSTS: "mcp.example.invalid",
      PUBLISHER_HOSTS: "ingest.example.invalid",
      MCP_RESOURCE_URL: "https://mcp.example.invalid/mcp",
      PUBLISHER_PUBLIC_URL: "https://ingest.example.invalid",
      MCP_VAULT_ID: vaultId,
      MCP_INSTALLATION_ID: installationId,
      PUBLISHER_EDGE_ATTESTATION_SECRET: "synthetic-edge-attestation-secret-1234567890",
      MCP_EDGE_ATTESTATION_SECRET_FILE: mcpEdgeAttestationSecretFile,
      JWT_ISSUER: issuer,
      JWT_AUDIENCE: audience,
      JWT_JWKS_JSON: JSON.stringify({ issuer, audience, issuedAt: verificationIssuedAt, expiresAt: new Date(Date.now() - 1_000).toISOString(), keys: [{ ...publicJwk, kid: "synthetic", alg: "EdDSA", use: "sig" }] }),
    }), store: new VaultStore(":memory:"), mcpHandler: async (_request, reply) => { await reply.send({ ok: true }); } });
    runtimes.push(expired);
    const staleResponse = await expired.app.inject({ method: "POST", url: "/mcp", headers: { host: "mcp.example.invalid", authorization: `Bearer ${token}`, ...mcpEdgeHeaders("mcp.example.invalid", "/mcp", token) }, payload: { jsonrpc: "2.0", id: 1, method: "tools/list" } });
    expect(staleResponse.statusCode).toBe(401);
    expect(staleResponse.headers["www-authenticate"]).toContain("temporarily_unavailable");
  });

  it("reports an offline JWKS bundle as not ready after its expiry", async () => {
    const keyPair = generateKeyPairSync("ed25519");
    const publicJwk = keyPair.publicKey.export({ format: "jwk" });
    const issuer = "https://issuer.expiry.example.invalid/";
    const audience = "vault-mcp-bridge";
    const vaultId = "vault_expiry_000001";
    const installationId = "install_expiry_000001";
    const now = Date.now();
    vi.useFakeTimers({ now });
    try {
      const runtime = await createApp({ config: loadConfig({
        NODE_ENV: "production",
        ALLOWED_HOSTS: "mcp.expiry.example.invalid,ingest.expiry.example.invalid",
        MCP_HOSTS: "mcp.expiry.example.invalid",
        PUBLISHER_HOSTS: "ingest.expiry.example.invalid",
        MCP_RESOURCE_URL: "https://mcp.expiry.example.invalid/mcp",
        PUBLISHER_PUBLIC_URL: "https://ingest.expiry.example.invalid",
        MCP_VAULT_ID: vaultId,
        MCP_INSTALLATION_ID: installationId,
        PUBLISHER_EDGE_ATTESTATION_SECRET: "synthetic-edge-attestation-secret-1234567890",
        MCP_EDGE_ATTESTATION_SECRET_FILE: mcpEdgeAttestationSecretFile,
        JWT_ISSUER: issuer,
        JWT_AUDIENCE: audience,
        JWT_JWKS_JSON: JSON.stringify({ issuer, audience, issuedAt: new Date(now - 1_000).toISOString(), expiresAt: new Date(now + 1_000).toISOString(), keys: [{ ...publicJwk, kid: "synthetic", alg: "EdDSA", use: "sig" }] }),
      }), store: new VaultStore(":memory:"), mcpHandler: async (_request, reply) => { await reply.send({ ok: true }); } });
      runtimes.push(runtime);
      const ready = await runtime.app.inject({ method: "GET", url: "/readyz", headers: { host: "mcp.expiry.example.invalid" } });
      expect(ready.statusCode).toBe(200);
      vi.setSystemTime(now + 1_001);
      const stale = await runtime.app.inject({ method: "GET", url: "/readyz", headers: { host: "mcp.expiry.example.invalid" } });
      expect(stale.statusCode).toBe(503);
    } finally {
      vi.useRealTimers();
    }
  });

  it("requires explicit opt-in before accepting a raw static JWKS", async () => {
    const keyPair = generateKeyPairSync("ed25519");
    const issuer = "https://issuer.raw.example.invalid/";
    const audience = "https://mcp.raw.example.invalid/mcp";
    const baseEnv: NodeJS.ProcessEnv = {
      NODE_ENV: "production",
      ALLOWED_HOSTS: "mcp.raw.example.invalid,ingest.raw.example.invalid",
      MCP_HOSTS: "mcp.raw.example.invalid",
      PUBLISHER_HOSTS: "ingest.raw.example.invalid",
      MCP_RESOURCE_URL: audience,
      PUBLISHER_PUBLIC_URL: "https://ingest.raw.example.invalid",
      MCP_VAULT_ID: "vault_raw_00000001",
      MCP_INSTALLATION_ID: "install_raw_000001",
      PUBLISHER_EDGE_ATTESTATION_SECRET: "synthetic-edge-attestation-secret-1234567890",
      MCP_EDGE_ATTESTATION_SECRET_FILE: mcpEdgeAttestationSecretFile,
      JWT_ISSUER: issuer,
      JWT_AUDIENCE: audience,
      JWT_JWKS_JSON: JSON.stringify({ keys: [{ ...keyPair.publicKey.export({ format: "jwk" }), kid: "raw", alg: "EdDSA", use: "sig" }] }),
    };
    await expect(createApp({ config: loadConfig(baseEnv), store: new VaultStore(":memory:"), mcpHandler: async (_request, reply) => { await reply.send({ ok: true }); } })).rejects.toThrow(/metadata/u);
    const optedIn = await createApp({ config: loadConfig({ ...baseEnv, JWT_ALLOW_RAW_JWKS: "true" }), store: new VaultStore(":memory:"), mcpHandler: async (_request, reply) => { await reply.send({ ok: true }); } });
    runtimes.push(optedIn);
  });

  it("requires MCP edge attestation before JWT and binds it to the request and bearer token", async () => {
    const runtime = await createApp({ config: config({ MCP_EDGE_ATTESTATION_SECRET: mcpEdgeSecret, MAX_MCP_EDGE_ATTESTATION_ENTRIES: "2" }), store: new VaultStore(":memory:"), mcpHandler: async (_request, reply) => { await reply.send({ ok: true }); } });
    runtimes.push(runtime);
    const token = "test-token";
    const base = { method: "POST", url: "/mcp", headers: { host: "localhost" } } as const;
    const missing = await runtime.app.inject({ method: "POST", url: "/mcp", headers: { host: "localhost", authorization: `Bearer ${token}` }, payload: { jsonrpc: "2.0", id: 1, method: "tools/list" } });
    expect(missing.statusCode).toBe(401);

    const validHeaders = mcpEdgeAttestationForRequest(base, mcpEdgeSecret, token, { nonce: "mcp_edge_nonce_valid_123456789012" });
    const accepted = await runtime.app.inject({ method: "POST", url: "/mcp", headers: { host: "localhost", authorization: `Bearer ${token}`, ...validHeaders }, payload: { jsonrpc: "2.0", id: 1, method: "tools/list" } });
    expect(accepted.statusCode).toBe(200);
    const replay = await runtime.app.inject({ method: "POST", url: "/mcp", headers: { host: "localhost", authorization: `Bearer ${token}`, ...validHeaders }, payload: { jsonrpc: "2.0", id: 1, method: "tools/list" } });
    expect(replay.statusCode).toBe(401);

    const substitutedTokenHeaders = mcpEdgeAttestationForRequest(base, mcpEdgeSecret, token, { nonce: "mcp_edge_nonce_substitute_123456" });
    const substitutedToken = await runtime.app.inject({ method: "POST", url: "/mcp", headers: { host: "localhost", authorization: "Bearer substituted-token", ...substitutedTokenHeaders }, payload: { jsonrpc: "2.0", id: 1, method: "tools/list" } });
    expect(substitutedToken.statusCode).toBe(401);

    const modifiedUrlHeaders = mcpEdgeAttestationForRequest(base, mcpEdgeSecret, token, { nonce: "mcp_edge_nonce_url_123456789012" });
    const modifiedUrl = await runtime.app.inject({ method: "POST", url: "/mcp?surface=modified", headers: { host: "localhost", authorization: `Bearer ${token}`, ...modifiedUrlHeaders }, payload: { jsonrpc: "2.0", id: 1, method: "tools/list" } });
    expect(modifiedUrl.statusCode).toBe(401);

    const modifiedHost = await runtime.app.inject({ method: "POST", url: "/mcp", headers: { host: "127.0.0.1", authorization: `Bearer ${token}`, ...mcpEdgeAttestationForRequest(base, mcpEdgeSecret, token, { nonce: "mcp_edge_nonce_host_1234567890" }) }, payload: { jsonrpc: "2.0", id: 1, method: "tools/list" } });
    expect(modifiedHost.statusCode).toBe(401);

    const staleHeaders = mcpEdgeAttestationForRequest(base, mcpEdgeSecret, token, { timestamp: Math.floor(Date.now() / 1000) - 301, nonce: "mcp_edge_nonce_stale_123456789" });
    const stale = await runtime.app.inject({ method: "POST", url: "/mcp", headers: { host: "localhost", authorization: `Bearer ${token}`, ...staleHeaders }, payload: { jsonrpc: "2.0", id: 1, method: "tools/list" } });
    expect(stale.statusCode).toBe(401);

    const health = await runtime.app.inject({ method: "GET", url: "/healthz", headers: { host: "localhost" } });
    expect(health.statusCode).toBe(200);
    const metadata = await runtime.app.inject({ method: "GET", url: "/.well-known/oauth-protected-resource/mcp", headers: { host: "localhost" } });
    expect(metadata.statusCode).toBe(200);
  });

  it("requires a cryptographic edge mTLS attestation instead of trusting a status header", async () => {
    const secret = "synthetic-edge-attestation-secret-1234567890";
    const runtime = await createApp({ config: config({ PUBLISHER_MTLS_REQUIRED: "true", PUBLISHER_EDGE_ATTESTATION_SECRET: secret }), store: new VaultStore(":memory:"), mcpHandler: async (_request, reply) => { await reply.send({ ok: true }); } });
    runtimes.push(runtime);
    const missing = await runtime.app.inject({ method: "POST", url: "/v1/pairing/consume", headers: { host: "localhost", "x-vmb-edge-mtls-status": "verified" }, payload: {} });
    expect(missing.statusCode).toBe(401);
    const requestShape = { method: "POST", url: "/v1/pairing/consume?surface=stable", headers: { host: "localhost" } } as never;
    const attestation = publisherEdgeAttestationForRequest(requestShape, secret, { nonce: "edge_nonce_test_1234567890123456" });
    const attested = await runtime.app.inject({ method: "POST", url: "/v1/pairing/consume?surface=stable", headers: { host: "localhost", ...attestation }, payload: {} });
    expect(attested.statusCode).toBe(400);
    const replay = await runtime.app.inject({ method: "POST", url: "/v1/pairing/consume?surface=stable", headers: { host: "localhost", ...attestation }, payload: {} });
    expect(replay.statusCode).toBe(401);
    const stale = publisherEdgeAttestationForRequest(requestShape, secret, { timestamp: Math.floor(Date.now() / 1000) - 301, nonce: "edge_nonce_stale_1234567890123456" });
    const staleResponse = await runtime.app.inject({ method: "POST", url: "/v1/pairing/consume?surface=stable", headers: { host: "localhost", ...stale }, payload: {} });
    expect(staleResponse.statusCode).toBe(401);
    const modifiedUrlAttestation = publisherEdgeAttestationForRequest(requestShape, secret, { nonce: "edge_nonce_url_1234567890123456" });
    const modifiedUrl = await runtime.app.inject({ method: "POST", url: "/v1/pairing/consume?surface=modified", headers: { host: "localhost", ...modifiedUrlAttestation }, payload: {} });
    expect(modifiedUrl.statusCode).toBe(401);
  });

  it("reports storage pressure as not ready before accepting traffic", async () => {
    const directory = mkdtempSync(join(tmpdir(), "vault-mcp-bridge-ready-"));
    const runtime = await createApp({ config: config({ SERVER_DATABASE_PATH: join(directory, "state.sqlite"), MIN_FREE_BYTES: "999999999999999999" }), mcpHandler: async (_request, reply) => { await reply.send({ ok: true }); } });
    try {
      const ready = await runtime.app.inject({ method: "GET", url: "/readyz", headers: { host: "localhost" } });
      expect(ready.statusCode).toBe(503);
      expect((await runtime.app.inject({ method: "GET", url: "/healthz", headers: { host: "localhost" } })).statusCode).toBe(200);
    } finally {
      await runtime.close();
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it("rejects a generation before SQLite activation when the vault quota is exhausted", async () => {
    const runtime = await createApp({ config: config({ MAX_VAULT_BYTES: "64" }), mcpHandler: async (_request, reply) => { await reply.send({ ok: true }); } });
    runtimes.push(runtime);
    const pairing = runtime.store.createPairingCode("vault_test_0000001", 600, "pairing_code_quota_123456789012345678901234567890");
    const device = await pair(runtime, pairing.code, "vault_test_0000001");
    const response = await runtime.app.inject({ method: "POST", url: "/v1/snapshots", payload: signedUpload(device.deviceId, device.vaultId, device.privateKey, makeSnapshot("vault_test_0000001")) });
    expect(response.statusCode).toBe(413);
    expect(runtime.store.getActive("vault_test_0000001")).toBeNull();
  });

  it("declares read-only OAuth security metadata on both MCP tools", () => {
    expect(oauthSecuritySchemes("vault:read")).toEqual([{ type: "oauth2", scopes: ["vault:read"] }]);
  });

  it("bounds principal rate-limit buckets and evicts inactive identities", () => {
    const guard = new PrincipalGuard(loadConfig({ NODE_ENV: "test", MAX_PRINCIPAL_BUCKETS: "2" }));
    expect(guard.enter("subject_a")).toBe(true);
    guard.leave("subject_a");
    expect(guard.enter("subject_b")).toBe(true);
    guard.leave("subject_b");
    expect(guard.enter("subject_c")).toBe(true);
    guard.leave("subject_c");
    expect(guard.size).toBe(2);
  });
});
