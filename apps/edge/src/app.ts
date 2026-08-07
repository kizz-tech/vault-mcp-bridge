import Fastify, { type FastifyInstance, type FastifyReply, type FastifyRequest } from "fastify";
import type { JWK, KeyInput } from "jose";
import { OpaqueIdSchema, MCP_READ_SCOPE } from "@vault-mcp-bridge/contracts";
import { assertProductionConfig, type EdgeConfig } from "./config.js";
import { parseBearer, parseCookie, safeEqual } from "./crypto.js";
import { OAuthError, OAuthService } from "./oauth.js";
import { CredentialLeaseError } from "./lease.js";
import { resolveLimits, type EdgeLimits } from "./limits.js";
import { RateGuard } from "./rate.js";
import { OwnerAuthenticator, OwnerSessionCapacityError, OwnerSessionService, type OwnerAuthConfig } from "./owner.js";
import { OwnerBrowserError, OwnerBrowserOidcBridge } from "./owner-browser.js";
import { DeterministicTunnelProvider, ExternalTunnelProvider, type CredentialVault, type TunnelProvider } from "./providers.js";
import { EdgeCapacityError, EdgeService, IdempotencyKeyError, InstallationNotFoundError } from "./service.js";
import { createMemoryStore } from "./store.js";
import type { EdgeStore, InstallationRecord } from "./types.js";
import { z } from "zod";

export type CreateEdgeAppOptions = {
  config?: Partial<EdgeConfig> & Pick<EdgeConfig, "origin" | "issuer" | "nodeEnv" | "mode">;
  provider?: TunnelProvider;
  credentialVault?: CredentialVault;
  store?: EdgeStore;
  oauth?: OAuthService;
  oauthSigningKey?: {
    privateKey: KeyInput;
    publicJwk: JWK;
  };
  ownerBrowser?: OwnerBrowserOidcBridge;
  now?: () => number;
};

export type EdgeApp = {
  app: FastifyInstance;
  service: EdgeService;
  oauth: OAuthService;
  store: EdgeStore;
  ownerAuthenticator: OwnerAuthenticator;
  ownerBrowser?: OwnerBrowserOidcBridge;
  close: () => Promise<void>;
};

const createConfig = (input: CreateEdgeAppOptions["config"]): EdgeConfig => {
  if (!input) throw new Error("edge config is required");
  const normalizeOrigin = (value: string, field: string): string => {
    const url = new URL(value);
    if (url.username || url.password || url.search || url.hash || (url.pathname !== "/" && url.pathname !== "")) {
      throw new Error(`${field} must be an origin URL`);
    }
    url.pathname = "";
    return url.toString().replace(/\/$/u, "");
  };
  const config = {
    nodeEnv: input.nodeEnv,
    mode: input.mode,
    origin: normalizeOrigin(input.origin, "EDGE_ORIGIN"),
    issuer: normalizeOrigin(input.issuer, "EDGE_ISSUER"),
    bindHost: input.bindHost ?? "127.0.0.1",
    bindPort: input.bindPort ?? 8790,
    providerName: input.providerName ?? "local",
    ...(input.limits ? { limits: input.limits } : {}),
    ...(input.trustProxy !== undefined ? { trustProxy: input.trustProxy } : {}),
    ...(input.ownerIssuer ? { ownerIssuer: input.ownerIssuer } : {}),
    ...(input.ownerAudience ? { ownerAudience: input.ownerAudience } : {}),
    ...(input.ownerJwks ? { ownerJwks: input.ownerJwks } : {}),
    ...(input.devOwnerToken ? { devOwnerToken: input.devOwnerToken } : {}),
    ...(input.devOwnerId ? { devOwnerId: input.devOwnerId } : {}),
    ...(input.ownerAuthorizationUrl ? { ownerAuthorizationUrl: input.ownerAuthorizationUrl } : {}),
    ...(input.ownerClientId ? { ownerClientId: input.ownerClientId } : {}),
    ...(input.ownerTokenEndpoint ? { ownerTokenEndpoint: input.ownerTokenEndpoint } : {}),
    ...(input.ownerScope ? { ownerScope: input.ownerScope } : {}),
    ...(input.autoApproveOwnerId ? { autoApproveOwnerId: input.autoApproveOwnerId } : {}),
    ...(input.providerAccountCredentialReference ? { providerAccountCredentialReference: input.providerAccountCredentialReference } : {}),
  } satisfies EdgeConfig;
  assertProductionConfig(config);
  return config;
};

const bodyRecord = (request: FastifyRequest): Record<string, unknown> => {
  if (!request.body || typeof request.body !== "object" || Array.isArray(request.body)) return {};
  return request.body as Record<string, unknown>;
};

const queryRecord = (request: FastifyRequest): Record<string, unknown> => {
  if (!request.query || typeof request.query !== "object" || Array.isArray(request.query)) return {};
  return request.query as Record<string, unknown>;
};

const stringValue = (value: unknown): string => typeof value === "string" ? value : "";

const formRecord = (request: FastifyRequest): Record<string, string> => {
  if (typeof request.body === "string") return Object.fromEntries(new URLSearchParams(request.body).entries());
  return Object.fromEntries(Object.entries(bodyRecord(request)).filter((entry): entry is [string, string] => typeof entry[1] === "string"));
};

const createInstallationSchema = z.object({
  installationId: OpaqueIdSchema.optional(),
  vaultId: OpaqueIdSchema,
  publisherCsr: z.string().min(128).max(16 * 1024).optional()
}).strict();
const registerClientSchema = z.object({
  installation_id: OpaqueIdSchema.optional(),
  installationId: OpaqueIdSchema.optional(),
  resource: z.string().url(),
  client_name: z.string().max(256).optional(),
  clientName: z.string().max(256).optional(),
  redirect_uris: z.array(z.string()).min(1).max(32),
  grant_types: z.array(z.string()).optional(),
  response_types: z.array(z.string()).optional(),
  token_endpoint_auth_method: z.string().optional(),
}).strict();
const credentialLeaseSchema = z.object({
  kind: z.enum(["tunnel", "publisher-mtls", "publisher-edge-attestation", "mcp-edge-attestation"]),
  client_public_key: z.string().min(32).max(512).optional(),
  clientPublicKey: z.string().min(32).max(512).optional(),
}).strict();
const introspectionSchema = z.object({ token: z.string().min(1).max(16 * 1024) }).strict();

const routeInstallationId = (request: FastifyRequest): string => {
  const params = request.params as Record<string, unknown>;
  return stringValue(params.installationId);
};

const routeLeaseId = (request: FastifyRequest): string => {
  const params = request.params as Record<string, unknown>;
  return stringValue(params.leaseId);
};

const routeClientId = (request: FastifyRequest): string => {
  const params = request.params as Record<string, unknown>;
  return stringValue(params.clientId);
};

const leaseErrorStatus = (error: CredentialLeaseError): number => {
  if (error.code === "secret_unavailable") return 503;
  if (error.code === "expired") return 410;
  if (error.code === "owner_mismatch" || error.code === "not_found") return 404;
  if (error.code === "capacity") return 429;
  return 400;
};

const flushStore = async (store: EdgeStore): Promise<void> => {
  if (store.flush) await store.flush();
};

export const createEdgeApp = async (options: CreateEdgeAppOptions): Promise<EdgeApp> => {
  const config = createConfig(options.config);
  const limits: EdgeLimits = resolveLimits(config.limits);
  const store = options.store ?? createMemoryStore();
  if (config.nodeEnv === "production" && (!options.store || options.store.isDurable !== true)) throw new Error("EDGE_DURABLE_STORE_REQUIRED");
  if (config.nodeEnv === "production" && !options.oauth && !options.oauthSigningKey) throw new Error("EDGE_OAUTH_KEY_STORE_REQUIRED");
  const oauth = options.oauth ?? await OAuthService.create({ store, issuer: config.issuer, limits, ...(options.now ? { now: options.now } : {}), ...(options.oauthSigningKey ? { signingKey: options.oauthSigningKey } : {}) });
  const provider = options.provider ?? (config.nodeEnv === "production"
    ? new ExternalTunnelProvider(config.providerName, config.providerAccountCredentialReference)
    : new DeterministicTunnelProvider({ origin: config.origin, ...(options.credentialVault ? { credentials: options.credentialVault } : {}), allowHttp: true, ...(options.now ? { now: options.now } : {}) }));
  const credentialVault = options.credentialVault ?? (provider instanceof DeterministicTunnelProvider ? provider.credentials : undefined);
  const service = new EdgeService({ mode: config.mode, origin: config.origin, issuer: config.issuer, provider, store, oauth, limits, ...(credentialVault ? { credentialVault } : {}), ...(options.now ? { now: options.now } : {}) });
  const ownerAuthConfig: OwnerAuthConfig = {
    nodeEnv: config.nodeEnv,
    ...(config.ownerIssuer ? { issuer: config.ownerIssuer } : {}),
    ...(config.ownerAudience ? { audience: config.ownerAudience } : {}),
    ...(config.ownerJwks ? { jwks: config.ownerJwks } : {}),
    ...(config.devOwnerToken ? { devBearerToken: config.devOwnerToken } : {}),
    ...(config.devOwnerId ? { devOwnerId: config.devOwnerId } : {}),
    ...(config.ownerAuthorizationUrl ? { ownerAuthorizationUrl: config.ownerAuthorizationUrl } : {}),
    ...(config.autoApproveOwnerId ? { autoApproveOwnerId: config.autoApproveOwnerId } : {}),
  };
  const ownerAuthenticator = new OwnerAuthenticator(ownerAuthConfig);
  const ownerBrowser = options.ownerBrowser ?? (config.ownerIssuer && config.ownerAuthorizationUrl && config.ownerTokenEndpoint && config.ownerClientId && config.ownerJwks
    ? new OwnerBrowserOidcBridge({
        issuer: config.ownerIssuer,
        clientId: config.ownerClientId,
        authorizationEndpoint: config.ownerAuthorizationUrl,
        tokenEndpoint: config.ownerTokenEndpoint,
        redirectUri: new URL("/owner/callback", config.origin).toString(),
        origin: config.origin,
        jwks: config.ownerJwks,
        ...(config.ownerScope ? { scope: config.ownerScope } : {}),
        allowLoopbackDev: config.nodeEnv !== "production",
        ...(options.now ? { now: options.now } : {})
      })
    : undefined);
  if (config.nodeEnv === "production" && !ownerBrowser) throw new Error("EDGE_OWNER_BROWSER_OIDC_REQUIRED");
  const sessions = new OwnerSessionService(store, options.now, 60 * 60, limits);
  const rateGuard = new RateGuard(limits.rateBurst, limits.ratePerMinute, limits.rateMaxKeys, options.now);
  const fastify = Fastify({ logger: false, bodyLimit: 256 * 1024, requestTimeout: 15_000 });

  fastify.addContentTypeParser("application/x-www-form-urlencoded", { parseAs: "string" }, (_request, body, done) => {
    done(null, String(body));
  });
  fastify.addHook("onSend", async (request, reply, payload) => {
    if (["POST", "PUT", "PATCH", "DELETE"].includes(request.method)) await flushStore(store);
    reply.header("cache-control", "no-store").header("x-content-type-options", "nosniff").header("referrer-policy", "no-referrer");
    return payload;
  });
  fastify.setErrorHandler((error, _request, reply) => {
    const candidate = error as { statusCode?: unknown };
    const statusCode = typeof candidate.statusCode === "number" && candidate.statusCode >= 400 && candidate.statusCode < 500 ? candidate.statusCode : 500;
    reply.code(statusCode).send({ error: statusCode === 500 ? "internal error" : "invalid request" });
  });

  const requireOwner = async (request: FastifyRequest, reply: FastifyReply): Promise<{ ownerId: string } | null> => {
    const principal = await ownerAuthenticator.verify(parseBearer(request.headers.authorization));
    if (!principal) {
      await reply.code(401).header("WWW-Authenticate", 'Bearer realm="edge-owner"').send({ error: "owner authentication required" });
      return null;
    }
    return principal;
  };

  const requestAddress = (request: FastifyRequest): string => {
    if (config.trustProxy) {
      const forwarded = request.headers["x-forwarded-for"];
      if (typeof forwarded === "string" && forwarded.trim()) return forwarded.split(",", 1)[0]?.trim() || "unknown";
    }
    return request.ip || request.socket.remoteAddress || "unknown";
  };
  const allowRequest = (request: FastifyRequest, scope: string, ownerId?: string): boolean => rateGuard.allow(`${scope}:${ownerId ? `owner:${ownerId}` : `ip:${requestAddress(request)}`}`);
  const sendRateLimit = (reply: FastifyReply): FastifyReply => reply.code(429).header("Retry-After", "1").send({ error: "rate limit exceeded" });

  const publicInstallation = (request: FastifyRequest): InstallationRecord | null => {
    const query = queryRecord(request);
    const resource = stringValue(query.resource);
    if (resource) {
      for (const record of store.installations.values()) {
        if (record.endpointBundle.mcpResourceUrl === resource) return record;
      }
    }
    const host = typeof request.headers.host === "string" ? request.headers.host : "";
    return service.resolveByHost(host);
  };

  const ownerForAuthorize = (request: FastifyRequest): { ownerId: string } | null => {
    const session = sessions.resolve(parseCookie(request.headers.cookie, "vmb_owner_session"));
    if (session) return session;
    if (config.nodeEnv !== "production" && ownerAuthConfig.autoApproveOwnerId) return { ownerId: ownerAuthConfig.autoApproveOwnerId };
    return null;
  };

  fastify.get("/healthz", async () => ({ ok: true }));
  fastify.get("/readyz", async (_request, reply) => {
    try {
      void store.installations.size;
      return { ok: true };
    } catch {
      return reply.code(503).send({ ok: false });
    }
  });

  fastify.post("/v1/owner/session", async (request, reply) => {
    const principal = await requireOwner(request, reply);
    if (!principal) return;
    if (!allowRequest(request, "owner-session", principal.ownerId)) return sendRateLimit(reply);
    let session: ReturnType<OwnerSessionService["create"]>;
    try {
      session = sessions.create(principal.ownerId);
    } catch (error) {
      if (error instanceof OwnerSessionCapacityError) return reply.code(503).send({ error: "server_error" });
      throw error;
    }
    const secure = config.origin.startsWith("https:") ? "; Secure" : "";
    reply.header("set-cookie", `vmb_owner_session=${session.value}; Path=/; HttpOnly; SameSite=Lax; Max-Age=3600${secure}`);
    return reply.code(204).send();
  });

  fastify.delete("/v1/owner/session", async (request, reply) => {
    sessions.revoke(parseCookie(request.headers.cookie, "vmb_owner_session"));
    return reply.code(204).send();
  });

  fastify.get("/owner/login", async (request, reply) => {
    if (!ownerBrowser) return reply.code(404).send({ error: "owner sign-in unavailable" });
    if (!allowRequest(request, "owner-login")) return sendRateLimit(reply);
    const returnUrl = stringValue(queryRecord(request).return_to);
    try {
      return reply.redirect(ownerBrowser.startLogin({ returnUrl }).authorizationUrl);
    } catch (error) {
      if (error instanceof OwnerBrowserError && error.code === "state_capacity") return reply.code(503).send({ error: "owner sign-in temporarily unavailable" });
      return reply.code(400).send({ error: "invalid owner sign-in request" });
    }
  });

  fastify.get("/owner/callback", async (request, reply) => {
    if (!ownerBrowser) return reply.code(404).send({ error: "owner sign-in unavailable" });
    if (!allowRequest(request, "owner-callback")) return sendRateLimit(reply);
    try {
      const result = await ownerBrowser.handleCallback(new URL(request.url, config.origin).toString());
      const session = sessions.create(result.ownerId);
      await flushStore(store);
      const secure = config.origin.startsWith("https:") ? "; Secure" : "";
      reply.header("set-cookie", `vmb_owner_session=${session.value}; Path=/; HttpOnly; SameSite=Lax; Max-Age=3600${secure}`);
      return reply.redirect(result.returnUrl);
    } catch (error) {
      if (error instanceof OwnerSessionCapacityError || (error instanceof OwnerBrowserError && error.code === "state_capacity")) {
        return reply.code(503).send({ error: "owner sign-in temporarily unavailable" });
      }
      return reply.code(400).send({ error: "owner sign-in failed" });
    }
  });

  fastify.post("/v1/installations", async (request, reply) => {
    const principal = await requireOwner(request, reply);
    if (!principal) return;
    if (!allowRequest(request, "installations", principal.ownerId)) return sendRateLimit(reply);
    const parsed = createInstallationSchema.safeParse(bodyRecord(request));
    if (!parsed.success) return reply.code(400).send({ error: "invalid installation request" });
    if (config.nodeEnv === "production" && (!parsed.data.installationId || !parsed.data.publisherCsr)) {
      return reply.code(400).send({ error: "installation identity and publisher CSR are required" });
    }
    const idempotencyHeader = request.headers["idempotency-key"];
    if (Array.isArray(idempotencyHeader) || (config.nodeEnv === "production" && typeof idempotencyHeader !== "string")) {
      return reply.code(400).send({ error: "idempotency key is required" });
    }
    try {
      const provisionRequest = {
        vaultId: parsed.data.vaultId,
        ...(parsed.data.installationId ? { installationId: parsed.data.installationId } : {}),
        ...(parsed.data.publisherCsr ? { publisherCsr: parsed.data.publisherCsr } : {})
      };
      const result = await service.createInstallationResult(principal.ownerId, provisionRequest, idempotencyHeader);
      return reply.code(result.idempotent ? 200 : 201).send({ installation: result.record });
    } catch (error) {
      if (error instanceof EdgeCapacityError) return reply.code(503).send({ error: "server_error" });
      if (error instanceof IdempotencyKeyError) return reply.code(error.conflict ? 409 : 400).send({ error: error.message });
      return reply.code(400).send({ error: error instanceof Error ? error.message : "installation failed" });
    }
  });

  fastify.get("/v1/installations", async (request, reply) => {
    const principal = await requireOwner(request, reply);
    if (!principal) return;
    if (!allowRequest(request, "installations", principal.ownerId)) return sendRateLimit(reply);
    return { installations: service.listInstallations(principal.ownerId) };
  });

  fastify.get("/v1/installations/:installationId", async (request, reply) => {
    const principal = await requireOwner(request, reply);
    if (!principal) return;
    if (!allowRequest(request, "installations", principal.ownerId)) return sendRateLimit(reply);
    try {
      return { installation: service.requireOwnerInstallation(principal.ownerId, routeInstallationId(request)) };
    } catch {
      return reply.code(404).send({ error: "installation not found" });
    }
  });

  fastify.post("/v1/installations/:installationId/rotate", async (request, reply) => {
    const principal = await requireOwner(request, reply);
    if (!principal) return;
    if (!allowRequest(request, "installations", principal.ownerId)) return sendRateLimit(reply);
    try {
      const installation = await service.rotateInstallation(principal.ownerId, routeInstallationId(request));
      return { installation };
    } catch {
      return reply.code(404).send({ error: "installation not found" });
    }
  });

  fastify.post("/v1/installations/:installationId/revoke", async (request, reply) => {
    const principal = await requireOwner(request, reply);
    if (!principal) return;
    if (!allowRequest(request, "installations", principal.ownerId)) return sendRateLimit(reply);
    try {
      await service.revokeInstallation(principal.ownerId, routeInstallationId(request));
      return { ok: true };
    } catch (error) {
      if (error instanceof InstallationNotFoundError) {
        return reply.code(404).send({ error: "installation_not_found" });
      }
      return reply.code(503).send({ error: "upstream_unavailable" });
    }
  });

  fastify.post("/v1/installations/:installationId/clients/:clientId/revoke", async (request, reply) => {
    const principal = await requireOwner(request, reply);
    if (!principal) return;
    if (!allowRequest(request, "installations", principal.ownerId)) return sendRateLimit(reply);
    try {
      const changed = await service.revokeClient(principal.ownerId, routeInstallationId(request), routeClientId(request));
      if (!changed) return reply.code(404).send({ error: "client not found" });
      return { ok: true };
    } catch (error) {
      if (error instanceof OAuthError) return reply.code(error.statusCode).send({ error: error.error });
      return reply.code(404).send({ error: "client not found" });
    }
  });

  const createLease = async (request: FastifyRequest, reply: FastifyReply) => {
    const principal = await requireOwner(request, reply);
    if (!principal) return;
    if (!allowRequest(request, "credential-lease", principal.ownerId)) return sendRateLimit(reply);
    const parsed = credentialLeaseSchema.safeParse(bodyRecord(request));
    if (!parsed.success) return reply.code(400).send({ error: "invalid credential lease request" });
    const clientPublicKey = parsed.data.client_public_key ?? parsed.data.clientPublicKey;
    if (!clientPublicKey) return reply.code(400).send({ error: "client_public_key is required" });
    try {
      return reply.code(201).send(service.createCredentialLease(principal.ownerId, routeInstallationId(request), parsed.data.kind, clientPublicKey));
    } catch (error) {
      if (error instanceof EdgeCapacityError) return reply.code(503).send({ error: "server_error" });
      if (error instanceof CredentialLeaseError) return reply.code(leaseErrorStatus(error)).send({ error: error.message });
      return reply.code(404).send({ error: "installation not found" });
    }
  };
  fastify.post("/v1/installations/:installationId/credentials/lease", createLease);

  const redeemLease = async (request: FastifyRequest, reply: FastifyReply) => {
    const principal = await requireOwner(request, reply);
    if (!principal) return;
    if (!allowRequest(request, "credential-lease", principal.ownerId)) return sendRateLimit(reply);
    try {
      return reply.code(200).send(await service.redeemCredentialLease(principal.ownerId, routeLeaseId(request)));
    } catch (error) {
      if (error instanceof CredentialLeaseError) return reply.code(leaseErrorStatus(error)).send({ error: error.message });
      return reply.code(404).send({ error: "credential lease not found" });
    }
  };
  // The flat route is the desktop IPC contract. Keep the nested alias for
  // callers that group credentials under the installation resource.
  fastify.post("/v1/credential-leases/:leaseId/redeem", redeemLease);
  fastify.post("/v1/installations/:installationId/credentials/lease/:leaseId/redeem", redeemLease);

  fastify.post("/oauth/register", async (request, reply) => {
    if (!allowRequest(request, "oauth-register")) return sendRateLimit(reply);
    const parsed = registerClientSchema.safeParse(bodyRecord(request));
    if (!parsed.success) return reply.code(400).send({ error: "invalid_client_metadata" });
    const input = parsed.data;
    const installationId = input.installation_id ?? input.installationId;
    const installation = installationId ? service.getInstallation(installationId) : service.findByResource(input.resource);
    if (!installation) return reply.code(400).send({ error: "invalid_target" });
    const boundInstallationId = installation.installationId;
    if (installation.status === "revoked" || installation.endpointBundle.mcpResourceUrl !== input.resource) return reply.code(400).send({ error: "invalid_target" });
    try {
      const clientName = input.client_name ?? input.clientName;
      const client = oauth.registerClient({
        installationId: boundInstallationId,
        resource: input.resource,
        redirectUris: input.redirect_uris,
        ...(clientName ? { clientName } : {}),
        ...(input.grant_types ? { grantTypes: input.grant_types } : {}),
        ...(input.response_types ? { responseTypes: input.response_types } : {}),
        ...(input.token_endpoint_auth_method ? { tokenEndpointAuthMethod: input.token_endpoint_auth_method } : {}),
      });
      return reply.code(201).send({
        client_id: client.clientId,
        client_id_issued_at: Math.floor(Date.parse(client.createdAt) / 1000),
        client_name: client.clientName,
        redirect_uris: client.redirectUris,
        grant_types: client.grantTypes,
        response_types: client.responseTypes,
        token_endpoint_auth_method: client.tokenEndpointAuthMethod,
      });
    } catch (error) {
      if (error instanceof OAuthError) return reply.code(error.statusCode).send({ error: error.error, error_description: error.message });
      return reply.code(400).send({ error: "invalid_client_metadata" });
    }
  });

  fastify.get("/oauth/authorize", async (request, reply) => {
    if (!allowRequest(request, "oauth-authorize")) return sendRateLimit(reply);
    const query = queryRecord(request);
    const clientId = stringValue(query.client_id);
    const redirectUri = stringValue(query.redirect_uri);
    const client = oauth.getClient(clientId);
    if (!client || !client.redirectUris.includes(redirectUri)) return reply.code(400).send({ error: "invalid_request" });
    const installation = service.getInstallation(client.installationId);
    if (!installation || installation.status === "revoked") return reply.code(400).send({ error: "invalid_target" });
    const resource = stringValue(query.resource);
    if (resource !== installation.endpointBundle.mcpResourceUrl) return reply.code(400).send({ error: "invalid_target" });
    const owner = ownerForAuthorize(request);
    if (!owner) {
      if (ownerBrowser) {
        // Resume on the session-cookie origin even when the public OAuth
        // issuer uses a distinct hostname for metadata.
        const returnTo = new URL(`${config.origin}/oauth/authorize`);
        for (const [key, value] of Object.entries(query)) if (typeof value === "string") returnTo.searchParams.set(key, value);
        const destination = new URL("/owner/login", config.origin);
        destination.searchParams.set("return_to", returnTo.toString());
        return reply.redirect(destination.toString());
      }
      return reply.code(401).send({ error: "owner authentication required" });
    }
    if (installation.ownerId !== owner.ownerId) return reply.code(403).send({ error: "owner is not allowed for this installation" });
    try {
      const result = oauth.authorize({
        installation,
        clientId,
        redirectUri,
        responseType: stringValue(query.response_type),
        scope: stringValue(query.scope) || MCP_READ_SCOPE,
        ...(stringValue(query.state) ? { state: stringValue(query.state) } : {}),
        codeChallenge: stringValue(query.code_challenge),
        codeChallengeMethod: stringValue(query.code_challenge_method),
        resource,
        ...(stringValue(query.nonce) ? { nonce: stringValue(query.nonce) } : {}),
        ownerId: owner.ownerId,
      });
      await flushStore(store);
      const destination = new URL(result.redirectUri);
      destination.searchParams.set("code", result.code);
      if (result.state) destination.searchParams.set("state", result.state);
      return reply.redirect(destination.toString());
    } catch (error) {
      if (error instanceof OAuthError) return reply.code(error.statusCode).send({ error: error.error, error_description: error.message });
      return reply.code(400).send({ error: "invalid_request" });
    }
  });

  fastify.post("/oauth/token", async (request, reply) => {
    if (!allowRequest(request, "oauth-token")) return sendRateLimit(reply);
    const form = formRecord(request);
    try {
      if (form.grant_type === "authorization_code") {
        const result = await oauth.exchangeAuthorizationCode({
          code: form.code ?? "",
          clientId: form.client_id ?? "",
          redirectUri: form.redirect_uri ?? "",
          codeVerifier: form.code_verifier ?? "",
          resource: form.resource ?? "",
        });
        return reply.code(200).send(result);
      }
      if (form.grant_type === "refresh_token") return reply.code(200).send(await oauth.refresh({ refreshToken: form.refresh_token ?? "", clientId: form.client_id ?? "", resource: form.resource ?? "" }));
      return reply.code(400).send({ error: "unsupported_grant_type" });
    } catch (error) {
      if (error instanceof OAuthError) return reply.code(error.statusCode).send({ error: error.error, error_description: error.message });
      return reply.code(400).send({ error: "invalid_grant" });
    }
  });

  /** Installation-scoped introspection is an internal edge contract. The
   * caller presents the distinct MCP edge credential as a bearer secret; it
   * is never accepted as an OAuth access token or publisher attestation. */
  fastify.post("/v1/installations/:installationId/oauth/introspect", async (request, reply) => {
    if (!allowRequest(request, "oauth-introspect")) return sendRateLimit(reply);
    const contentType = request.headers["content-type"];
    if (typeof contentType !== "string" || !/^application\/json(?:\s*;|$)/iu.test(contentType)) {
      return reply.code(400).send({ error: "invalid introspection request" });
    }
    const parsed = introspectionSchema.safeParse(bodyRecord(request));
    if (!parsed.success) return reply.code(400).send({ error: "invalid introspection request" });
    const installation = service.getInstallation(routeInstallationId(request));
    // Unknown/revoked installations intentionally collapse to an inactive
    // result so this endpoint cannot be used as an installation oracle.
    if (!installation || installation.status === "revoked") return { active: false };
    let expectedSecret: string | null = null;
    try {
      expectedSecret = credentialVault ? await credentialVault.get(installation.endpointBundle.mcpEdgeAttestation) : null;
    } catch {
      expectedSecret = null;
    }
    // A legacy installation may not have a distinct MCP credential yet; this
    // is an inactive result rather than an authentication oracle.
    if (!expectedSecret) return { active: false };
    const providedSecret = parseBearer(request.headers.authorization);
    if (!providedSecret || !safeEqual(providedSecret, expectedSecret)) {
      return reply.code(401).header("WWW-Authenticate", 'Bearer realm="mcp-edge-introspection"').send({ error: "introspection authentication required" });
    }
    try {
      const result = await oauth.introspectAccessToken(parsed.data.token, {
        installationId: installation.installationId,
        resource: installation.endpointBundle.mcpResourceUrl,
      });
      return result;
    } catch {
      return { active: false };
    }
  });

  fastify.post("/oauth/revoke", async (request, reply) => {
    if (!allowRequest(request, "oauth-revoke")) return sendRateLimit(reply);
    const form = formRecord(request);
    try {
      await oauth.revoke(form.token ?? "", form.client_id || undefined);
      return reply.code(200).send({});
    } catch (error) {
      if (error instanceof OAuthError) return reply.code(error.statusCode).send({ error: error.error });
      return reply.code(500).send({ error: "server_error" });
    }
  });

  fastify.get("/.well-known/oauth-authorization-server", async () => oauth.authorizationServerMetadata());
  fastify.get("/.well-known/jwks.json", async () => oauth.jwks());
  const protectedResource = async (request: FastifyRequest, reply: FastifyReply) => {
    const installation = publicInstallation(request);
    if (!installation || installation.status === "revoked") return reply.code(404).send({ error: "resource not found" });
    return service.protectedResourceMetadata(installation);
  };
  fastify.get("/.well-known/oauth-protected-resource", protectedResource);
  fastify.get("/.well-known/oauth-protected-resource/mcp", protectedResource);

  return {
    app: fastify,
    service,
    oauth,
    store,
    ownerAuthenticator,
    ...(ownerBrowser ? { ownerBrowser } : {}),
    close: async () => { await flushStore(store); await fastify.close(); },
  };
};
