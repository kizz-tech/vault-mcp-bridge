import { createLocalJWKSet, createRemoteJWKSet, jwtVerify, type JSONWebKeySet, type JWTPayload } from "jose";
import type { FastifyReply, FastifyRequest } from "fastify";
import { createHash, createHmac, randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { safeEqual } from "./crypto.js";
import type { Principal } from "./types.js";
import type { ServerConfig } from "./config.js";

type AuthResult = { principal: Principal } | { statusCode: 401 | 403; message: string; authenticate?: string };
type Jwks = ReturnType<typeof createLocalJWKSet> | ReturnType<typeof createRemoteJWKSet>;
type OfflineVerification = { jwks: Jwks; expiresAt?: number };

const requestOrigin = (request: FastifyRequest): string => {
  const host = request.headers.host ?? "localhost";
  const scheme = request.headers["x-forwarded-proto"] === "https" ? "https" : "http";
  return `${scheme}://${host}`;
};

export const protectedResourceMetadataUrl = (request: FastifyRequest, config: ServerConfig): string => {
  const resource = new URL(config.mcpResourceUrl ?? `${requestOrigin(request)}/mcp`);
  return new URL(`/.well-known/oauth-protected-resource${resource.pathname}`, resource.origin).toString();
};

const getBearer = (request: FastifyRequest): string | null => {
  const header = request.headers.authorization;
  if (typeof header !== "string") return null;
  const match = /^Bearer\s+([^\s]+)$/iu.exec(header.trim());
  return match?.[1] ?? null;
};

const scopeFromClaims = (payload: JWTPayload): string => {
  if (typeof payload.scope === "string") return payload.scope;
  const scp = payload.scp;
  if (Array.isArray(scp)) return scp.filter((value): value is string => typeof value === "string").join(" ");
  return "";
};

const claimString = (payload: JWTPayload, claimName: string): string | undefined => {
  const value = payload[claimName];
  return typeof value === "string" && value.length > 0 ? value : undefined;
};

const parseJwks = (raw: string): JSONWebKeySet => {
  try {
    const value: unknown = JSON.parse(raw);
    if (!value || typeof value !== "object" || !Array.isArray((value as { keys?: unknown }).keys) || (value as { keys: unknown[] }).keys.length === 0) {
      throw new Error("JWKS must contain a non-empty keys array");
    }
    return value as JSONWebKeySet;
  } catch {
    throw new Error("offline JWKS is invalid");
  }
};

const parseOfflineVerification = (raw: string, config: ServerConfig): OfflineVerification => {
  const parsed = parseJwks(raw) as JSONWebKeySet & { issuer?: unknown; audience?: unknown; issuedAt?: unknown; expiresAt?: unknown };
  const hasBundleMetadata = parsed.issuer !== undefined || parsed.audience !== undefined || parsed.issuedAt !== undefined || parsed.expiresAt !== undefined;
  if (!hasBundleMetadata) {
    if (!config.jwtAllowRawJwks) throw new Error("offline verification bundle metadata is required");
    return { jwks: createLocalJWKSet(parsed) };
  }
  if (parsed.issuer !== config.jwtIssuer || parsed.audience !== config.jwtAudience || typeof parsed.issuedAt !== "string" || typeof parsed.expiresAt !== "string") {
    throw new Error("offline verification bundle issuer or audience does not match server configuration");
  }
  const issuedAt = Date.parse(parsed.issuedAt);
  const expiresAt = Date.parse(parsed.expiresAt);
  if (!Number.isFinite(issuedAt) || !Number.isFinite(expiresAt) || expiresAt <= issuedAt) throw new Error("offline verification bundle lifetime is invalid");
  return { jwks: createLocalJWKSet(parsed), expiresAt };
};

const loadOfflineJwks = (config: ServerConfig): OfflineVerification | undefined => {
  if (config.jwtJwksJson) return parseOfflineVerification(config.jwtJwksJson, config);
  if (config.jwtJwksFile) {
    let raw: string;
    try {
      raw = readFileSync(config.jwtJwksFile, "utf8");
    } catch {
      throw new Error("offline JWKS file is unavailable");
    }
    return parseOfflineVerification(raw, config);
  }
  return undefined;
};

export class McpAuthenticator {
  private readonly jwks: Jwks | undefined;
  private readonly offlineBundleExpiresAt: number | undefined;

  constructor(private readonly config: ServerConfig) {
    if (config.nodeEnv === "production") {
      const offline = loadOfflineJwks(config);
      this.jwks = offline?.jwks ?? (config.jwtAllowRemoteJwks && config.jwtJwksUrl ? createRemoteJWKSet(new URL(config.jwtJwksUrl)) : undefined);
      this.offlineBundleExpiresAt = offline?.expiresAt;
    }
  }

  /**
   * Reports only whether bearer authentication can currently be served. The
   * bundle expiry is checked at request time as well, so readiness changes
   * from healthy to unavailable without restarting the server.
   */
  readiness(): { ok: boolean } {
    if (this.config.nodeEnv !== "production") return { ok: true };
    const verifierConfigured = this.jwks !== undefined && Boolean(this.config.jwtIssuer && this.config.jwtAudience);
    const offlineBundleFresh = this.offlineBundleExpiresAt === undefined || Date.now() < this.offlineBundleExpiresAt;
    return { ok: verifierConfigured && offlineBundleFresh };
  }

  async authenticate(request: FastifyRequest): Promise<AuthResult> {
    const challenge = (error?: string): string => {
      const fields = ['Bearer realm="mcp"', `resource_metadata="${protectedResourceMetadataUrl(request, this.config)}"`, `scope="${this.config.jwtScope}"`];
      if (error) fields.push(`error="${error}"`);
      return fields.join(", ");
    };
    const token = getBearer(request);
    if (!token) return { statusCode: 401, message: "bearer token required", authenticate: challenge() };
    if (this.config.nodeEnv !== "production") {
      if (!this.config.mcpDevToken || !safeEqual(token, this.config.mcpDevToken)) return { statusCode: 401, message: "invalid bearer token", authenticate: challenge("invalid_token") };
      return { principal: { subject: "development", scope: this.config.jwtScope, ...(this.config.mcpVaultId ? { vaultId: this.config.mcpVaultId } : {}), ...(this.config.mcpInstallationId ? { installationId: this.config.mcpInstallationId } : {}) } };
    }
    if (this.offlineBundleExpiresAt !== undefined && Date.now() >= this.offlineBundleExpiresAt) return { statusCode: 401, message: "authentication unavailable", authenticate: challenge("temporarily_unavailable") };
    if (!this.jwks || !this.config.jwtIssuer || !this.config.jwtAudience) return { statusCode: 401, message: "authentication unavailable", authenticate: challenge("temporarily_unavailable") };
    try {
      const result = await jwtVerify(token, this.jwks, {
        issuer: this.config.jwtIssuer,
        audience: this.config.jwtAudience,
        algorithms: ["RS256", "ES256", "EdDSA"],
      });
      const scope = scopeFromClaims(result.payload);
      if (!scope.split(/\s+/u).includes(this.config.jwtScope)) return { statusCode: 403, message: "required scope missing", authenticate: challenge("insufficient_scope") };
      const subject = typeof result.payload.sub === "string" ? result.payload.sub : "";
      if (!subject || typeof result.payload.exp !== "number") return { statusCode: 401, message: "invalid bearer token", authenticate: challenge("invalid_token") };
      const installationId = claimString(result.payload, this.config.jwtInstallationClaim);
      const vaultId = claimString(result.payload, this.config.jwtVaultClaim);
      const clientId = claimString(result.payload, this.config.jwtClientClaim) ?? claimString(result.payload, "azp");
      if (!installationId || !this.config.mcpInstallationId || installationId !== this.config.mcpInstallationId) return { statusCode: 401, message: "invalid bearer token", authenticate: challenge("invalid_token") };
      if (!vaultId || !this.config.mcpVaultId || vaultId !== this.config.mcpVaultId) return { statusCode: 401, message: "invalid bearer token", authenticate: challenge("invalid_token") };
      if (!clientId || (this.config.jwtClientId && clientId !== this.config.jwtClientId)) return { statusCode: 401, message: "invalid bearer token", authenticate: challenge("invalid_token") };
      return { principal: { subject, scope, clientId, vaultId, installationId } };
    } catch {
      return { statusCode: 401, message: "invalid bearer token", authenticate: challenge("invalid_token") };
    }
  }
}

export type AttestationRequest = Pick<FastifyRequest, "method" | "url" | "headers">;

export type PublisherEdgeAttestationOptions = {
  certStatus?: string;
  timestamp?: number;
  nonce?: string;
  attestationHeader?: string;
  certStatusHeader?: string;
  timestampHeader?: string;
  nonceHeader?: string;
};

const attestationPayload = (request: AttestationRequest, certStatus: string, timestamp: string, nonce: string): string => {
  const exactUrl = request.url || "/";
  const host = String(request.headers.host ?? "").toLowerCase();
  return [request.method.toUpperCase(), exactUrl, host, certStatus, timestamp, nonce].join("\n");
};

const readAttestationSecret = (config: ServerConfig): Buffer | null => {
  const configured = config.publisherEdgeAttestationSecret ?? (config.publisherEdgeAttestationSecretFile ? (() => {
    try {
      return readFileSync(config.publisherEdgeAttestationSecretFile!, "utf8").trim();
    } catch {
      return "";
    }
  })() : "");
  if (!configured || configured.length < 32) return null;
  return Buffer.from(configured, "utf8");
};

/**
 * Verifies the edge's mTLS result without trusting a bare client-supplied
 * status header. The edge signs the request surface and status with an
 * installation-scoped secret that is provisioned out-of-band. A direct
 * request can therefore not bypass publisher mTLS by setting headers.
 */
export class PublisherEdgeAttestor {
  private readonly secret: Buffer | null;
  private readonly usedNonces = new Map<string, number>();

  constructor(private readonly config: ServerConfig) {
    this.secret = readAttestationSecret(config);
    if (config.nodeEnv === "production" && config.publisherMtlsRequired && !this.secret) {
      throw new Error("publisher edge mTLS attestation secret is unavailable");
    }
  }

  private pruneNonces(now: number): void {
    const retentionMs = Math.max(60_000, this.config.maxClockSkewSeconds * 2_000);
    for (const [nonce, seenAt] of this.usedNonces) {
      if (now - seenAt > retentionMs) this.usedNonces.delete(nonce);
    }
  }

  private evictOldest(): void {
    const oldest = this.usedNonces.keys().next().value;
    if (typeof oldest === "string") this.usedNonces.delete(oldest);
  }

  verify(request: FastifyRequest): boolean {
    if (!this.config.publisherMtlsRequired) return true;
    if (!this.secret) return false;
    const now = Date.now();
    this.pruneNonces(now);
    const status = request.headers[this.config.publisherEdgeCertStatusHeader.toLowerCase()];
    const signature = request.headers[this.config.publisherEdgeAttestationHeader.toLowerCase()];
    const timestampRaw = request.headers[this.config.publisherEdgeTimestampHeader.toLowerCase()];
    const nonce = request.headers[this.config.publisherEdgeNonceHeader.toLowerCase()];
    if (typeof status !== "string" || status !== this.config.publisherEdgeCertStatus || typeof signature !== "string" || !/^[A-Za-z0-9_-]{43}$/u.test(signature) || typeof timestampRaw !== "string" || !/^\d{1,12}$/u.test(timestampRaw) || typeof nonce !== "string" || !/^[A-Za-z0-9._~-]{22,128}$/u.test(nonce)) return false;
    const timestamp = Number(timestampRaw);
    if (!Number.isSafeInteger(timestamp) || Math.abs(Math.floor(now / 1000) - timestamp) > this.config.maxClockSkewSeconds) return false;
    const expected = createHmac("sha256", this.secret).update(attestationPayload(request, status, timestampRaw, nonce)).digest("base64url");
    if (!safeEqual(signature, expected) || this.usedNonces.has(nonce)) return false;
    if (this.usedNonces.size >= this.config.maxPublisherEdgeAttestationEntries) this.evictOldest();
    this.usedNonces.set(nonce, now);
    return true;
  }
}

/** Deterministic signer used by local edge adapters and synthetic tests. */
export const publisherEdgeAttestationForRequest = (request: AttestationRequest, secret: string, options: PublisherEdgeAttestationOptions = {}): Readonly<Record<string, string>> => {
  const certStatus = options.certStatus ?? "verified";
  const timestamp = String(options.timestamp ?? Math.floor(Date.now() / 1000));
  const nonce = options.nonce ?? randomBytes(24).toString("base64url");
  const attestationHeader = options.attestationHeader ?? "x-vmb-edge-attestation";
  const certStatusHeader = options.certStatusHeader ?? "x-vmb-edge-mtls-status";
  const timestampHeader = options.timestampHeader ?? "x-vmb-edge-timestamp";
  const nonceHeader = options.nonceHeader ?? "x-vmb-edge-nonce";
  const signature = createHmac("sha256", Buffer.from(secret, "utf8")).update(attestationPayload(request, certStatus, timestamp, nonce)).digest("base64url");
  return { [attestationHeader]: signature, [certStatusHeader]: certStatus, [timestampHeader]: timestamp, [nonceHeader]: nonce };
};

export const publisherEdgeAttestationHeadersForRequest = publisherEdgeAttestationForRequest;

/** Signature-only compatibility helper for non-HTTP callers. */
export const publisherEdgeAttestationSignatureForRequest = (request: AttestationRequest, secret: string, options: PublisherEdgeAttestationOptions = {}): string => {
  const headers = publisherEdgeAttestationForRequest(request, secret, options);
  return headers[options.attestationHeader ?? "x-vmb-edge-attestation"] ?? "";
};

export type McpEdgeAttestationOptions = {
  timestamp?: number;
  nonce?: string;
  attestationHeader?: string;
  timestampHeader?: string;
  nonceHeader?: string;
};

const bearerTokenDigest = (token: string): string => createHash("sha256").update(token, "utf8").digest("base64url");

/**
 * The MCP edge signs the complete request surface and the bearer token's
 * digest. The edge Worker strips these headers from the incoming request and
 * adds fresh values after its online token decision; the origin therefore
 * treats them as an untrusted proof until this HMAC verifies.
 */
const mcpEdgeAttestationPayload = (request: AttestationRequest, tokenDigest: string, timestamp: string, nonce: string): string => {
  const method = request.method.toUpperCase();
  const hostHeader = request.headers.host;
  if (typeof hostHeader !== "string" || hostHeader.length === 0) throw new Error("MCP edge attestation host is missing");
  const url = new URL(request.url || "/", `http://${hostHeader}`);
  const pathWithQuery = `${url.pathname || "/"}${url.search}`;
  const host = new URL(`http://${hostHeader}`).hostname.toLowerCase();
  return [method, pathWithQuery, host, tokenDigest, timestamp, nonce].join("\n");
};

const readMcpEdgeAttestationSecret = (config: ServerConfig): Buffer | null => {
  const configured = config.mcpEdgeAttestationSecret ?? (config.mcpEdgeAttestationSecretFile ? (() => {
    try {
      return readFileSync(config.mcpEdgeAttestationSecretFile!, "utf8").trim();
    } catch {
      return "";
    }
  })() : "");
  if (!configured || configured.length < 32) return null;
  return Buffer.from(configured, "utf8");
};

/**
 * Verifies the Worker-to-origin MCP admission proof. This credential is
 * intentionally separate from publisher mTLS attestation and is bound to the
 * exact request URL/host plus the bearer token, preventing direct-origin
 * callers from substituting a different token or replaying an old request.
 */
export class McpEdgeAttestor {
  private readonly secret: Buffer | null;
  private readonly usedNonces = new Map<string, number>();

  constructor(private readonly config: ServerConfig) {
    this.secret = readMcpEdgeAttestationSecret(config);
    if (config.nodeEnv === "production" && !this.secret) {
      throw new Error("MCP edge attestation secret is unavailable");
    }
  }

  private pruneNonces(now: number): void {
    const retentionMs = Math.max(60_000, this.config.maxClockSkewSeconds * 2_000);
    for (const [nonce, seenAt] of this.usedNonces) {
      if (now - seenAt > retentionMs) this.usedNonces.delete(nonce);
    }
  }

  private evictOldest(): void {
    const oldest = this.usedNonces.keys().next().value;
    if (typeof oldest === "string") this.usedNonces.delete(oldest);
  }

  verify(request: FastifyRequest): boolean {
    // Development/test servers retain the existing local bearer-token path
    // when no synthetic MCP edge secret is configured. Once a secret is
    // provided (including tests), the edge proof is enforced as normal.
    if (!this.secret && this.config.nodeEnv !== "production") return true;
    if (!this.secret) return false;
    const token = getBearer(request);
    if (!token) return false;
    const host = request.headers.host;
    if (typeof host !== "string" || host.length === 0) return false;
    const now = Date.now();
    this.pruneNonces(now);
    const signature = request.headers[this.config.mcpEdgeAttestationHeader.toLowerCase()];
    const timestampRaw = request.headers[this.config.mcpEdgeTimestampHeader.toLowerCase()];
    const nonce = request.headers[this.config.mcpEdgeNonceHeader.toLowerCase()];
    if (typeof signature !== "string" || !/^[A-Za-z0-9_-]{43}$/u.test(signature) || typeof timestampRaw !== "string" || !/^\d{1,12}$/u.test(timestampRaw) || typeof nonce !== "string" || !/^[A-Za-z0-9._~-]{22,128}$/u.test(nonce)) return false;
    const timestamp = Number(timestampRaw);
    if (!Number.isSafeInteger(timestamp) || Math.abs(Math.floor(now / 1000) - timestamp) > this.config.maxClockSkewSeconds) return false;
    const digest = bearerTokenDigest(token);
    let expected: string;
    try {
      expected = createHmac("sha256", this.secret).update(mcpEdgeAttestationPayload(request, digest, timestampRaw, nonce)).digest("base64url");
    } catch {
      return false;
    }
    if (!safeEqual(signature, expected) || this.usedNonces.has(nonce)) return false;
    if (this.usedNonces.size >= this.config.maxMcpEdgeAttestationEntries) this.evictOldest();
    this.usedNonces.set(nonce, now);
    return true;
  }
}

/** Deterministic signer used by the Worker adapter and synthetic tests. */
export const mcpEdgeAttestationForRequest = (request: AttestationRequest, secret: string, bearerToken: string, options: McpEdgeAttestationOptions = {}): Readonly<Record<string, string>> => {
  const timestamp = String(options.timestamp ?? Math.floor(Date.now() / 1000));
  const nonce = options.nonce ?? randomBytes(24).toString("base64url");
  const attestationHeader = options.attestationHeader ?? "x-vmb-mcp-edge-attestation";
  const timestampHeader = options.timestampHeader ?? "x-vmb-mcp-edge-timestamp";
  const nonceHeader = options.nonceHeader ?? "x-vmb-mcp-edge-nonce";
  const digest = bearerTokenDigest(bearerToken);
  const signature = createHmac("sha256", Buffer.from(secret, "utf8")).update(mcpEdgeAttestationPayload(request, digest, timestamp, nonce)).digest("base64url");
  return { [attestationHeader]: signature, [timestampHeader]: timestamp, [nonceHeader]: nonce };
};

export const mcpEdgeAttestationHeadersForRequest = mcpEdgeAttestationForRequest;

/** Signature-only compatibility helper for non-HTTP callers. */
export const mcpEdgeAttestationSignatureForRequest = (request: AttestationRequest, secret: string, bearerToken: string, options: McpEdgeAttestationOptions = {}): string => {
  const headers = mcpEdgeAttestationForRequest(request, secret, bearerToken, options);
  return headers[options.attestationHeader ?? "x-vmb-mcp-edge-attestation"] ?? "";
};

export const enforceHostAndOrigin = (request: FastifyRequest, config: ServerConfig, allowedHosts: ReadonlySet<string> = config.allowedHosts): { statusCode: 403; message: string } | null => {
  const hostHeader = request.headers.host;
  if (typeof hostHeader !== "string") return { statusCode: 403, message: "host is not allowed" };
  const host = hostHeader.toLowerCase().replace(/:\d+$/u, "");
  const hosts = allowedHosts;
  if (hosts.size > 0 && !hosts.has(host) && !hosts.has(hostHeader.toLowerCase())) return { statusCode: 403, message: "host is not allowed" };
  const origin = request.headers.origin;
  if (typeof origin === "string" && (config.allowedOrigins.size === 0 || !config.allowedOrigins.has(origin))) return { statusCode: 403, message: "origin is not allowed" };
  return null;
};

export const protectedResourceMetadata = (request: FastifyRequest, config: ServerConfig): Record<string, unknown> => {
  const resource = config.mcpResourceUrl ?? `${requestOrigin(request)}/mcp`;
  const metadata: Record<string, unknown> = {
    resource,
    scopes_supported: [config.jwtScope],
    bearer_methods_supported: ["header"],
  };
  if (config.jwtIssuer) metadata.authorization_servers = [config.jwtIssuer];
  return metadata;
};

export const sendAuthError = (reply: FastifyReply, result: Exclude<AuthResult, { principal: Principal }>): FastifyReply => {
  if (result.authenticate) reply.header("WWW-Authenticate", result.authenticate);
  return reply.code(result.statusCode).send({ error: result.message });
};

type Bucket = { tokens: number; updatedAt: number; active: number };

export class PrincipalGuard {
  private readonly buckets = new Map<string, Bucket>();
  constructor(private readonly config: ServerConfig) {}

  get size(): number {
    return this.buckets.size;
  }

  private prune(now: number): void {
    const ttl = this.config.principalBucketTtlSeconds * 1000;
    for (const [subject, bucket] of this.buckets) {
      if (bucket.active === 0 && now - bucket.updatedAt > ttl) this.buckets.delete(subject);
    }
  }

  private evictOldestInactive(): void {
    for (const [subject, bucket] of this.buckets) {
      if (bucket.active === 0) {
        this.buckets.delete(subject);
        return;
      }
    }
  }

  enter(subject: string): boolean {
    const now = Date.now();
    this.prune(now);
    let existing = this.buckets.get(subject);
    if (!existing && this.buckets.size >= this.config.maxPrincipalBuckets) {
      this.evictOldestInactive();
      if (this.buckets.size >= this.config.maxPrincipalBuckets) return false;
    }
    existing ??= { tokens: this.config.requestBurst, updatedAt: now, active: 0 };
    const elapsedSeconds = (now - existing.updatedAt) / 1000;
    existing.tokens = Math.min(this.config.requestBurst, existing.tokens + elapsedSeconds * (this.config.requestRatePerMinute / 60));
    existing.updatedAt = now;
    if (existing.active >= this.config.maxConcurrentPerPrincipal || existing.tokens < 1) {
      this.buckets.set(subject, existing);
      return false;
    }
    existing.tokens -= 1;
    existing.active += 1;
    this.buckets.set(subject, existing);
    return true;
  }

  leave(subject: string): void {
    const bucket = this.buckets.get(subject);
    if (bucket) bucket.active = Math.max(0, bucket.active - 1);
  }
}
