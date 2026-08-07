import { resolve } from "node:path";
import { LIMITS } from "@vault-mcp-bridge/contracts";

export type ServerConfig = {
  nodeEnv: "development" | "test" | "production";
  host: string;
  port: number;
  databasePath: string;
  allowedHosts: ReadonlySet<string>;
  allowedOrigins: ReadonlySet<string>;
  mcpHosts: ReadonlySet<string>;
  publisherHosts: ReadonlySet<string>;
  mcpResourceUrl?: string;
  publisherPublicUrl?: string;
  pairingTtlSeconds: number;
  maxBodyBytes: number;
  maxSnapshotBytes: number;
  maxDocumentBytes: number;
  maxSearchQueryBytes: number;
  maxSearchResults: number;
  maxFetchBytes: number;
  maxClockSkewSeconds: number;
  nonceRetentionSeconds: number;
  maxRequestSeconds: number;
  /** Maximum bytes retained for one vault (active + rollback generation). */
  maxVaultBytes: number;
  /** Maximum aggregate SQLite bytes, including WAL/SHM sidecars. */
  maxDatabaseBytes: number;
  /** Maximum bytes consumed by FTS/index pages. */
  maxIndexBytes: number;
  /** Maximum SQLite sidecar/temp bytes accepted before an ingest. */
  maxTempBytes: number;
  /** Minimum free bytes required on the database filesystem. */
  minFreeBytes: number;
  /** Number of generations retained per vault; V1 requires at least two. */
  maxRetainedGenerations: number;
  mcpReadsDisabled: boolean;
  publisherIngestDisabled: boolean;
  publisherMtlsRequired: boolean;
  publisherEdgeAttestationHeader: string;
  publisherEdgeCertStatusHeader: string;
  publisherEdgeCertStatus: string;
  publisherEdgeTimestampHeader: string;
  publisherEdgeNonceHeader: string;
  maxPublisherEdgeAttestationEntries: number;
  publisherEdgeAttestationSecret?: string;
  publisherEdgeAttestationSecretFile?: string;
  mcpEdgeAttestationHeader: string;
  mcpEdgeTimestampHeader: string;
  mcpEdgeNonceHeader: string;
  maxMcpEdgeAttestationEntries: number;
  mcpEdgeAttestationSecret?: string;
  mcpEdgeAttestationSecretFile?: string;
  mcpVaultId?: string;
  mcpInstallationId?: string;
  mcpDevToken?: string;
  jwtIssuer?: string;
  jwtAudience?: string;
  jwtJwksUrl?: string;
  jwtJwksFile?: string;
  jwtJwksJson?: string;
  /** Explicit Advanced-mode escape hatch; disabled by default so the server
   * never attempts network JWKS discovery from an internal-only container. */
  jwtAllowRemoteJwks: boolean;
  /** Advanced escape hatch for a raw JWKS without managed bundle metadata. */
  jwtAllowRawJwks: boolean;
  jwtClientId?: string;
  jwtInstallationClaim: string;
  jwtVaultClaim: string;
  jwtClientClaim: string;
  jwtScope: string;
  requestRatePerMinute: number;
  requestBurst: number;
  maxConcurrentPerPrincipal: number;
  maxPrincipalBuckets: number;
  principalBucketTtlSeconds: number;
};

const splitList = (value: string | undefined, fallback: string[]): ReadonlySet<string> => {
  const values = (value ?? "")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
  return new Set(values.length > 0 ? values : fallback);
};

const parseInteger = (value: string | undefined, fallback: number, minimum: number): number => {
  const parsed = Number.parseInt(value ?? "", 10);
  return Number.isFinite(parsed) && parsed >= minimum ? parsed : fallback;
};

const parseBoolean = (value: string | undefined, fallback: boolean): boolean => {
  if (value === undefined) return fallback;
  return value === "true" || value === "1" || value === "yes";
};

export const loadConfig = (env: NodeJS.ProcessEnv = process.env): ServerConfig => {
  const nodeEnv = env.NODE_ENV === "production" ? "production" : env.NODE_ENV === "test" ? "test" : "development";
  const configuredDatabasePath = env.SERVER_DATABASE_PATH ?? ".data/vault-mcp-bridge.sqlite";
  const databasePath = configuredDatabasePath === ":memory:" ? configuredDatabasePath : resolve(configuredDatabasePath);
  const developmentToken = nodeEnv === "production" ? undefined : env.MCP_DEV_TOKEN?.trim() || undefined;
  const allowedHosts = splitList(env.ALLOWED_HOSTS, nodeEnv === "production" ? [] : ["127.0.0.1", "localhost"]);
  const allowedOrigins = splitList(env.ALLOWED_ORIGINS, nodeEnv === "production" ? [] : ["http://127.0.0.1:8787", "http://localhost:8787"]);
  const nonceRetentionSeconds = parseInteger(env.NONCE_RETENTION_SECONDS, 86_400, 60);
  const maxClockSkewSeconds = Math.min(parseInteger(env.MAX_CLOCK_SKEW_SECONDS, 300, 1), nonceRetentionSeconds - 1);
  const result: ServerConfig = {
    nodeEnv,
    host: env.SERVER_HOST ?? "127.0.0.1",
    port: parseInteger(env.SERVER_PORT, 8787, 1),
    databasePath,
    allowedHosts,
    allowedOrigins,
    mcpHosts: splitList(env.MCP_HOSTS, nodeEnv === "production" ? [] : [...allowedHosts]),
    publisherHosts: splitList(env.PUBLISHER_HOSTS, nodeEnv === "production" ? [] : [...allowedHosts]),
    pairingTtlSeconds: parseInteger(env.PAIRING_TTL_SECONDS, 600, 30),
    maxBodyBytes: parseInteger(env.MAX_BODY_BYTES ?? env.MCP_RESPONSE_BODY_LIMIT_BYTES, LIMITS.maxSnapshotBytes + 64 * 1024, 1024),
    maxSnapshotBytes: Math.min(parseInteger(env.MAX_SNAPSHOT_BYTES, LIMITS.maxSnapshotBytes, 1024), LIMITS.maxSnapshotBytes),
    maxDocumentBytes: Math.min(parseInteger(env.MAX_DOCUMENT_BYTES, LIMITS.maxDocumentTextBytes, 1024), LIMITS.maxDocumentTextBytes),
    maxSearchQueryBytes: Math.min(parseInteger(env.MAX_SEARCH_QUERY_BYTES, LIMITS.maxQueryChars, 1), LIMITS.maxQueryChars),
    maxSearchResults: Math.min(parseInteger(env.MAX_SEARCH_RESULTS, LIMITS.maxResults, 1), LIMITS.maxResults),
    maxFetchBytes: Math.min(parseInteger(env.MAX_FETCH_BYTES, LIMITS.maxFetchedTextBytes, 1), LIMITS.maxFetchedTextBytes),
    maxClockSkewSeconds,
    nonceRetentionSeconds,
    maxRequestSeconds: parseInteger(env.MAX_REQUEST_SECONDS, 30, 1),
    maxVaultBytes: parseInteger(env.MAX_VAULT_BYTES ?? env.MCP_REPLICA_BYTES_LIMIT, 512 * 1024 * 1024, 1),
    maxDatabaseBytes: parseInteger(env.MAX_DATABASE_BYTES ?? env.MCP_DATABASE_BYTES_LIMIT, 2 * 1024 * 1024 * 1024, 1),
    maxIndexBytes: parseInteger(env.MAX_INDEX_BYTES ?? env.MCP_INDEX_BYTES_LIMIT, 1024 * 1024 * 1024, 1),
    maxTempBytes: parseInteger(env.MAX_TEMP_BYTES ?? env.MCP_STAGING_BYTES_LIMIT ?? env.MCP_TEMP_BYTES_LIMIT, 128 * 1024 * 1024, 1),
    minFreeBytes: parseInteger(env.MIN_FREE_BYTES ?? env.MCP_FREE_SPACE_RESERVE_BYTES, 256 * 1024 * 1024, 0),
    maxRetainedGenerations: Math.max(2, parseInteger(env.MAX_RETAINED_GENERATIONS ?? env.MCP_RETAINED_GENERATIONS, 2, 2)),
    mcpReadsDisabled: env.MCP_READS_DISABLED === "true" || env.MCP_READS_DISABLED === "1",
    publisherIngestDisabled: env.PUBLISHER_INGEST_DISABLED === "true" || env.PUBLISHER_INGEST_DISABLED === "1",
    publisherMtlsRequired: parseBoolean(env.PUBLISHER_MTLS_REQUIRED, nodeEnv === "production"),
    publisherEdgeAttestationHeader: env.PUBLISHER_EDGE_ATTESTATION_HEADER?.trim() || "x-vmb-edge-attestation",
    publisherEdgeCertStatusHeader: env.PUBLISHER_EDGE_CERT_STATUS_HEADER?.trim() || "x-vmb-edge-mtls-status",
    publisherEdgeCertStatus: env.PUBLISHER_EDGE_CERT_STATUS?.trim() || "verified",
    publisherEdgeTimestampHeader: env.PUBLISHER_EDGE_TIMESTAMP_HEADER?.trim() || "x-vmb-edge-timestamp",
    publisherEdgeNonceHeader: env.PUBLISHER_EDGE_NONCE_HEADER?.trim() || "x-vmb-edge-nonce",
    maxPublisherEdgeAttestationEntries: parseInteger(env.MAX_PUBLISHER_EDGE_ATTESTATION_ENTRIES, 10_000, 1),
    mcpEdgeAttestationHeader: env.MCP_EDGE_ATTESTATION_HEADER?.trim() || "x-vmb-mcp-edge-attestation",
    mcpEdgeTimestampHeader: env.MCP_EDGE_TIMESTAMP_HEADER?.trim() || "x-vmb-mcp-edge-timestamp",
    mcpEdgeNonceHeader: env.MCP_EDGE_NONCE_HEADER?.trim() || "x-vmb-mcp-edge-nonce",
    maxMcpEdgeAttestationEntries: parseInteger(env.MAX_MCP_EDGE_ATTESTATION_ENTRIES, 10_000, 1),
    ...(env.MCP_VAULT_ID ? { mcpVaultId: env.MCP_VAULT_ID } : {}),
    ...(env.MCP_INSTALLATION_ID ? { mcpInstallationId: env.MCP_INSTALLATION_ID } : {}),
    jwtInstallationClaim: env.JWT_INSTALLATION_CLAIM?.trim() || "installation_id",
    jwtVaultClaim: env.JWT_VAULT_CLAIM?.trim() || "vault_id",
    jwtClientClaim: env.JWT_CLIENT_CLAIM?.trim() || "client_id",
    jwtAllowRemoteJwks: parseBoolean(env.JWT_ALLOW_REMOTE_JWKS, false),
    jwtAllowRawJwks: parseBoolean(env.JWT_ALLOW_RAW_JWKS, false),
    jwtScope: env.JWT_SCOPE ?? "vault:read",
    requestRatePerMinute: parseInteger(env.REQUEST_RATE_PER_MINUTE, 60, 1),
    requestBurst: parseInteger(env.REQUEST_BURST, 20, 1),
    maxConcurrentPerPrincipal: parseInteger(env.MAX_CONCURRENT_PER_PRINCIPAL, 4, 1),
    maxPrincipalBuckets: parseInteger(env.MAX_PRINCIPAL_BUCKETS, 10_000, 1),
    principalBucketTtlSeconds: parseInteger(env.PRINCIPAL_BUCKET_TTL_SECONDS, 900, 1),
  };
  if (developmentToken) result.mcpDevToken = developmentToken;
  if (env.JWT_ISSUER) result.jwtIssuer = env.JWT_ISSUER;
  if (env.JWT_AUDIENCE) result.jwtAudience = env.JWT_AUDIENCE;
  if (env.JWT_JWKS_URL) result.jwtJwksUrl = env.JWT_JWKS_URL;
  if (env.JWT_JWKS_FILE) result.jwtJwksFile = resolve(env.JWT_JWKS_FILE);
  if (env.JWT_JWKS_JSON) result.jwtJwksJson = env.JWT_JWKS_JSON;
  if (env.JWT_CLIENT_ID) result.jwtClientId = env.JWT_CLIENT_ID;
  if (env.PUBLISHER_EDGE_ATTESTATION_SECRET) result.publisherEdgeAttestationSecret = env.PUBLISHER_EDGE_ATTESTATION_SECRET;
  if (env.PUBLISHER_EDGE_ATTESTATION_SECRET_FILE) result.publisherEdgeAttestationSecretFile = resolve(env.PUBLISHER_EDGE_ATTESTATION_SECRET_FILE);
  if (env.MCP_EDGE_ATTESTATION_SECRET) result.mcpEdgeAttestationSecret = env.MCP_EDGE_ATTESTATION_SECRET;
  if (env.MCP_EDGE_ATTESTATION_SECRET_FILE) result.mcpEdgeAttestationSecretFile = resolve(env.MCP_EDGE_ATTESTATION_SECRET_FILE);
  if (env.MCP_RESOURCE_URL) result.mcpResourceUrl = env.MCP_RESOURCE_URL;
  if (env.PUBLISHER_PUBLIC_URL) result.publisherPublicUrl = env.PUBLISHER_PUBLIC_URL;
  return result;
};

export const assertProductionConfig = (config: ServerConfig): void => {
  assertConfigSafety(config);
  if (config.nodeEnv !== "production") return;
  if (config.databasePath === ":memory:") throw new Error("SERVER_DATABASE_PATH must be durable in production");
  const missing = [
    ["JWT_ISSUER", config.jwtIssuer],
    ["JWT_AUDIENCE", config.jwtAudience],
    ["MCP_RESOURCE_URL", config.mcpResourceUrl],
    ["PUBLISHER_PUBLIC_URL", config.publisherPublicUrl],
    ["MCP_VAULT_ID", config.mcpVaultId],
    ["MCP_INSTALLATION_ID", config.mcpInstallationId],
  ].filter(([, value]) => !value).map(([name]) => name);
  if (!config.jwtJwksFile && !config.jwtJwksJson && !(config.jwtAllowRemoteJwks && config.jwtJwksUrl)) {
    missing.push(config.jwtAllowRemoteJwks ? "JWT_JWKS_URL" : "JWT_JWKS_FILE or JWT_JWKS_JSON (or explicitly enable JWT_ALLOW_REMOTE_JWKS)");
  }
  if (config.allowedHosts.size === 0) missing.push("ALLOWED_HOSTS");
  if (config.mcpHosts.size === 0) missing.push("MCP_HOSTS");
  if (config.publisherHosts.size === 0) missing.push("PUBLISHER_HOSTS");
  if (missing.length > 0) {
    throw new Error(`production authentication is not configured: ${missing.join(", ")}`);
  }
  if (config.mcpDevToken) {
    throw new Error("MCP_DEV_TOKEN must not be configured in production");
  }
  if (!config.publisherMtlsRequired) throw new Error("PUBLISHER_MTLS_REQUIRED must be enabled in production");
  if (!config.publisherEdgeAttestationSecret && !config.publisherEdgeAttestationSecretFile) {
    throw new Error("publisher edge mTLS attestation is not configured");
  }
  if (config.publisherEdgeAttestationSecret && config.publisherEdgeAttestationSecret.length < 32) {
    throw new Error("PUBLISHER_EDGE_ATTESTATION_SECRET must be at least 32 characters");
  }
  if (!config.publisherEdgeCertStatus) throw new Error("publisher edge mTLS status is not configured");
  if (!config.mcpEdgeAttestationSecretFile) {
    throw new Error("MCP_EDGE_ATTESTATION_SECRET_FILE must be configured in production");
  }
  if (config.mcpEdgeAttestationSecret) {
    throw new Error("MCP_EDGE_ATTESTATION_SECRET is test-only and must not be configured in production");
  }
  if (!/^[A-Za-z0-9_-]{16,256}$/u.test(config.mcpInstallationId!)) throw new Error("MCP_INSTALLATION_ID must be an opaque installation identifier");
  for (const claim of [config.jwtInstallationClaim, config.jwtVaultClaim, config.jwtClientClaim]) {
    if (!/^[A-Za-z][A-Za-z0-9_-]{0,63}$/u.test(claim)) throw new Error("JWT claim name is invalid");
  }
  const publisherHostSet = new Set([...config.publisherHosts].map((host) => host.toLowerCase()));
  const overlappingHosts = [...config.mcpHosts].filter((host) => publisherHostSet.has(host.toLowerCase()));
  if (overlappingHosts.length > 0) throw new Error(`MCP_HOSTS and PUBLISHER_HOSTS must not overlap: ${overlappingHosts.join(", ")}`);
  if (!/^[A-Za-z0-9_-]{16,256}$/u.test(config.mcpVaultId!)) throw new Error("MCP_VAULT_ID must be an opaque vault identifier");
  for (const [name, value] of [["JWT_ISSUER", config.jwtIssuer], ["MCP_RESOURCE_URL", config.mcpResourceUrl], ["PUBLISHER_PUBLIC_URL", config.publisherPublicUrl]] as const) {
    if (!value || new URL(value).protocol !== "https:") throw new Error(`${name} must be an HTTPS URL in production`);
  }
  if (config.jwtJwksUrl && new URL(config.jwtJwksUrl).protocol !== "https:") throw new Error("JWT_JWKS_URL must be an HTTPS URL in production");
  const resource = new URL(config.mcpResourceUrl!);
  const publisher = new URL(config.publisherPublicUrl!);
  if (resource.pathname !== "/mcp" || resource.search || resource.hash) throw new Error("MCP_RESOURCE_URL must end at /mcp");
  if (publisher.pathname !== "/" || publisher.search || publisher.hash) throw new Error("PUBLISHER_PUBLIC_URL must be an origin URL");
  if (!config.mcpHosts.has(resource.hostname.toLowerCase())) throw new Error("MCP_RESOURCE_URL host must be in MCP_HOSTS");
  if (!config.publisherHosts.has(publisher.hostname.toLowerCase())) throw new Error("PUBLISHER_PUBLIC_URL host must be in PUBLISHER_HOSTS");
  for (const host of [...config.mcpHosts, ...config.publisherHosts]) {
    if (!config.allowedHosts.has(host)) throw new Error("surface hosts must also be present in ALLOWED_HOSTS");
  }
};

export const assertConfigSafety = (config: ServerConfig): void => {
  if (config.maxClockSkewSeconds >= config.nonceRetentionSeconds) {
    throw new Error("MAX_CLOCK_SKEW_SECONDS must be below NONCE_RETENTION_SECONDS");
  }
  const edgeHeaders = [
    config.publisherEdgeAttestationHeader,
    config.publisherEdgeCertStatusHeader,
    config.publisherEdgeTimestampHeader,
    config.publisherEdgeNonceHeader,
  ].map((header) => header.toLowerCase());
  if (edgeHeaders.some((header) => !/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/u.test(header)) || new Set(edgeHeaders).size !== edgeHeaders.length) {
    throw new Error("publisher edge attestation header names must be valid and distinct");
  }
  const mcpEdgeHeaders = [
    config.mcpEdgeAttestationHeader,
    config.mcpEdgeTimestampHeader,
    config.mcpEdgeNonceHeader,
  ].map((header) => header.toLowerCase());
  if (mcpEdgeHeaders.some((header) => !/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/u.test(header)) || new Set(mcpEdgeHeaders).size !== mcpEdgeHeaders.length) {
    throw new Error("MCP edge attestation header names must be valid and distinct");
  }
  if (new Set([...edgeHeaders, ...mcpEdgeHeaders]).size !== edgeHeaders.length + mcpEdgeHeaders.length) {
    throw new Error("publisher and MCP edge attestation header names must be distinct");
  }
  if (config.maxPublisherEdgeAttestationEntries < 1 || config.maxMcpEdgeAttestationEntries < 1 || config.maxPrincipalBuckets < 1 || config.principalBucketTtlSeconds < 1) {
    throw new Error("edge attestation and principal guard limits must be positive");
  }
};
