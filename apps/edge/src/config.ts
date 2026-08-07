import type { JWK } from "jose";
import { isAbsolute } from "node:path";
import type { EdgeEnvironment, EdgeMode } from "./types.js";
import type { EdgeLimits } from "./limits.js";

const env = (name: string): string | undefined => {
  const value = process.env[name];
  return value && value.trim() ? value.trim() : undefined;
};

const firstEnv = (...names: string[]): string | undefined => {
  for (const name of names) {
    const value = env(name);
    if (value) return value;
  }
  return undefined;
};

const parseJwks = (value: string | undefined): { keys: JWK[] } | undefined => {
  if (!value) return undefined;
  try {
    const parsed = JSON.parse(value) as { keys?: unknown };
    if (!parsed || !Array.isArray(parsed.keys)) throw new Error("keys missing");
    return { keys: parsed.keys as JWK[] };
  } catch {
    throw new Error("EDGE_OWNER_JWKS must be a JSON Web Key Set");
  }
};

export type EdgeConfig = {
  nodeEnv: EdgeEnvironment;
  mode: EdgeMode;
  origin: string;
  issuer: string;
  bindHost: string;
  bindPort: number;
  ownerIssuer?: string;
  ownerAudience?: string;
  ownerJwks?: { keys: JWK[] };
  devOwnerToken?: string;
  devOwnerId?: string;
  ownerAuthorizationUrl?: string;
  /** Browser/OIDC owner client metadata. The issuer is intentionally kept
   * exactly as configured; it is an identity namespace, not an edge origin. */
  ownerClientId?: string;
  ownerTokenEndpoint?: string;
  ownerScope?: string;
  autoApproveOwnerId?: string;
  providerName: string;
  providerAccountCredentialReference?: string;
  /** Production persistence and provider secret paths. These are required in
   * production and intentionally remain optional for memory-backed dev/test. */
  stateFile?: string;
  credentialVaultFile?: string;
  credentialMasterKeyFile?: string;
  cloudflareApiTokenFile?: string;
  /** Compatibility aliases for callers that use "path" terminology. */
  statePath?: string;
  vaultPath?: string;
  masterKeyPath?: string;
  cloudflareApiTokenPath?: string;
  cloudflareAccountId?: string;
  cloudflareZoneId?: string;
  cloudflareZoneName?: string;
  limits?: Partial<EdgeLimits>;
  trustProxy?: boolean;
};

export const loadConfig = (): EdgeConfig => {
  const nodeEnv = (env("NODE_ENV") ?? "development") as EdgeEnvironment;
  if (!["development", "test", "production"].includes(nodeEnv)) throw new Error("NODE_ENV is invalid");
  const mode = (env("EDGE_MODE") ?? "self-hosted") as EdgeMode;
  if (mode !== "managed" && mode !== "self-hosted") throw new Error("EDGE_MODE is invalid");
  const origin = env("EDGE_ORIGIN") ?? "http://127.0.0.1:8790";
  const issuer = env("EDGE_ISSUER") ?? origin;
  const config: EdgeConfig = {
    nodeEnv,
    mode,
    origin,
    issuer,
    bindHost: env("EDGE_BIND_HOST") ?? "127.0.0.1",
    bindPort: Number.parseInt(env("EDGE_BIND_PORT") ?? "8790", 10),
    providerName: env("EDGE_PROVIDER") ?? (nodeEnv === "production" ? "external" : "deterministic"),
  };
  const ownerIssuer = env("EDGE_OWNER_ISSUER");
  const ownerAudience = env("EDGE_OWNER_AUDIENCE");
  const ownerJwks = parseJwks(env("EDGE_OWNER_JWKS"));
  const devOwnerToken = env("EDGE_DEV_OWNER_TOKEN");
  const devOwnerId = env("EDGE_DEV_OWNER_ID");
  const ownerAuthorizationUrl = env("EDGE_OWNER_AUTHORIZATION_URL");
  const ownerClientId = env("EDGE_OWNER_CLIENT_ID");
  const ownerTokenEndpoint = env("EDGE_OWNER_TOKEN_ENDPOINT");
  const ownerScope = env("EDGE_OWNER_SCOPE");
  const autoApproveOwnerId = env("EDGE_AUTO_APPROVE_OWNER_ID");
  const providerAccountCredentialReference = env("EDGE_PROVIDER_ACCOUNT_CREDENTIAL_REF");
  const stateFile = firstEnv("EDGE_STATE_FILE", "EDGE_STATE_PATH");
  const credentialVaultFile = firstEnv("EDGE_CREDENTIAL_VAULT_FILE", "EDGE_CREDENTIAL_VAULT_PATH", "EDGE_VAULT_FILE", "EDGE_VAULT_PATH");
  const credentialMasterKeyFile = firstEnv("EDGE_CREDENTIAL_MASTER_KEY_FILE", "EDGE_CREDENTIAL_MASTER_KEY_PATH", "EDGE_MASTER_KEY_FILE", "EDGE_MASTER_KEY_PATH");
  const cloudflareApiTokenFile = firstEnv("EDGE_CLOUDFLARE_API_TOKEN_FILE", "EDGE_CLOUDFLARE_API_TOKEN_PATH");
  const cloudflareAccountId = firstEnv("EDGE_CLOUDFLARE_ACCOUNT_ID");
  const cloudflareZoneId = firstEnv("EDGE_CLOUDFLARE_ZONE_ID");
  const cloudflareZoneName = firstEnv("EDGE_CLOUDFLARE_ZONE_NAME", "EDGE_CLOUDFLARE_DOMAIN");
  const trustProxy = env("EDGE_TRUST_PROXY");
  if (ownerIssuer) config.ownerIssuer = ownerIssuer;
  if (ownerAudience) config.ownerAudience = ownerAudience;
  if (ownerJwks) config.ownerJwks = ownerJwks;
  if (devOwnerToken) config.devOwnerToken = devOwnerToken;
  if (devOwnerId) config.devOwnerId = devOwnerId;
  if (ownerAuthorizationUrl) config.ownerAuthorizationUrl = ownerAuthorizationUrl;
  if (ownerClientId) config.ownerClientId = ownerClientId;
  if (ownerTokenEndpoint) config.ownerTokenEndpoint = ownerTokenEndpoint;
  if (ownerScope) config.ownerScope = ownerScope;
  if (autoApproveOwnerId) config.autoApproveOwnerId = autoApproveOwnerId;
  if (providerAccountCredentialReference) config.providerAccountCredentialReference = providerAccountCredentialReference;
  if (stateFile) {
    config.stateFile = stateFile;
    config.statePath = stateFile;
  }
  if (credentialVaultFile) {
    config.credentialVaultFile = credentialVaultFile;
    config.vaultPath = credentialVaultFile;
  }
  if (credentialMasterKeyFile) {
    config.credentialMasterKeyFile = credentialMasterKeyFile;
    config.masterKeyPath = credentialMasterKeyFile;
  }
  if (cloudflareApiTokenFile) {
    config.cloudflareApiTokenFile = cloudflareApiTokenFile;
    config.cloudflareApiTokenPath = cloudflareApiTokenFile;
  }
  if (cloudflareAccountId) config.cloudflareAccountId = cloudflareAccountId;
  if (cloudflareZoneId) config.cloudflareZoneId = cloudflareZoneId;
  if (cloudflareZoneName) config.cloudflareZoneName = cloudflareZoneName;
  if (trustProxy === "true") config.trustProxy = true;
  return config;
};

export const assertProductionConfig = (config: EdgeConfig): void => {
  if (config.nodeEnv !== "production") return;
  for (const [name, value] of [["EDGE_ORIGIN", config.origin], ["EDGE_ISSUER", config.issuer]] as const) {
    const url = new URL(value);
    if (url.protocol !== "https:") throw new Error(`${name} must use HTTPS in production`);
  }
  if (!config.ownerIssuer || !config.ownerAudience || !config.ownerJwks || !config.ownerAuthorizationUrl) throw new Error("production owner identity verification is not configured");
  if (config.devOwnerToken || config.autoApproveOwnerId) throw new Error("development owner auth cannot be enabled in production");
  if (config.providerName === "local" || config.providerName === "deterministic") throw new Error("deterministic edge provider cannot be used in production");
  if (config.providerName !== "cloudflare") throw new Error("production Cloudflare provider is required");
}

const requireAbsolutePath = (name: string, value: string | undefined): string => {
  if (!value || !isAbsolute(value)) throw new Error(`${name} must be an absolute path in production`);
  return value;
};

/** Runtime-only production gates used by the process composition. Kept
 * separate from assertProductionConfig so callers that construct an app with
 * injected test adapters retain the existing app-level capability errors. */
export const assertProductionRuntimeConfig = (config: EdgeConfig): void => {
  if (config.nodeEnv !== "production") return;
  requireAbsolutePath("EDGE_STATE_FILE", config.stateFile ?? config.statePath);
  requireAbsolutePath("EDGE_CREDENTIAL_VAULT_FILE", config.credentialVaultFile ?? config.vaultPath);
  requireAbsolutePath("EDGE_CREDENTIAL_MASTER_KEY_FILE", config.credentialMasterKeyFile ?? config.masterKeyPath);
  requireAbsolutePath("EDGE_CLOUDFLARE_API_TOKEN_FILE", config.cloudflareApiTokenFile ?? config.cloudflareApiTokenPath);
  if (!config.cloudflareAccountId) throw new Error("EDGE_CLOUDFLARE_ACCOUNT_ID is required in production");
  if (!config.cloudflareZoneId) throw new Error("EDGE_CLOUDFLARE_ZONE_ID is required in production");
  if (!config.cloudflareZoneName) throw new Error("EDGE_CLOUDFLARE_ZONE_NAME is required in production");
  if (!config.ownerClientId) throw new Error("EDGE_OWNER_CLIENT_ID is required in production");
  if (!config.ownerTokenEndpoint) throw new Error("EDGE_OWNER_TOKEN_ENDPOINT is required in production");
};
