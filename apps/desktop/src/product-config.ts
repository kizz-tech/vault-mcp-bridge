import { readFile } from "node:fs/promises";

/**
 * Non-secret desktop configuration.  Access/refresh tokens, private keys and
 * lease material are intentionally absent from this type.  The file can be
 * provisioned by a package installer or by an operator; the UI never edits it.
 */
export interface ProductConfig {
  readonly edgeOrigin: string;
  readonly ownerIssuer: string;
  readonly ownerAuthorizationEndpoint: string;
  readonly ownerTokenEndpoint: string;
  readonly ownerJwksUri: string;
  readonly ownerAudience: string;
  readonly ownerClientId: string;
  readonly ownerScope?: string;
  readonly development?: boolean;
  readonly images: {
    readonly serverRepository: string;
    readonly serverDigest: `sha256:${string}`;
    readonly tunnelRepository: string;
    readonly tunnelDigest: `sha256:${string}`;
  };
  readonly runtimeMode?: "rootless" | "rootful";
  readonly installationDirectory?: string;
  readonly syncIntervalMinutes?: number;
}

export interface ProductConfigSource {
  readonly filePath?: string;
  readonly filePaths?: readonly string[];
  readonly env?: NodeJS.ProcessEnv;
  readonly allowLoopback?: boolean;
}

const DIGEST = /^sha256:[a-f0-9]{64}$/u;
const REPOSITORY = /^[a-z0-9][a-z0-9./_-]{0,255}$/u;
const PRODUCT_CONFIG_KEYS = new Set([
  "edgeOrigin",
  "ownerIssuer",
  "ownerAuthorizationEndpoint",
  "ownerTokenEndpoint",
  "ownerJwksUri",
  "ownerAudience",
  "ownerClientId",
  "ownerScope",
  "development",
  "images",
  "runtimeMode",
  "installationDirectory",
  "syncIntervalMinutes"
]);
const IMAGE_CONFIG_KEYS = new Set(["serverRepository", "serverDigest", "tunnelRepository", "tunnelDigest"]);
const BROAD_INSTALLATION_ROOTS = new Set(["/", "/etc", "/home", "/opt", "/private", "/private/tmp", "/root", "/srv", "/tmp", "/usr", "/Users", "/var"]);

function stringValue(value: unknown, field: string, max = 2048): string {
  if (typeof value !== "string" || value.trim().length === 0 || value.length > max) {
    throw new Error(`config_${field}_invalid`);
  }
  return value.trim();
}

function urlValue(value: unknown, field: string, allowLoopback: boolean, preserveTrailingSlash = false, originOnly = false): string {
  const text = stringValue(value, field);
  let parsed: URL;
  try {
    parsed = new URL(text);
  } catch {
    throw new Error(`config_${field}_invalid`);
  }
  const loopback = ["localhost", "127.0.0.1", "::1"].includes(parsed.hostname.toLowerCase());
  if (parsed.protocol !== "https:" && !(allowLoopback && parsed.protocol === "http:" && loopback)) {
    throw new Error(`config_${field}_https_required`);
  }
  if (parsed.username || parsed.password || parsed.search || parsed.hash || (originOnly && parsed.pathname !== "/")) {
    throw new Error(`config_${field}_invalid`);
  }
  const result = parsed.toString();
  return preserveTrailingSlash ? result : result.replace(/\/$/u, "");
}

function optionalString(value: unknown, field: string, max = 512): string | undefined {
  if (value === undefined || value === null || value === "") return undefined;
  return stringValue(value, field, max);
}

function validateInstallationDirectory(value: string): string {
  const normalized = value.replace(/\/+$/u, "") || "/";
  const parts = normalized.split("/").filter(Boolean);
  if (
    !normalized.startsWith("/") ||
    /[\0\r\n$`;&|<>]/u.test(normalized) ||
    parts.some((part) => part === "." || part === ".." || !/^[A-Za-z0-9._-]+$/u.test(part))
  ) {
    throw new Error("config_installation_directory_invalid");
  }
  if (BROAD_INSTALLATION_ROOTS.has(normalized) || /^\/(?:home\/[^/]+|Users\/[^/]+)$/u.test(normalized)) {
    throw new Error("config_installation_directory_invalid");
  }
  return normalized;
}

function parseObject(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("config_invalid");
  return value as Record<string, unknown>;
}

function parseConfig(value: unknown, allowLoopback: boolean): ProductConfig {
  const input = parseObject(value);
  if (Object.keys(input).some((key) => !PRODUCT_CONFIG_KEYS.has(key))) throw new Error("config_unknown_key");
  const images = parseObject(input.images);
  if (Object.keys(images).some((key) => !IMAGE_CONFIG_KEYS.has(key))) throw new Error("config_images_unknown_key");
  const serverDigest = stringValue(images.serverDigest, "server_digest", 80);
  const tunnelDigest = stringValue(images.tunnelDigest, "tunnel_digest", 80);
  if (!DIGEST.test(serverDigest) || !DIGEST.test(tunnelDigest)) throw new Error("config_image_digest_invalid");
  const serverRepository = stringValue(images.serverRepository, "server_repository", 256);
  const tunnelRepository = stringValue(images.tunnelRepository, "tunnel_repository", 256);
  if (!REPOSITORY.test(serverRepository) || !REPOSITORY.test(tunnelRepository)) throw new Error("config_image_repository_invalid");
  const ownerScope = optionalString(input.ownerScope, "owner_scope");
  const installationDirectory = optionalString(input.installationDirectory, "installation_directory", 512);
  const syncIntervalMinutes = input.syncIntervalMinutes === undefined ? undefined : Number(input.syncIntervalMinutes);
  if (input.runtimeMode !== undefined && input.runtimeMode !== "rootless" && input.runtimeMode !== "rootful") {
    throw new Error("config_runtime_mode_invalid");
  }
  if (syncIntervalMinutes !== undefined && (!Number.isSafeInteger(syncIntervalMinutes) || syncIntervalMinutes < 1 || syncIntervalMinutes > 24 * 60)) {
    throw new Error("config_sync_interval_invalid");
  }
  const result: ProductConfig = {
    edgeOrigin: urlValue(input.edgeOrigin, "edge_origin", allowLoopback, false, true),
    ownerIssuer: urlValue(input.ownerIssuer, "owner_issuer", allowLoopback, true),
    ownerAuthorizationEndpoint: urlValue(input.ownerAuthorizationEndpoint, "owner_authorization_endpoint", allowLoopback),
    ownerTokenEndpoint: urlValue(input.ownerTokenEndpoint, "owner_token_endpoint", allowLoopback),
    ownerJwksUri: urlValue(input.ownerJwksUri, "owner_jwks_uri", allowLoopback),
    ownerAudience: stringValue(input.ownerAudience, "owner_audience"),
    ownerClientId: stringValue(input.ownerClientId, "owner_client_id", 512),
    ...(ownerScope ? { ownerScope } : {}),
    ...(input.development === true ? { development: true } : {}),
    images: {
      serverRepository,
      serverDigest: serverDigest as `sha256:${string}`,
      tunnelRepository,
      tunnelDigest: tunnelDigest as `sha256:${string}`
    },
    ...(input.runtimeMode ? { runtimeMode: input.runtimeMode } : {}),
    ...(installationDirectory ? { installationDirectory } : {}),
    ...(syncIntervalMinutes !== undefined ? { syncIntervalMinutes } : {})
  };
  if (result.installationDirectory) {
    return { ...result, installationDirectory: validateInstallationDirectory(result.installationDirectory) };
  }
  return result;
}

function envObject(env: NodeJS.ProcessEnv): Record<string, unknown> | null {
  const edgeOrigin = env.VAULT_BRIDGE_EDGE_ORIGIN;
  if (!edgeOrigin) return null;
  return {
    edgeOrigin,
    ownerIssuer: env.VAULT_BRIDGE_OWNER_ISSUER,
    ownerAuthorizationEndpoint: env.VAULT_BRIDGE_OWNER_AUTHORIZATION_ENDPOINT,
    ownerTokenEndpoint: env.VAULT_BRIDGE_OWNER_TOKEN_ENDPOINT,
    ownerJwksUri: env.VAULT_BRIDGE_OWNER_JWKS_URI,
    ownerAudience: env.VAULT_BRIDGE_OWNER_AUDIENCE,
    ownerClientId: env.VAULT_BRIDGE_OWNER_CLIENT_ID,
    ...(env.VAULT_BRIDGE_OWNER_SCOPE ? { ownerScope: env.VAULT_BRIDGE_OWNER_SCOPE } : {}),
    images: {
      serverRepository: env.VAULT_BRIDGE_SERVER_IMAGE_REPOSITORY,
      serverDigest: env.VAULT_BRIDGE_SERVER_IMAGE_DIGEST,
      tunnelRepository: env.VAULT_BRIDGE_TUNNEL_IMAGE_REPOSITORY,
      tunnelDigest: env.VAULT_BRIDGE_TUNNEL_IMAGE_DIGEST
    },
    ...(env.VAULT_BRIDGE_RUNTIME_MODE ? { runtimeMode: env.VAULT_BRIDGE_RUNTIME_MODE } : {}),
    ...(env.VAULT_BRIDGE_INSTALLATION_DIRECTORY ? { installationDirectory: env.VAULT_BRIDGE_INSTALLATION_DIRECTORY } : {}),
    ...(env.VAULT_BRIDGE_SYNC_INTERVAL_MINUTES ? { syncIntervalMinutes: Number(env.VAULT_BRIDGE_SYNC_INTERVAL_MINUTES) } : {})
  };
}

/** Load and validate only non-secret config. Missing config is represented by undefined. */
export async function loadProductConfig(source: ProductConfigSource = {}): Promise<ProductConfig | undefined> {
  const allowLoopback = source.allowLoopback === true;
  const envValue = envObject(source.env ?? process.env);
  let value: unknown = envValue;
  if (!value) {
    const paths = source.filePaths ?? (source.filePath ? [source.filePath] : []);
    for (const filePath of paths) {
      try {
        value = JSON.parse(await readFile(filePath, "utf8")) as unknown;
        break;
      } catch (error) {
        if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") continue;
        throw new Error("config_unreadable");
      }
    }
  }
  if (!value) return undefined;
  return parseConfig(value, allowLoopback);
}

export function validateProductConfig(value: unknown, allowLoopback = false): ProductConfig {
  return parseConfig(value, allowLoopback);
}
