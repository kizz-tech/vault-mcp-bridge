import { readFile } from "node:fs/promises";

export interface SecureTunnelProductConfig {
  readonly image: string;
  readonly syncIntervalMinutes: number;
}

export interface SecureTunnelConfigSource {
  readonly filePaths?: readonly string[];
  readonly env?: NodeJS.ProcessEnv;
  readonly allowMutableImage?: boolean;
}

const PINNED_IMAGE_RE = /^[a-z0-9][a-z0-9./_-]{0,255}@sha256:[a-f0-9]{64}$/u;
const MUTABLE_IMAGE_RE = /^[a-z0-9][a-z0-9./_-]{0,255}:[A-Za-z0-9._-]{1,128}$/u;

export function validateSecureTunnelProductConfig(value: unknown, allowMutableImage = false): SecureTunnelProductConfig {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("secure_tunnel_config_invalid");
  const record = value as Record<string, unknown>;
  if (Object.keys(record).some((key) => !["image", "syncIntervalMinutes"].includes(key))) {
    throw new Error("secure_tunnel_config_unknown_key");
  }
  const image = typeof record.image === "string" ? record.image.trim() : "";
  if (!PINNED_IMAGE_RE.test(image) && !(allowMutableImage && MUTABLE_IMAGE_RE.test(image))) {
    throw new Error("secure_tunnel_image_must_be_digest_pinned");
  }
  const syncIntervalMinutes = record.syncIntervalMinutes === undefined ? 5 : Number(record.syncIntervalMinutes);
  if (!Number.isSafeInteger(syncIntervalMinutes) || syncIntervalMinutes < 1 || syncIntervalMinutes > 24 * 60) {
    throw new Error("secure_tunnel_sync_interval_invalid");
  }
  return { image, syncIntervalMinutes };
}

export async function loadSecureTunnelProductConfig(source: SecureTunnelConfigSource = {}): Promise<SecureTunnelProductConfig | undefined> {
  const environment = source.env ?? process.env;
  if (environment.VAULT_BRIDGE_SECURE_TUNNEL_IMAGE) {
    return validateSecureTunnelProductConfig({
      image: environment.VAULT_BRIDGE_SECURE_TUNNEL_IMAGE,
      ...(environment.VAULT_BRIDGE_SYNC_INTERVAL_MINUTES
        ? { syncIntervalMinutes: Number(environment.VAULT_BRIDGE_SYNC_INTERVAL_MINUTES) }
        : {})
    }, source.allowMutableImage === true);
  }
  for (const filePath of source.filePaths ?? []) {
    try {
      return validateSecureTunnelProductConfig(JSON.parse(await readFile(filePath, "utf8")) as unknown, source.allowMutableImage === true);
    } catch (error) {
      if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") continue;
      throw error;
    }
  }
  return undefined;
}
