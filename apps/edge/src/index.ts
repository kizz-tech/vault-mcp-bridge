import { lstatSync, readFileSync } from "node:fs";

import { createEdgeApp } from "./app.js";
import {
  assertProductionConfig,
  assertProductionRuntimeConfig,
  loadConfig,
  type EdgeConfig,
} from "./config.js";
import { CloudflareTunnelProvider } from "./cloudflare-provider.js";
import { DurableCredentialVault } from "./durable-credential-vault.js";
import { DurableEdgeStore } from "./durable-store.js";
import { DeterministicTunnelProvider, MemoryCredentialVault, type TunnelProvider } from "./providers.js";
import { loadOrCreateOAuthSigningKey } from "./signing-key-store.js";
import { createMemoryStore } from "./store.js";

const SECRET_FILE_MIN_BYTES = 20;
const SECRET_FILE_MAX_BYTES = 4 * 1024;

/** Read a deployment-mounted secret without accepting permissive file modes.
 * Only the trimmed token is retained by this process; failures never expose
 * the path contents or token value. */
export const readSecretFile = (filePath: string): string => {
  let bytes: Buffer;
  try {
    const stat = lstatSync(filePath);
    const mode = stat.mode & 0o7777;
    if (!stat.isFile() || (mode !== 0o400 && mode !== 0o600)) throw new Error("invalid secret file");
    bytes = readFileSync(filePath);
  } catch (error) {
    throw new Error("EDGE_CLOUDFLARE_API_TOKEN_FILE is unavailable", { cause: error });
  }
  const token = bytes.toString("utf8").trim();
  const tokenBytes = Buffer.byteLength(token, "utf8");
  if (tokenBytes < SECRET_FILE_MIN_BYTES || tokenBytes > SECRET_FILE_MAX_BYTES || /\s/u.test(token)) {
    throw new Error("Cloudflare API token is invalid");
  }
  return token;
};

type RunningEdge = Awaited<ReturnType<typeof createEdgeApp>>;

const createDevelopmentComposition = async (config: EdgeConfig): Promise<RunningEdge> => {
  const store = createMemoryStore();
  const credentials = new MemoryCredentialVault();
  const provider: TunnelProvider = new DeterministicTunnelProvider({
    origin: config.origin,
    credentials,
    allowHttp: true,
  });
  return createEdgeApp({ config, store, credentialVault: credentials, provider });
};

const createProductionComposition = async (config: EdgeConfig): Promise<RunningEdge> => {
  assertProductionRuntimeConfig(config);
  const stateFile = (config.stateFile ?? config.statePath) as string;
  const credentialVaultFile = (config.credentialVaultFile ?? config.vaultPath) as string;
  const credentialMasterKeyFile = (config.credentialMasterKeyFile ?? config.masterKeyPath) as string;
  const cloudflareApiTokenFile = (config.cloudflareApiTokenFile ?? config.cloudflareApiTokenPath) as string;
  const accountId = config.cloudflareAccountId as string;
  const zoneId = config.cloudflareZoneId as string;
  const zoneName = config.cloudflareZoneName as string;

  const store = new DurableEdgeStore({ statePath: stateFile });
  // DurableCredentialVault reads and validates the raw 32-byte master key
  // itself, including the required 0400/0600 mode; the edge never receives a
  // key through environment variables or command-line arguments.
  const credentials = new DurableCredentialVault({
    filePath: credentialVaultFile,
    masterKeyFile: credentialMasterKeyFile,
  });
  const oauthSigningKey = await loadOrCreateOAuthSigningKey(credentials);
  // Check that an existing vault is writable as well as readable; otherwise
  // the first provider mutation could fail after the edge has started.
  await credentials.flush();
  const provider = new CloudflareTunnelProvider({
    accountId,
    zoneId,
    zoneName,
    apiToken: readSecretFile(cloudflareApiTokenFile),
    credentials,
    dedicatedZone: true,
    introspectionBaseUrl: config.origin,
  });

  // DurableEdgeStore is a single-writer adapter; run exactly one edge process
  // per state file unless a transactional multi-process repository replaces it.
  await store.flush();
  return createEdgeApp({ config, store, credentialVault: credentials, oauthSigningKey, provider });
};

const config = loadConfig();
assertProductionConfig(config);
const edge = config.nodeEnv === "production"
  ? await createProductionComposition(config)
  : await createDevelopmentComposition(config);
await edge.app.listen({ host: config.bindHost, port: config.bindPort });

let shuttingDown = false;
const shutdown = async (): Promise<void> => {
  if (shuttingDown) return;
  shuttingDown = true;
  await edge.close();
  process.exit(0);
};
process.once("SIGINT", () => { void shutdown(); });
process.once("SIGTERM", () => { void shutdown(); });
