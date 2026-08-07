import { randomUUID } from "node:crypto";
import { createAgentService, type AgentMode, type AgentService, type CredentialStore as CoreCredentialStore, type PublisherTlsCredentialProvider, type RemoteClient as CoreRemoteClient, type VaultScanner as CoreVaultScanner } from "@vault-mcp-bridge/agent-core";
import { resolveDataDir } from "./config.js";
import { FileCredentialStore } from "./credentials.js";
import { HttpRemoteClient } from "./remote-client.js";
import { DefaultVaultScanner } from "./scanner.js";
import type { AgentDeps } from "./types.js";

/**
 * Adapter used by the legacy loopback dashboard and by desktop development.
 * The Fastify routes remain a compatibility surface; new UI code should call
 * this framework-independent service instead of reaching into route state.
 */
export async function createLocalAgentService(options: {
  dataDir?: string;
  mode?: AgentMode;
  allowLoopbackRemoteHttp?: boolean;
  publisherTlsCredentialProvider?: PublisherTlsCredentialProvider;
  deps?: AgentDeps;
} = {}): Promise<AgentService> {
  const dataDir = resolveDataDir(options.dataDir);
  const credentials = options.deps?.credentials ?? new FileCredentialStore(dataDir);
  const idKey = await credentials.getOrCreateIdKey?.() ?? randomUUID();
  const scanner = options.deps?.scanVault ?? new DefaultVaultScanner(idKey);
  const mode = options.mode ?? (process.env.NODE_ENV === "production" ? "production" : "development");
  const remoteClient = options.deps?.remoteClient ?? new HttpRemoteClient(options.allowLoopbackRemoteHttp ?? false, options.publisherTlsCredentialProvider ? { credentialProvider: options.publisherTlsCredentialProvider, requireMtls: mode === "production" } : {});
  return createAgentService({
    dataDir,
    mode,
    scanner: scanner as unknown as CoreVaultScanner,
    remoteClient: remoteClient as unknown as CoreRemoteClient,
    credentials: credentials as unknown as CoreCredentialStore,
    ...(options.publisherTlsCredentialProvider ? { publisherTlsCredentialProvider: options.publisherTlsCredentialProvider } : {}),
    ...(options.deps?.now ? { now: options.deps.now } : {})
  });
}
