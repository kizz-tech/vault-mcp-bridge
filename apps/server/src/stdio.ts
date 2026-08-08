import { McpServer } from "@modelcontextprotocol/server";
import { serveStdio } from "@modelcontextprotocol/server/stdio";
import { loadConfig } from "./config.js";
import { registerVaultTools, type McpServerLike } from "./mcp.js";
import { assertPrivateStdioConfig } from "./private-stdio-config.js";
import { VaultStore } from "./store.js";

const config = loadConfig();
assertPrivateStdioConfig(config);
const store = new VaultStore(config.databasePath, config.nonceRetentionSeconds, {
  maxVaultBytes: config.maxVaultBytes,
  maxDatabaseBytes: config.maxDatabaseBytes,
  maxIndexBytes: config.maxIndexBytes,
  maxTempBytes: config.maxTempBytes,
  minFreeBytes: config.minFreeBytes,
  maxRetainedGenerations: config.maxRetainedGenerations,
});

const handle = serveStdio(() => {
  const server = new McpServer({ name: "vault-mcp-bridge", version: "0.1.0" });
  registerVaultTools(server as unknown as McpServerLike, store, config);
  return server;
});

let closing = false;
const close = async (): Promise<void> => {
  if (closing) return;
  closing = true;
  try {
    await handle.close();
  } finally {
    store.close();
  }
};

process.once("SIGTERM", () => { void close(); });
process.once("SIGINT", () => { void close(); });
