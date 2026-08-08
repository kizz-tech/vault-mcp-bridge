import { assertConfigSafety, type ServerConfig } from "./config.js";

const OPAQUE_ID_RE = /^[A-Za-z0-9_-]{16,256}$/u;

export const assertPrivateStdioConfig = (config: ServerConfig, env: NodeJS.ProcessEnv = process.env): void => {
  assertConfigSafety(config);
  if (env.MCP_STDIO_PRIVATE_TUNNEL !== "1") throw new Error("MCP_STDIO_PRIVATE_TUNNEL=1 is required");
  if (config.nodeEnv !== "production") throw new Error("private stdio MCP requires NODE_ENV=production");
  if (config.databasePath === ":memory:") throw new Error("SERVER_DATABASE_PATH must be durable");
  if (!config.mcpVaultId || !OPAQUE_ID_RE.test(config.mcpVaultId)) throw new Error("MCP_VAULT_ID must be an opaque identifier");
  if (!env.CONTROL_PLANE_TUNNEL_ID?.trim()) throw new Error("CONTROL_PLANE_TUNNEL_ID is required");
  if (config.mcpReadsDisabled) throw new Error("MCP reads are disabled");
  if (config.mcpDevToken) throw new Error("MCP_DEV_TOKEN is not allowed for private stdio MCP");
};
