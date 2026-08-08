import { readFile, stat } from "node:fs/promises";
import { isAbsolute, resolve } from "node:path";

import type { DesktopState, JournalEntry, ServerInput } from "./types.js";

const MAX_PLAN_BYTES = 16 * 1024;
const TUNNEL_ID_RE = /^tunnel_[a-f0-9]{32}$/u;

export type AgentSetupPlan = {
  version: 1;
  vaultRoot: string;
  server: ServerInput;
  openai: { tunnelId: string };
};

export type AgentCommand =
  | { name: "help" }
  | { name: "doctor" }
  | { name: "status" }
  | { name: "journal" }
  | { name: "prepare"; configPath: string; runtimeKeyStdin: true }
  | { name: "setup"; approvedFingerprint: string };

export function parseAgentCommand(arguments_: readonly string[]): AgentCommand {
  const args = arguments_.filter((argument) => argument !== "--json");
  const name = args[0] ?? "help";
  if (name === "help" && args.length === 1) return { name: "help" };
  if (["doctor", "status", "journal"].includes(name) && args.length === 1) return { name: name as "doctor" | "status" | "journal" };
  if (name === "prepare") {
    const configIndex = args.indexOf("--config");
    const configPath = configIndex >= 0 ? args[configIndex + 1] : undefined;
    if (args.length !== 4 || configIndex !== 1 || !configPath || args[3] !== "--runtime-key-stdin") throw new Error("agent_command_invalid");
    if (!isAbsolute(configPath) || resolve(configPath) !== configPath) throw new Error("agent_config_path_invalid");
    return { name: "prepare", configPath, runtimeKeyStdin: true };
  }
  if (name === "setup") {
    if (args.length !== 3 || args[1] !== "--approve-host-fingerprint" || !args[2]) throw new Error("agent_command_invalid");
    return { name: "setup", approvedFingerprint: args[2] };
  }
  throw new Error("agent_command_invalid");
}

export async function readAgentSetupPlan(path: string): Promise<AgentSetupPlan> {
  const metadata = await stat(path);
  if (!metadata.isFile() || metadata.size < 2 || metadata.size > MAX_PLAN_BYTES) throw new Error("agent_config_invalid");
  if (typeof process.getuid === "function" && metadata.uid !== process.getuid()) throw new Error("agent_config_owner_invalid");
  if ((metadata.mode & 0o077) !== 0) throw new Error("agent_config_permissions_invalid");
  let value: unknown;
  try {
    value = JSON.parse(await readFile(path, "utf8")) as unknown;
  } catch {
    throw new Error("agent_config_invalid");
  }
  return validateAgentSetupPlan(value);
}

export function validateAgentSetupPlan(value: unknown): AgentSetupPlan {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("agent_config_invalid");
  const record = value as Record<string, unknown>;
  if (!hasOnlyKeys(record, ["version", "vaultRoot", "server", "openai"]) || record.version !== 1) throw new Error("agent_config_invalid");
  const vaultRoot = typeof record.vaultRoot === "string" ? record.vaultRoot : "";
  if (!isAbsolute(vaultRoot) || resolve(vaultRoot) !== vaultRoot) throw new Error("agent_config_invalid");
  if (!record.server || typeof record.server !== "object" || Array.isArray(record.server)) throw new Error("agent_config_invalid");
  const server = record.server as Record<string, unknown>;
  if (!hasOnlyKeys(server, ["host", "user", "port"])) throw new Error("agent_config_invalid");
  if (typeof server.host !== "string" || typeof server.user !== "string" || typeof server.port !== "number") throw new Error("agent_config_invalid");
  if (!record.openai || typeof record.openai !== "object" || Array.isArray(record.openai)) throw new Error("agent_config_invalid");
  const openai = record.openai as Record<string, unknown>;
  if (!hasOnlyKeys(openai, ["tunnelId"]) || typeof openai.tunnelId !== "string" || !TUNNEL_ID_RE.test(openai.tunnelId)) {
    throw new Error("agent_config_invalid");
  }
  return {
    version: 1,
    vaultRoot,
    server: { host: server.host, user: server.user, port: server.port },
    openai: { tunnelId: openai.tunnelId }
  };
}

export function agentStatus(state: DesktopState): Record<string, unknown> {
  return {
    ok: state.mode !== "attention",
    mode: state.mode,
    phase: state.phase,
    vault: state.vault ? { configured: true, notes: state.vault.noteCount, bytes: state.vault.bytes } : { configured: false },
    server: { configured: Boolean(state.server), connected: Boolean(state.server?.connected) },
    openai: { configured: Boolean(state.tunnel?.configured), connected: Boolean(state.mcp) },
    sync: {
      paused: state.paused,
      intervalMinutes: state.sync.intervalMinutes,
      lastCheckedAt: state.sync.lastCheckedAt,
      nextCheckAt: state.sync.nextCheckAt,
      lastResult: state.sync.lastResult,
      lastChanges: state.sync.lastChanges
    },
    attention: state.attention ? { code: state.attention.code, action: state.attention.action } : null
  };
}

export function agentJournal(entries: readonly JournalEntry[]): Record<string, unknown> {
  return {
    ok: true,
    entries: entries.slice(-200).map((entry) => ({
      at: entry.at,
      message: entry.message,
      level: entry.level,
      ...(entry.category ? { category: entry.category } : {}),
      ...(entry.result ? { result: entry.result } : {}),
      ...(entry.trigger ? { trigger: entry.trigger } : {}),
      ...(entry.changes ? { changes: { ...entry.changes } } : {}),
      ...(entry.generation !== undefined ? { generation: entry.generation } : {}),
      ...(entry.durationMs !== undefined ? { durationMs: entry.durationMs } : {})
    }))
  };
}

export async function readRuntimeKeyFromStdin(stream: NodeJS.ReadableStream): Promise<string> {
  const chunks: Buffer[] = [];
  let bytes = 0;
  for await (const chunk of stream) {
    const value = Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk));
    bytes += value.byteLength;
    if (bytes > 1024) throw new Error("runtime_key_stdin_invalid");
    chunks.push(value);
  }
  const key = Buffer.concat(chunks).toString("utf8").trim();
  if (key.length < 20 || key.length > 512 || /\s/u.test(key)) throw new Error("runtime_key_stdin_invalid");
  return key;
}

export const AGENT_HELP = Object.freeze({
  ok: true,
  commands: [
    "vault-bridge doctor --json",
    "vault-bridge status --json",
    "vault-bridge prepare --config /absolute/private-plan.json --runtime-key-stdin --json",
    "vault-bridge setup --approve-host-fingerprint SHA256/... --json",
    "vault-bridge journal --json"
  ],
  contract: "read-only-v1"
});

function hasOnlyKeys(record: Record<string, unknown>, keys: readonly string[]): boolean {
  const allowed = new Set(keys);
  return Object.keys(record).length === keys.length && Object.keys(record).every((key) => allowed.has(key));
}
