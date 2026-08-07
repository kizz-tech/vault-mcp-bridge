import { chmod, mkdir, open, readFile, rename } from "node:fs/promises";
import { dirname, join } from "node:path";
import { UploadReceiptSchema } from "@vault-mcp-bridge/contracts";
import type { AgentConfig, AgentRuntime, AgentState, AgentStateStore, DeviceIdentity, PairingState } from "./types.js";

export const DEFAULT_INCLUDE = ["**/*.md", "**/*.canvas", "**/*.base"] as const;
export const DEFAULT_EXCLUDE = [".obsidian/**", "**/.obsidian/**", "**/.git/**", "**/.*", "**/node_modules/**"] as const;
export const DEFAULT_SYNC_INTERVAL_MINUTES = 0;
export const DEFAULT_MAX_JOURNAL_ENTRIES = 100;
const JOURNAL_CODES = new Set([
  "ssh-connected",
  "server-checked",
  "deployment-staged",
  "container-started",
  "device-bound",
  "vault-synchronized",
  "endpoint-verified",
  "paused",
  "resumed",
  "failed"
]);

export function defaultAgentConfig(): AgentConfig {
  return {
    include: [...DEFAULT_INCLUDE],
    exclude: [...DEFAULT_EXCLUDE],
    syncIntervalMinutes: DEFAULT_SYNC_INTERVAL_MINUTES
  };
}

export function defaultAgentRuntime(now = new Date()): AgentRuntime {
  return {
    startedAt: now.toISOString(),
    phase: "idle",
    paused: false,
    pairing: { paired: false },
    journal: []
  };
}

interface PersistedAgentState {
  version: 1;
  config: AgentConfig;
  runtime: AgentRuntime;
  identity?: DeviceIdentity;
  pairing: PairingState;
}

function optionalString(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function stringList(value: unknown, fallback: readonly string[]): string[] {
  if (!Array.isArray(value)) return [...fallback];
  const values = value.filter((entry): entry is string => typeof entry === "string" && entry.length <= 1024);
  return values.length > 0 ? values.slice(0, 256) : [...fallback];
}

function normalizeConfig(value: unknown): AgentConfig {
  const candidate = value && typeof value === "object" ? value as Record<string, unknown> : {};
  const interval = Number(candidate.syncIntervalMinutes ?? DEFAULT_SYNC_INTERVAL_MINUTES);
  const vaultRoot = optionalString(candidate.vaultRoot);
  const remoteServerUrl = optionalString(candidate.remoteServerUrl);
  const vaultId = optionalString(candidate.vaultId);
  const agentId = optionalString(candidate.agentId);
  const label = optionalString(candidate.label);
  return {
    ...(vaultRoot ? { vaultRoot } : {}),
    include: stringList(candidate.include, DEFAULT_INCLUDE),
    exclude: stringList(candidate.exclude, DEFAULT_EXCLUDE),
    ...(remoteServerUrl ? { remoteServerUrl } : {}),
    ...(vaultId ? { vaultId } : {}),
    syncIntervalMinutes: Number.isInteger(interval) && interval >= 0 && interval <= 1440 ? interval : DEFAULT_SYNC_INTERVAL_MINUTES,
    ...(agentId ? { agentId } : {}),
    ...(label ? { label } : {})
  };
}

function normalizePairing(value: unknown): PairingState {
  const candidate = value && typeof value === "object" ? value as Record<string, unknown> : {};
  const deviceId = optionalString(candidate.deviceId);
  const publicKey = optionalString(candidate.publicKey);
  const pairedAt = optionalString(candidate.pairedAt);
  return {
    paired: candidate.paired === true,
    ...(deviceId ? { deviceId } : {}),
    ...(publicKey ? { publicKey } : {}),
    ...(pairedAt ? { pairedAt } : {})
  };
}

function normalizeIdentity(value: unknown): DeviceIdentity | undefined {
  if (!value || typeof value !== "object") return undefined;
  const candidate = value as Record<string, unknown>;
  const publicKey = optionalString(candidate.publicKey);
  const createdAt = optionalString(candidate.createdAt);
  if (!publicKey || !createdAt || candidate.keyAlgorithm !== "ed25519") return undefined;
  return { publicKey, keyAlgorithm: "ed25519", createdAt };
}

function normalizeRuntime(value: unknown, now: () => Date): AgentRuntime {
  const candidate = value && typeof value === "object" ? value as Record<string, unknown> : {};
  const startedAt = optionalString(candidate.startedAt) ?? now().toISOString();
  const phase = ["idle", "vault-selected", "preview-ready", "device-bound", "synchronizing", "ready", "paused", "needs-attention"].includes(String(candidate.phase))
    ? String(candidate.phase) as AgentRuntime["phase"]
    : "idle";
  const journal = Array.isArray(candidate.journal)
    ? candidate.journal.filter((entry): entry is AgentRuntime["journal"][number] => Boolean(entry && typeof entry === "object" && typeof (entry as Record<string, unknown>).at === "string" && JOURNAL_CODES.has(String((entry as Record<string, unknown>).code)) && typeof (entry as Record<string, unknown>).installationId === "string" && /^[A-Za-z0-9_-]{16,256}$/u.test(String((entry as Record<string, unknown>).installationId)))).slice(-DEFAULT_MAX_JOURNAL_ENTRIES)
    : [];
  const lastScanAt = optionalString(candidate.lastScanAt);
  const lastUploadAt = optionalString(candidate.lastUploadAt);
  const lastError = optionalString(candidate.lastError);
  const lastPublisherStatus = candidate.lastPublisherStatus && typeof candidate.lastPublisherStatus === "object"
    ? candidate.lastPublisherStatus as AgentRuntime["lastPublisherStatus"]
    : undefined;
  const lastPreview = candidate.lastPreview && typeof candidate.lastPreview === "object"
    ? candidate.lastPreview as AgentRuntime["lastPreview"]
    : undefined;
  const lastReceipt = UploadReceiptSchema.safeParse(candidate.lastReceipt);
  return {
    startedAt,
    phase,
    paused: candidate.paused === true,
    ...(lastScanAt ? { lastScanAt } : {}),
    ...(lastUploadAt ? { lastUploadAt } : {}),
    ...(lastReceipt.success ? { lastReceipt: lastReceipt.data } : {}),
    ...(lastPublisherStatus ? { lastPublisherStatus } : {}),
    ...(lastPreview ? { lastPreview } : {}),
    ...(lastError ? { lastError } : {}),
    pairing: normalizePairing(candidate.pairing),
    journal
  };
}

async function ensureDataDir(dataDir: string): Promise<void> {
  await mkdir(dataDir, { recursive: true, mode: 0o700 });
  await chmod(dataDir, 0o700).catch(() => undefined);
}

async function atomicWriteJson(path: string, value: unknown): Promise<void> {
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  const temporary = `${path}.${process.pid}.${Date.now()}.tmp`;
  const handle = await open(temporary, "wx", 0o600);
  try {
    await handle.writeFile(`${JSON.stringify(value, null, 2)}\n`, "utf8");
    await handle.sync();
  } finally {
    await handle.close();
  }
  await chmod(temporary, 0o600).catch(() => undefined);
  await rename(temporary, path);
  await chmod(path, 0o600).catch(() => undefined);
}

/** Small atomic JSON state store; it persists references and UI state only. */
export class JsonAgentStateStore implements AgentStateStore {
  private readonly path: string;
  private readonly now: () => Date;

  constructor(dataDir: string, now = () => new Date()) {
    this.path = join(dataDir, "agent-state.json");
    this.now = now;
  }

  async load(): Promise<Partial<Pick<AgentState, "config" | "runtime" | "identity" | "pairing">>> {
    await ensureDataDir(dirname(this.path));
    try {
      const parsed = JSON.parse(await readFile(this.path, "utf8")) as Partial<PersistedAgentState>;
      const runtime = normalizeRuntime(parsed.runtime, this.now);
      const identity = normalizeIdentity(parsed.identity);
      return {
        config: normalizeConfig(parsed.config),
        runtime,
        pairing: normalizePairing(parsed.pairing ?? runtime.pairing),
        ...(identity ? { identity } : {})
      };
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return {};
      throw new Error("agent_state_unreadable", { cause: error });
    }
  }

  async save(state: Pick<AgentState, "config" | "runtime" | "identity" | "pairing">): Promise<void> {
    await ensureDataDir(dirname(this.path));
    const persisted: PersistedAgentState = {
      version: 1,
      config: state.config,
      runtime: state.runtime,
      pairing: state.pairing,
      ...(state.identity ? { identity: state.identity } : {})
    };
    await atomicWriteJson(this.path, persisted);
  }
}

/** In-memory store used by the desktop process and deterministic tests. */
export class MemoryAgentStateStore implements AgentStateStore {
  private value: Partial<Pick<AgentState, "config" | "runtime" | "identity" | "pairing">> = {};

  async load(): Promise<Partial<Pick<AgentState, "config" | "runtime" | "identity" | "pairing">>> {
    return structuredClone(this.value);
  }

  async save(state: Pick<AgentState, "config" | "runtime" | "identity" | "pairing">): Promise<void> {
    this.value = structuredClone(state);
  }
}

export { normalizeConfig, normalizeRuntime };
