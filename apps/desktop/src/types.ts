/** Renderer-safe state. Do not add credentials, absolute paths, or raw output. */
export type DesktopMode = "onboarding" | "synchronizing" | "ready" | "attention";

export type SetupPhase =
  | "idle"
  | "preflight"
  | "staged"
  | "deployed"
  | "device-bound"
  | "first-snapshot"
  | "endpoint-verified"
  | "ready";

export interface VaultSummary {
  name: string;
  noteCount: number;
  bytes: number;
}

export interface ServerInput {
  host: string;
  user: string;
  port: number;
}

export interface ServerSummary {
  label: string;
  host: string;
  user: string;
  port: number;
  connected: boolean;
}

export interface TunnelInput {
  tunnelId: string;
  apiKey: string;
}

export interface TunnelSummary {
  configured: boolean;
}

export interface AttentionState {
  code:
    | "vault-missing"
    | "ssh-failed"
    | "host-key-changed"
    | "docker-unavailable"
    | "capacity"
    | "deployment-failed"
    | "sync-blocked"
    | "server-offline"
    | "oauth-not-linked"
    | "tunnel-not-configured"
    | "orchestrator-unavailable";
  message: string;
  action: "choose-vault" | "change-server" | "configure-tunnel" | "review-fingerprint" | "retry" | "connect" | "limits";
}

export interface McpConnection {
  host: string;
  resourceUrl: string;
}

export interface SyncChanges {
  added: number;
  modified: number;
  removed: number;
  unchanged: number;
  total: number;
  bytes: number;
}

export type SyncTrigger = "startup" | "scheduled" | "manual" | "resume" | "setup";

export interface SyncSummary {
  intervalMinutes: number;
  lastCheckedAt: string | null;
  nextCheckAt: string | null;
  lastResult: "published" | "unchanged" | "failed" | null;
  lastChanges: SyncChanges | null;
}

export interface DesktopState {
  mode: DesktopMode;
  phase: SetupPhase;
  vault: VaultSummary | null;
  server: ServerSummary | null;
  tunnel: TunnelSummary | null;
  requiresTunnelConfig: boolean;
  mcp: McpConnection | null;
  paused: boolean;
  lastPublishedAt: string | null;
  sync: SyncSummary;
  attention: AttentionState | null;
  /** Explicit lifecycle state; renderer actions must not infer it from phase. */
  serverCopy: "none" | "active" | "retained" | "unknown";
}

export interface JournalEntry {
  at: string;
  message: string;
  level: "info" | "warn" | "error";
  category?: "sync" | "setup" | "connection" | "security" | "system";
  result?: "published" | "unchanged" | "failed";
  trigger?: SyncTrigger;
  changes?: SyncChanges;
  generation?: number;
  durationMs?: number;
}

export interface DesktopBackend {
  initialize?(): Promise<DesktopState>;
  close?(): void;
  getState(): Promise<DesktopState>;
  selectVault(root: string): Promise<VaultSummary>;
  configureServer(input: ServerInput): Promise<ServerSummary>;
  configureTunnel?(input: TunnelInput): Promise<TunnelSummary>;
  setup(): Promise<DesktopState>;
  synchronize(): Promise<DesktopState>;
  setPaused(paused: boolean): Promise<DesktopState>;
  getJournal(): Promise<JournalEntry[]>;
  setStartAtLogin(enabled: boolean): Promise<void>;
  connectChatGpt(): Promise<DesktopState>;
  connectOwner?(): Promise<DesktopState>;
  update?(): Promise<DesktopState>;
  disconnect?(): Promise<DesktopState>;
  removeServerCopy?(): Promise<DesktopState>;
  subscribe(listener: (state: DesktopState) => void): () => void;
}

export interface VaultBridgeRendererApi {
  getState(): Promise<DesktopState>;
  chooseVault(): Promise<DesktopState>;
  configureServer(input: ServerInput): Promise<DesktopState>;
  configureTunnel(input: TunnelInput): Promise<DesktopState>;
  setup(): Promise<DesktopState>;
  synchronize(): Promise<DesktopState>;
  setPaused(paused: boolean): Promise<DesktopState>;
  getJournal(): Promise<JournalEntry[]>;
  setStartAtLogin(enabled: boolean): Promise<void>;
  connectChatGpt(): Promise<DesktopState>;
  connectOwner(): Promise<DesktopState>;
  update(): Promise<DesktopState>;
  /** Revoke remote access and stop the exact service while preserving its replica. */
  disconnect(): Promise<DesktopState>;
  /** Revoke remote access, remove the exact service, and delete its replica. */
  removeServerCopy(): Promise<DesktopState>;
  onState(listener: (state: DesktopState) => void): () => void;
  openExternal(url: string): Promise<void>;
}

export const EMPTY_STATE: DesktopState = Object.freeze({
  mode: "onboarding",
  phase: "idle",
  vault: null,
  server: null,
  tunnel: null,
  requiresTunnelConfig: true,
  mcp: null,
  paused: false,
  lastPublishedAt: null,
  sync: {
    intervalMinutes: 5,
    lastCheckedAt: null,
    nextCheckAt: null,
    lastResult: null,
    lastChanges: null
  },
  attention: null,
  serverCopy: "none"
});

export function cloneState(state: DesktopState): DesktopState {
  return {
    ...state,
    vault: state.vault ? { ...state.vault } : null,
    server: state.server ? { ...state.server } : null,
    tunnel: state.tunnel ? { ...state.tunnel } : null,
    mcp: state.mcp ? { ...state.mcp } : null,
    sync: {
      ...state.sync,
      lastChanges: state.sync.lastChanges ? { ...state.sync.lastChanges } : null
    },
    attention: state.attention ? { ...state.attention } : null
  };
}

export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes < 0) return "0 B";
  if (bytes < 1024) return `${Math.round(bytes)} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let value = bytes;
  let unit = -1;
  do {
    value /= 1024;
    unit += 1;
  } while (value >= 1024 && unit < units.length - 1);
  return `${value >= 10 ? Math.round(value) : value.toFixed(1)} ${units[unit]}`;
}

export function displayServerLabel(input: ServerInput): string {
  const user = input.user.trim();
  const host = input.host.trim();
  return user ? `${user}@${host}` : host;
}
