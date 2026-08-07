import { basename, extname, resolve } from "node:path";
import { opendir, realpath, stat } from "node:fs/promises";

import { cloneState, EMPTY_STATE, type DesktopBackend, type DesktopState, type JournalEntry, type ServerInput, type ServerSummary, type SetupPhase, type VaultSummary } from "./types.js";
import { displayServerLabel, type AttentionState } from "./types.js";
import { OpenSshAdapter } from "./ssh.js";

const MAX_FILES = 5_000;
const MAX_TOTAL_BYTES = 16 * 1024 * 1024;
const ALLOWED_EXTENSIONS = new Set([".md", ".canvas", ".base"]);
const EXCLUDED_NAMES = new Set([".obsidian", ".git", ".trash", "node_modules"]);

export interface SetupHandler {
  run(input: {
    vaultRoot: string;
    server: ServerInput;
    onPhase(phase: SetupPhase): void;
    onJournal(entry: JournalEntry): void;
  }): Promise<Partial<DesktopState>>;
}

export class VaultMissingError extends Error {
  constructor() {
    super("Vault not found");
    this.name = "VaultMissingError";
  }
}

export class LocalDesktopBackend implements DesktopBackend {
  private state = cloneState(EMPTY_STATE);
  private vaultRoot: string | null = null;
  private listeners = new Set<(state: DesktopState) => void>();
  private journal: JournalEntry[] = [];
  private setupPromise: Promise<DesktopState> | null = null;

  constructor(
    private readonly dependencies: {
      ssh?: OpenSshAdapter;
      setup?: SetupHandler;
      initialState?: Partial<DesktopState>;
    } = {}
  ) {
    this.state = {
      ...cloneState(EMPTY_STATE),
      ...dependencies.initialState,
      vault: dependencies.initialState?.vault ? { ...dependencies.initialState.vault } : null,
      server: dependencies.initialState?.server ? { ...dependencies.initialState.server } : null,
      mcp: dependencies.initialState?.mcp ? { ...dependencies.initialState.mcp } : null,
      attention: dependencies.initialState?.attention ? { ...dependencies.initialState.attention } : null
    };
  }

  async getState(): Promise<DesktopState> {
    return cloneState(this.state);
  }

  async selectVault(root: string): Promise<VaultSummary> {
    if (typeof root !== "string" || !root.trim()) throw new VaultMissingError();
    let summary: VaultSummary;
    try {
      summary = await scanVault(root);
    } catch (error) {
      if (error instanceof VaultMissingError) {
        this.state = { ...this.state, mode: "attention", attention: { code: "vault-missing", message: "Vault not found", action: "choose-vault" } };
        this.appendJournal("Vault not found", "error");
        this.publish();
      }
      throw error;
    }
    this.vaultRoot = await realpath(root);
    this.state = {
      ...this.state,
      mode: this.state.server ? "onboarding" : "onboarding",
      phase: "idle",
      vault: summary,
      attention: null
    };
    this.appendJournal("Vault scanned");
    this.publish();
    return { ...summary };
  }

  async configureServer(input: ServerInput): Promise<ServerSummary> {
    const target = OpenSshAdapter.fromInput(input);
    const server: ServerSummary = {
      label: displayServerLabel(input),
      host: target.host,
      user: target.user,
      port: target.port,
      connected: false
    };
    this.state = { ...this.state, server, attention: null };
    this.appendJournal("Server saved");
    this.publish();
    return { ...server };
  }

  async setup(): Promise<DesktopState> {
    if (this.setupPromise) return this.setupPromise;
    if (!this.vaultRoot || !this.state.vault) return this.fail("vault-missing", "Vault not found", "choose-vault");
    if (!this.state.server) return this.fail("ssh-failed", "Server not configured", "change-server");
    if (!this.dependencies.setup) {
      return this.fail("orchestrator-unavailable", "Setup unavailable", "retry");
    }
    const server = {
      host: this.state.server.host,
      user: this.state.server.user,
      port: this.state.server.port
    };
    this.state = { ...this.state, mode: "synchronizing", phase: "preflight", attention: null };
    this.appendJournal("Setup started");
    this.publish();
    const handler = this.dependencies.setup;
    this.setupPromise = handler
      .run({
        vaultRoot: this.vaultRoot,
        server,
        onPhase: (phase) => {
          this.state = { ...this.state, phase, mode: phase === "ready" ? "ready" : "synchronizing" };
          this.publish();
        },
        onJournal: (entry) => this.appendJournal(entry.message, entry.level, entry.at)
      })
      .then((patch) => {
        this.state = {
          ...this.state,
          ...patch,
          mode: patch.mode ?? (patch.phase === "ready" ? "ready" : "synchronizing"),
          attention: patch.attention ?? null
        };
        if (this.state.mode === "ready") this.appendJournal("Ready");
        this.publish();
        return cloneState(this.state);
      })
      .catch((error: unknown) => {
        const attention = normalizeSetupError(error);
        this.state = { ...this.state, mode: "attention", attention };
        this.appendJournal(attention.message, "error");
        this.publish();
        return cloneState(this.state);
      })
      .finally(() => {
        this.setupPromise = null;
      });
    return this.setupPromise;
  }

  async synchronize(): Promise<DesktopState> {
    if (!this.dependencies.setup || !this.vaultRoot || !this.state.server) return this.setup();
    return this.setup();
  }

  async setPaused(paused: boolean): Promise<DesktopState> {
    this.state = {
      ...this.state,
      paused,
      mode: paused ? "ready" : this.state.mode,
      attention: null
    };
    this.appendJournal(paused ? "Sync paused" : "Sync resumed");
    this.publish();
    return cloneState(this.state);
  }

  async getJournal(): Promise<JournalEntry[]> {
    return this.journal.map((entry) => ({ ...entry }));
  }

  async setStartAtLogin(_enabled: boolean): Promise<void> {
    // The Electron main process owns this operation; this no-op keeps the
    // backend port usable in headless tests and non-macOS development.
  }

  async connectChatGpt(): Promise<DesktopState> {
    if (!this.state.mcp) {
      return this.fail("oauth-not-linked", "ChatGPT not connected", "connect");
    }
    this.state = { ...this.state, attention: null };
    this.publish();
    return cloneState(this.state);
  }

  subscribe(listener: (state: DesktopState) => void): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  private async fail(code: AttentionState["code"], message: string, action: AttentionState["action"]): Promise<DesktopState> {
    this.state = { ...this.state, mode: "attention", attention: { code, message, action } };
    this.appendJournal(message, "error");
    this.publish();
    return cloneState(this.state);
  }

  private appendJournal(message: string, level: JournalEntry["level"] = "info", at = new Date().toISOString()): void {
    this.journal.push({ at, message: redactJournalMessage(message), level });
    if (this.journal.length > 200) this.journal.splice(0, this.journal.length - 200);
  }

  private publish(): void {
    const state = cloneState(this.state);
    for (const listener of this.listeners) listener(state);
  }
}

export async function scanVault(root: string): Promise<VaultSummary> {
  let canonical: string;
  try {
    canonical = await realpath(root);
    const rootStat = await stat(canonical);
    if (!rootStat.isDirectory()) throw new VaultMissingError();
  } catch {
    throw new VaultMissingError();
  }
  let noteCount = 0;
  let bytes = 0;
  const pending = [canonical];
  while (pending.length) {
    const directory = pending.pop();
    if (!directory) continue;
    let handle;
    try {
      handle = await opendir(directory);
    } catch {
      continue;
    }
    for await (const entry of handle) {
      if (entry.name.startsWith(".") || EXCLUDED_NAMES.has(entry.name)) continue;
      const path = resolve(directory, entry.name);
      if (entry.isDirectory()) {
        pending.push(path);
        continue;
      }
      if (!entry.isFile() || !ALLOWED_EXTENSIONS.has(extname(entry.name).toLowerCase())) continue;
      try {
        const fileStat = await stat(path);
        if (!fileStat.isFile()) continue;
        noteCount += 1;
        bytes += fileStat.size;
      } catch {
        // Unreadable files are omitted from the preview; the scanner in the
        // agent-core records the exact unreadable count during setup.
      }
      if (noteCount >= MAX_FILES || bytes >= MAX_TOTAL_BYTES) break;
    }
    if (noteCount >= MAX_FILES || bytes >= MAX_TOTAL_BYTES) break;
  }
  return { name: basename(canonical) || "Vault", noteCount, bytes };
}

function normalizeSetupError(error: unknown): AttentionState {
  const message = error instanceof Error ? error.message : "Setup failed";
  if (/host|fingerprint|identity changed/iu.test(message)) return { code: "host-key-changed", message: "Server identity changed", action: "review-fingerprint" };
  if (/docker/iu.test(message)) return { code: "docker-unavailable", message: "Docker unavailable", action: "retry" };
  if (/capacity|disk|memory/iu.test(message)) return { code: "capacity", message: "Server capacity is insufficient", action: "limits" };
  if (/ssh|auth/iu.test(message)) return { code: "ssh-failed", message: "SSH authentication failed", action: "change-server" };
  return { code: "deployment-failed", message: "Container did not start", action: "retry" };
}

function redactJournalMessage(message: string): string {
  return message
    .replace(/(?:Bearer\s+|token[=:]\s*|password[=:]\s*)[^\s,;]+/giu, "[redacted]")
    .replace(/(?:\/Users\/|\/home\/|[A-Za-z]:\\)[^\s]*/gu, "[path]")
    .slice(0, 240);
}
