import { createHash, randomBytes } from "node:crypto";
import { chmod, mkdir, open, readFile, realpath, rename, rm } from "node:fs/promises";
import { basename, dirname, join } from "node:path";

import { DefaultVaultScanner, type VaultScanner } from "@vault-mcp-bridge/agent-core";
import { runPrivateSync, type PrivateSyncConfig, type PrivateSyncReceipt } from "@vault-mcp-bridge/agent";

import type { SecureTunnelProductConfig } from "./secure-tunnel-config.js";
import { SafeStorageSecretStore, type SecretStore } from "./secret-store.js";
import {
  FileHostKeyPinStore,
  OpenSftpAdapter,
  OpenSshAdapter,
  type HostKeyPinStore,
  type SshHostKeyAlgorithm,
  type SshTarget
} from "./ssh.js";
import {
  EMPTY_STATE,
  cloneState,
  displayServerLabel,
  type AttentionState,
  type DiagnosticInfo,
  type DesktopBackend,
  type DesktopState,
  type JournalEntry,
  type ServerInput,
  type ServerSummary,
  type SyncChanges,
  type SyncTrigger,
  type TunnelInput,
  type TunnelSummary,
  type VaultSummary
} from "./types.js";

const RUNTIME_KEY_SECRET = "secure-tunnel.runtime-api-key";
const TUNNEL_ID_RE = /^tunnel_[a-f0-9]{32}$/u;
const OPAQUE_ID_RE = /^[A-Za-z0-9_-]{16,256}$/u;
const IMAGE_RE = /^[a-z0-9][a-z0-9./_-]{0,255}(?:@sha256:[a-f0-9]{64}|:[A-Za-z0-9._-]{1,128})$/u;
const SAFE_REMOTE_HOME_RE = /^\/(?:[A-Za-z0-9._-]+\/?){1,20}$/u;
const SSH_HOST_RE = /^[A-Za-z0-9._-]{1,255}$/u;
const SSH_USER_RE = /^[A-Za-z0-9._-]{1,253}$/u;
const MIN_REMOTE_FREE_BYTES = 2 * 1024 * 1024 * 1024;
const MAX_JOURNAL = 200;

type PrivateRecord = {
  version: 1;
  phase: "idle" | "ready" | "retained";
  vault?: { root: string; id: string; summary: VaultSummary };
  server?: ServerInput;
  tunnelId?: string;
  installationId?: string;
  deviceId?: string;
  projectName?: string;
  remoteDirectory?: string;
  paused: boolean;
  lastPublishedAt?: string;
  lastCheckedAt?: string;
  lastSyncResult?: "published" | "unchanged" | "failed";
  lastSyncChanges?: SyncChanges;
  sshHost?: string;
  sshUser?: string;
  sshPort?: number;
  sshHostKeyAlgorithm?: SshHostKeyAlgorithm;
};

export interface PrivateInstallation {
  readonly projectName: string;
  readonly remoteDirectory: string;
  readonly sshHost?: string;
  readonly sshUser?: string;
  readonly sshPort?: number;
  readonly sshHostKeyAlgorithm?: SshHostKeyAlgorithm;
}

export interface PrivateDeploymentPort {
  setup(input: {
    readonly server: ServerInput;
    readonly tunnelId: string;
    readonly apiKey: string;
    readonly vaultId: string;
    readonly installationId: string;
    readonly projectName: string;
  }): Promise<PrivateInstallation>;
  disconnect(input: PrivateInstallation & { readonly server: ServerInput }): Promise<void>;
  remove(input: PrivateInstallation & { readonly server: ServerInput }): Promise<void>;
  health?(input: PrivateInstallation & { readonly server: ServerInput }): Promise<{ ssh: true; runtime: boolean }>;
}

export type PrivateHealthCheck = {
  status: "pass" | "fail" | "skip";
  diagnostic?: DiagnosticInfo;
};

export type PrivateHealthReport = {
  ok: boolean;
  checkedAt: string;
  checks: {
    configuration: PrivateHealthCheck;
    vault: PrivateHealthCheck;
    server: PrivateHealthCheck;
    openai: PrivateHealthCheck;
    synchronization: PrivateHealthCheck;
  };
};

export interface PrivateDesktopBackendOptions {
  readonly appDataPath: string;
  readonly config: SecureTunnelProductConfig;
  readonly composeTemplatePath: string;
  readonly secretStore?: SecretStore;
  readonly scanner?: VaultScanner;
  readonly deployment?: PrivateDeploymentPort;
  readonly ssh?: OpenSshAdapter;
  readonly sftp?: OpenSftpAdapter;
  readonly pins?: HostKeyPinStore;
  readonly confirmation?: { confirm(fingerprint: string, target: SshTarget): Promise<boolean> };
  readonly browser?: { openExternal(url: string): Promise<void> };
  readonly tunnelVerifier?: (tunnelId: string, apiKey: string) => Promise<void>;
  readonly syncer?: (configPath: string) => Promise<PrivateSyncReceipt>;
  readonly now?: () => Date;
}

export class PrivateDesktopBackend implements DesktopBackend {
  private state = cloneState(EMPTY_STATE);
  private record: PrivateRecord = { version: 1, phase: "idle", paused: false };
  private readonly listeners = new Set<(state: DesktopState) => void>();
  private readonly journal: JournalEntry[] = [];
  private readonly scanner: VaultScanner;
  private readonly secrets: SecretStore;
  private readonly deployment: PrivateDeploymentPort;
  private setupPromise: Promise<DesktopState> | undefined;
  private syncPromise: Promise<DesktopState> | undefined;
  private syncTimer: NodeJS.Timeout | undefined;
  private nextSyncAt: Date | undefined;

  constructor(private readonly options: PrivateDesktopBackendOptions) {
    this.scanner = options.scanner ?? new DefaultVaultScanner();
    this.secrets = options.secretStore ?? new SafeStorageSecretStore(join(options.appDataPath, "secrets.json"), { isEncryptionAvailable: () => false });
    this.deployment = options.deployment ?? new SshPrivateDeployment({
      config: options.config,
      composeTemplatePath: options.composeTemplatePath,
      appDataPath: options.appDataPath,
      ssh: options.ssh ?? new OpenSshAdapter(undefined, join(options.appDataPath, "ssh", "known_hosts")),
      sftp: options.sftp ?? new OpenSftpAdapter(undefined, join(options.appDataPath, "ssh", "known_hosts")),
      pins: options.pins ?? new FileHostKeyPinStore(join(options.appDataPath, "ssh", "pins.json")),
      confirmation: options.confirmation ?? { confirm: async () => false }
    });
  }

  async initialize(options: { backgroundSync?: boolean; refreshVault?: boolean } = {}): Promise<DesktopState> {
    this.record = await readRecord(this.recordPath());
    this.journal.splice(0, this.journal.length, ...(await readJournal(this.journalPath())));
    if (this.record.phase === "ready" && (!this.record.sshHost || !this.record.sshHostKeyAlgorithm)) {
      const knownHost = await readKnownHostRecord(join(this.options.appDataPath, "ssh", "known_hosts"));
      if (knownHost) {
        const sshUser = this.record.sshUser ?? this.record.server?.user;
        this.record = {
          ...this.record,
          sshHost: this.record.sshHost ?? knownHost.host,
          sshPort: this.record.sshPort ?? knownHost.port,
          sshHostKeyAlgorithm: this.record.sshHostKeyAlgorithm ?? knownHost.algorithm,
          ...(sshUser ? { sshUser } : {})
        };
        await this.persist();
      }
    }
    if (this.record.vault && options.refreshVault !== false) {
      const scan = await this.scanner.scan(this.record.vault.root, {});
      if (scan.errors.length === 0) {
        this.record = {
          ...this.record,
          vault: {
            ...this.record.vault,
            summary: { ...this.record.vault.summary, noteCount: scan.files.length, bytes: scan.bytes }
          }
        };
        await this.persist();
      }
    }
    await this.projectRecord();
    if (this.record.phase === "ready" && options.backgroundSync !== false) {
      this.scheduleSync();
      void this.synchronize("startup");
    }
    return cloneState(this.state);
  }

  close(): void {
    if (this.syncTimer) clearInterval(this.syncTimer);
    this.syncTimer = undefined;
    this.nextSyncAt = undefined;
  }

  async getState(): Promise<DesktopState> { return cloneState(this.state); }

  async selectVault(root: string): Promise<VaultSummary> {
    this.assertConfigurationMutable();
    const canonicalRoot = await realpath(root);
    const scan = await this.scanner.scan(canonicalRoot, {});
    if (scan.errors.length > 0) throw new Error("vault_scan_incomplete");
    const summary = { name: basename(canonicalRoot) || "Vault", noteCount: scan.files.length, bytes: scan.bytes };
    const vaultId = this.record.vault?.id ?? opaqueId("vault");
    this.record = { ...this.record, vault: { root: canonicalRoot, id: vaultId, summary }, phase: "idle" };
    await this.persist();
    await this.append("Vault scanned", "info", { category: "setup" });
    await this.projectRecord();
    return { ...summary };
  }

  async configureServer(input: ServerInput): Promise<ServerSummary> {
    this.assertConfigurationMutable();
    const target = OpenSshAdapter.fromInput(input);
    const server = { host: target.host, user: target.user, port: target.port };
    this.record = { ...this.record, server, phase: "idle" };
    await this.persist();
    await this.append("Server saved", "info", { category: "setup" });
    await this.projectRecord();
    return serverSummary(server);
  }

  async configureTunnel(input: TunnelInput): Promise<TunnelSummary> {
    this.assertConfigurationMutable();
    const tunnelId = input.tunnelId.trim();
    const apiKey = input.apiKey.trim();
    if (!TUNNEL_ID_RE.test(tunnelId) || apiKey.length < 20 || apiKey.length > 512 || /\s/u.test(apiKey)) {
      throw new Error("tunnel_credentials_invalid");
    }
    await (this.options.tunnelVerifier ?? verifyTunnel)(tunnelId, apiKey);
    await this.secrets.put(RUNTIME_KEY_SECRET, apiKey);
    this.record = { ...this.record, tunnelId, phase: "idle" };
    await this.persist();
    await this.append("OpenAI tunnel verified", "info", { category: "connection" });
    await this.projectRecord();
    return { configured: true };
  }

  async setup(): Promise<DesktopState> {
    if (this.setupPromise) return this.setupPromise;
    this.setupPromise = this.runSetup().finally(() => { this.setupPromise = undefined; });
    return this.setupPromise;
  }

  async synchronize(trigger: SyncTrigger = "manual"): Promise<DesktopState> {
    if (this.syncPromise) return this.syncPromise;
    if (this.record.phase !== "ready" || this.record.paused) return cloneState(this.state);
    this.syncPromise = this.runSync(trigger).finally(() => { this.syncPromise = undefined; });
    return this.syncPromise;
  }

  async setPaused(paused: boolean): Promise<DesktopState> {
    this.record = { ...this.record, paused };
    await this.persist();
    await this.append(paused ? "Sync paused" : "Sync resumed", "info", { category: "sync" });
    await this.projectRecord();
    this.scheduleSync();
    if (!paused) void this.synchronize("resume");
    return cloneState(this.state);
  }

  async getJournal(): Promise<JournalEntry[]> { return this.journal.map(cloneJournalEntry); }
  async setStartAtLogin(_enabled: boolean): Promise<void> {}

  async diagnose(options: { verifyLocalTunnelCredential?: boolean } = {}): Promise<PrivateHealthReport> {
    const checkedAt = this.now().toISOString();
    const configured = this.record.phase === "ready" && Boolean(
      this.record.vault && this.record.server && this.record.tunnelId && this.installation() && this.record.deviceId
    );
    const checks: PrivateHealthReport["checks"] = {
      configuration: { status: configured ? "pass" : "fail" },
      vault: { status: "skip" },
      server: { status: "skip" },
      openai: { status: "skip" },
      synchronization: { status: "skip" }
    };
    if (!configured || !this.record.vault || !this.record.server) return { ok: false, checkedAt, checks };

    try {
      const scan = await this.scanner.scan(this.record.vault.root, {});
      checks.vault = scan.errors.length === 0
        ? { status: "pass" }
        : { status: "fail", diagnostic: diagnosticFor(new Error("vault scan incomplete")) };
    } catch (error) {
      checks.vault = { status: "fail", diagnostic: diagnosticFor(error, "vault") };
    }

    const installation = this.installation();
    let runtimeHealthy = false;
    if (installation && this.deployment.health) {
      try {
        const health = await this.deployment.health({ ...installation, server: this.record.server });
        runtimeHealthy = health.ssh && health.runtime;
        checks.server = health.ssh && health.runtime
          ? { status: "pass" }
          : { status: "fail", diagnostic: diagnosticFor(new Error("runtime unavailable"), "runtime") };
      } catch (error) {
        checks.server = { status: "fail", diagnostic: diagnosticFor(error, "ssh") };
      }
    }

    if (options.verifyLocalTunnelCredential === false) {
      checks.openai = runtimeHealthy
        ? { status: "pass" }
        : { status: "fail", diagnostic: diagnosticFor(new Error("tunnel unavailable"), "openai") };
    } else {
      const apiKey = await this.secrets.get(RUNTIME_KEY_SECRET);
      if (this.record.tunnelId && apiKey) {
        try {
          await (this.options.tunnelVerifier ?? verifyTunnel)(this.record.tunnelId, apiKey);
          checks.openai = { status: "pass" };
        } catch (error) {
          checks.openai = { status: "fail", diagnostic: diagnosticFor(error, "openai") };
        }
      } else {
        checks.openai = { status: "fail", diagnostic: diagnosticFor(new Error("tunnel unavailable"), "openai") };
      }
    }

    checks.synchronization = this.record.lastSyncResult && this.record.lastSyncResult !== "failed"
      ? { status: "pass" }
      : { status: "fail", diagnostic: diagnosticFor(new Error("sync failed"), "sync") };
    return {
      ok: Object.values(checks).every((check) => check.status === "pass"),
      checkedAt,
      checks
    };
  }

  async connectChatGpt(): Promise<DesktopState> {
    if (this.record.phase !== "ready") return this.fail("tunnel-not-configured", "Finish setup first", "retry");
    await this.options.browser?.openExternal("https://chatgpt.com/");
    await this.append("ChatGPT opened", "info", { category: "connection" });
    return cloneState(this.state);
  }

  async disconnect(): Promise<DesktopState> {
    const installation = this.installation();
    if (!installation || !this.record.server || this.record.phase !== "ready") return cloneState(this.state);
    try {
      await this.deployment.disconnect({ ...installation, server: this.record.server });
      this.record = { ...this.record, phase: "retained", paused: true };
      await this.persist();
      await this.append("Remote access stopped", "warn", { category: "security" });
      await this.projectRecord();
      return cloneState(this.state);
    } catch {
      return this.fail("deployment-failed", "Disconnect failed", "retry");
    }
  }

  async removeServerCopy(): Promise<DesktopState> {
    const installation = this.installation();
    if (!installation || !this.record.server || this.record.phase === "idle") return cloneState(this.state);
    try {
      await this.deployment.remove({ ...installation, server: this.record.server });
      this.record = {
        version: 1,
        phase: "idle",
        paused: false,
        ...(this.record.vault ? { vault: this.record.vault } : {}),
        ...(this.record.server ? { server: this.record.server } : {}),
        ...(this.record.tunnelId ? { tunnelId: this.record.tunnelId } : {})
      };
      await this.persist();
      await this.append("Server copy removed", "warn", { category: "security" });
      await this.projectRecord();
      return cloneState(this.state);
    } catch {
      return this.fail("deployment-failed", "Removal failed", "retry");
    }
  }

  subscribe(listener: (state: DesktopState) => void): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  private async runSetup(): Promise<DesktopState> {
    const startedAt = Date.now();
    const vault = this.record.vault;
    if (!vault) return this.fail("vault-missing", "Vault not found", "choose-vault");
    if (!this.record.server) return this.fail("ssh-failed", "Server not configured", "change-server");
    if (!this.record.tunnelId) return this.fail("tunnel-not-configured", "OpenAI tunnel not configured", "configure-tunnel");
    const apiKey = await this.secrets.get(RUNTIME_KEY_SECRET);
    if (!apiKey) return this.fail("tunnel-not-configured", "OpenAI tunnel not configured", "configure-tunnel");
    const installationId = this.record.installationId ?? opaqueId("installation");
    const deviceId = this.record.deviceId ?? opaqueId("device");
    const projectName = this.record.projectName ?? projectNameFor(installationId);
    this.state = { ...this.state, mode: "synchronizing", phase: "preflight", attention: null };
    this.publish();
    try {
      const installed = await this.deployment.setup({
        server: this.record.server,
        tunnelId: this.record.tunnelId,
        apiKey,
        vaultId: vault.id,
        installationId,
        projectName
      });
      this.record = {
        ...this.record,
        installationId,
        deviceId,
        projectName: installed.projectName,
        remoteDirectory: installed.remoteDirectory,
        ...(installed.sshHost ? { sshHost: installed.sshHost } : {}),
        ...(installed.sshUser ? { sshUser: installed.sshUser } : {}),
        ...(installed.sshPort !== undefined ? { sshPort: installed.sshPort } : {}),
        ...(installed.sshHostKeyAlgorithm ? { sshHostKeyAlgorithm: installed.sshHostKeyAlgorithm } : {})
      };
      await this.writeSyncConfig();
      this.state = { ...this.state, mode: "synchronizing", phase: "first-snapshot" };
      this.publish();
      const receipt = await this.syncOnce();
      const checkedAt = this.now().toISOString();
      const result = receipt.status === "uploaded" ? "published" : "unchanged";
      this.record = {
        ...this.record,
        vault: {
          ...vault,
          summary: { ...vault.summary, noteCount: receipt.documentCount, bytes: receipt.changes.bytes }
        },
        phase: "ready",
        paused: false,
        ...(receipt.status === "uploaded" ? { lastPublishedAt: checkedAt } : {}),
        lastCheckedAt: checkedAt,
        lastSyncResult: result,
        lastSyncChanges: receipt.changes
      };
      await this.persist();
      await this.appendSync(receipt, "setup", Date.now() - startedAt);
      await this.projectRecord();
      this.scheduleSync();
      return cloneState(this.state);
    } catch (error) {
      return this.failFrom(error);
    }
  }

  private async runSync(trigger: SyncTrigger): Promise<DesktopState> {
    const startedAt = Date.now();
    this.state = { ...this.state, mode: "synchronizing", phase: "first-snapshot", attention: null };
    this.publish();
    try {
      const receipt = await this.syncOnce();
      const checkedAt = this.now().toISOString();
      const result = receipt.status === "uploaded" ? "published" : "unchanged";
      this.record = {
        ...this.record,
        ...(this.record.vault
          ? {
              vault: {
                ...this.record.vault,
                summary: {
                  ...this.record.vault.summary,
                  noteCount: receipt.documentCount,
                  bytes: receipt.changes.bytes
                }
              }
            }
          : {}),
        ...(receipt.status === "uploaded" ? { lastPublishedAt: checkedAt } : {}),
        lastCheckedAt: checkedAt,
        lastSyncResult: result,
        lastSyncChanges: receipt.changes
      };
      await this.persist();
      await this.appendSync(receipt, trigger, Date.now() - startedAt);
      await this.projectRecord();
      return cloneState(this.state);
    } catch (error) {
      const diagnostic = diagnosticFor(error, "sync");
      this.record = { ...this.record, lastCheckedAt: this.now().toISOString(), lastSyncResult: "failed" };
      await this.persist();
      this.state = {
        ...this.state,
        sync: {
          ...this.state.sync,
          lastCheckedAt: this.record.lastCheckedAt ?? null,
          lastResult: "failed"
        }
      };
      await this.append(diagnosticMessage(diagnostic), "error", {
        category: "sync",
        result: "failed",
        trigger,
        durationMs: Date.now() - startedAt,
        diagnostic
      });
      return this.fail("sync-blocked", diagnosticMessage(diagnostic), "retry", false);
    }
  }

  private async syncOnce(): Promise<PrivateSyncReceipt> {
    await this.writeSyncConfig();
    return (this.options.syncer ?? ((configPath) => runPrivateSync({ configPath })))(this.syncConfigPath());
  }

  private async writeSyncConfig(): Promise<void> {
    const installation = this.installation();
    if (!installation || !this.record.vault || !this.record.server || !this.record.deviceId) throw new Error("private_sync_not_configured");
    const config: PrivateSyncConfig = {
      version: 1,
      vaultRoot: this.record.vault.root,
      vaultId: this.record.vault.id,
      deviceId: this.record.deviceId,
      sshHost: this.record.server.host,
      sshUser: this.record.server.user,
      sshPort: this.record.server.port,
      sshKnownHostsFile: join(this.options.appDataPath, "ssh", "known_hosts"),
      ...(installation.sshHost && installation.sshHost !== this.record.server.host
        ? { sshHostKeyAlias: installation.sshHost }
        : {}),
      ...(this.record.sshHostKeyAlgorithm ? { sshHostKeyAlgorithm: this.record.sshHostKeyAlgorithm } : {}),
      remoteDirectory: installation.remoteDirectory,
      projectName: installation.projectName,
      include: ["**/*.md", "**/*.canvas", "**/*.base"],
      exclude: [".obsidian/**", "**/.obsidian/**", "**/.git/**", "**/.*", "**/node_modules/**"]
    };
    await atomicWrite(this.syncConfigPath(), config);
  }

  private async projectRecord(): Promise<void> {
    const hasTunnelConfiguration = Boolean(this.record.tunnelId);
    const active = this.record.phase === "ready";
    const retained = this.record.phase === "retained";
    const server = this.record.server ? serverSummary(this.record.server, active) : null;
    this.state = {
      ...this.state,
      mode: active ? "ready" : retained ? "onboarding" : "onboarding",
      phase: active ? "ready" : "idle",
      vault: this.record.vault ? { ...this.record.vault.summary } : null,
      server,
      tunnel: hasTunnelConfiguration ? { configured: true } : null,
      requiresTunnelConfig: true,
      mcp: active ? { host: "Connected", resourceUrl: `https://api.openai.com/v1/tunnels/${this.record.tunnelId ?? ""}` } : null,
      paused: this.record.paused,
      lastPublishedAt: this.record.lastPublishedAt ?? null,
      sync: {
        intervalMinutes: this.options.config.syncIntervalMinutes,
        lastCheckedAt: this.record.lastCheckedAt ?? null,
        nextCheckAt: this.record.paused ? null : this.nextSyncAt?.toISOString() ?? null,
        lastResult: this.record.lastSyncResult ?? null,
        lastChanges: this.record.lastSyncChanges ? { ...this.record.lastSyncChanges } : null
      },
      attention: null,
      serverCopy: active ? "active" : retained ? "retained" : "none"
    };
    this.publish();
  }

  private installation(): PrivateInstallation | undefined {
    return this.record.projectName && this.record.remoteDirectory
      ? {
          projectName: this.record.projectName,
          remoteDirectory: this.record.remoteDirectory,
          ...(this.record.sshHost ? { sshHost: this.record.sshHost } : {}),
          ...(this.record.sshUser ? { sshUser: this.record.sshUser } : {}),
          ...(this.record.sshPort !== undefined ? { sshPort: this.record.sshPort } : {}),
          ...(this.record.sshHostKeyAlgorithm ? { sshHostKeyAlgorithm: this.record.sshHostKeyAlgorithm } : {})
        }
      : undefined;
  }

  private assertConfigurationMutable(): void {
    if (this.record.phase === "ready" || this.record.phase === "retained") throw new Error("disconnect_and_remove_before_configuration_change");
  }

  private async persist(): Promise<void> { await atomicWrite(this.recordPath(), this.record); }
  private recordPath(): string { return join(this.options.appDataPath, "private-setup.json"); }
  private syncConfigPath(): string { return join(this.options.appDataPath, "private-sync", "config.json"); }
  private journalPath(): string { return join(this.options.appDataPath, "journal.json"); }
  private now(): Date { return this.options.now?.() ?? new Date(); }

  private scheduleSync(): void {
    if (this.syncTimer) clearInterval(this.syncTimer);
    this.syncTimer = undefined;
    this.nextSyncAt = undefined;
    if (this.record.phase !== "ready" || this.record.paused) {
      this.state = { ...this.state, sync: { ...this.state.sync, nextCheckAt: null } };
      this.publish();
      return;
    }
    const intervalMs = this.options.config.syncIntervalMinutes * 60_000;
    this.nextSyncAt = new Date(this.now().getTime() + intervalMs);
    this.state = { ...this.state, sync: { ...this.state.sync, nextCheckAt: this.nextSyncAt.toISOString() } };
    this.publish();
    this.syncTimer = setInterval(() => {
      this.nextSyncAt = new Date(this.now().getTime() + intervalMs);
      this.state = { ...this.state, sync: { ...this.state.sync, nextCheckAt: this.nextSyncAt.toISOString() } };
      this.publish();
      void this.synchronize("scheduled");
    }, intervalMs);
    this.syncTimer.unref();
  }

  private failFrom(error: unknown): Promise<DesktopState> {
    const message = error instanceof Error ? error.message : "";
    if (/host|fingerprint|identity/iu.test(message)) return this.fail("host-key-changed", "Server identity changed", "review-fingerprint");
    if (/docker/iu.test(message)) return this.fail("docker-unavailable", "Docker unavailable", "retry");
    if (/capacity|space|memory/iu.test(message)) return this.fail("capacity", "Server capacity is insufficient", "limits");
    if (/ssh|authentication/iu.test(message)) return this.fail("ssh-failed", "SSH authentication failed", "change-server");
    if (/tunnel|api key/iu.test(message)) return this.fail("tunnel-not-configured", "OpenAI tunnel unavailable", "configure-tunnel");
    return this.fail("deployment-failed", "Container did not start", "retry");
  }

  private async fail(code: AttentionState["code"], message: string, action: AttentionState["action"], recordEvent = true): Promise<DesktopState> {
    this.state = { ...this.state, mode: "attention", attention: { code, message, action } };
    if (recordEvent) await this.append(message, "error", { category: "system" });
    this.publish();
    return cloneState(this.state);
  }

  private async append(
    message: string,
    level: JournalEntry["level"] = "info",
    details: Omit<Partial<JournalEntry>, "at" | "message" | "level"> = {}
  ): Promise<void> {
    this.journal.push({ at: this.now().toISOString(), message: message.slice(0, 160), level, ...details });
    if (this.journal.length > MAX_JOURNAL) this.journal.splice(0, this.journal.length - MAX_JOURNAL);
    await atomicWrite(this.journalPath(), { version: 1, entries: this.journal });
  }

  private async appendSync(receipt: PrivateSyncReceipt, trigger: SyncTrigger, durationMs: number): Promise<void> {
    await this.append(receipt.status === "uploaded" ? "Changes published" : "No changes", "info", {
      category: "sync",
      result: receipt.status === "uploaded" ? "published" : "unchanged",
      trigger,
      changes: { ...receipt.changes },
      generation: receipt.generation,
      durationMs
    });
  }

  private publish(): void {
    const value = cloneState(this.state);
    for (const listener of this.listeners) listener(value);
  }
}

class SshPrivateDeployment implements PrivateDeploymentPort {
  constructor(private readonly options: {
    readonly config: SecureTunnelProductConfig;
    readonly composeTemplatePath: string;
    readonly appDataPath: string;
    readonly ssh: OpenSshAdapter;
    readonly sftp: OpenSftpAdapter;
    readonly pins: HostKeyPinStore;
    readonly confirmation: { confirm(fingerprint: string, target: SshTarget): Promise<boolean> };
  }) {
    if (!IMAGE_RE.test(options.config.image)) throw new Error("secure_tunnel_image_invalid");
  }

  async setup(input: {
    readonly server: ServerInput;
    readonly tunnelId: string;
    readonly apiKey: string;
    readonly vaultId: string;
    readonly installationId: string;
    readonly projectName: string;
  }): Promise<PrivateInstallation> {
    const target = await this.target(input.server);
    await this.options.ssh.check(target);
    const system = (await this.options.ssh.runFixed(target, ["uname", "-s"])).stdout.trim();
    if (system !== "Linux") throw new Error("docker_linux_required");
    await this.options.ssh.runFixed(target, ["docker", "version"]);
    await this.options.ssh.runFixed(target, ["docker", "compose", "version"]);
    await this.options.ssh.runFixed(target, ["curl", "--silent", "--show-error", "--output", "/dev/null", "--max-time", "10", "https://api.openai.com"]);
    const home = (await this.options.ssh.runFixed(target, ["pwd"])).stdout.trim().replace(/\/$/u, "");
    if (!SAFE_REMOTE_HOME_RE.test(home) || home.includes("..") || ["", "/", "/etc", "/opt", "/srv", "/tmp", "/usr", "/var"].includes(home)) {
      throw new Error("remote_home_invalid");
    }
    const availableBytes = availableBytesFromDf((await this.options.ssh.runFixed(target, ["df", "-Pk", "--", home])).stdout);
    if (availableBytes < MIN_REMOTE_FREE_BYTES) throw new Error("server_capacity_insufficient");
    const remoteDirectory = `${home}/.local/share/vault-bridge/installations/${input.installationId}`;
    const stage = join(this.options.appDataPath, "staging", input.installationId);
    const secretDirectory = join(stage, "secrets");
    const remoteSecrets = `${remoteDirectory}/secrets`;
    await mkdir(secretDirectory, { recursive: true, mode: 0o700 });
    const composePath = join(stage, "compose.yaml");
    const environmentPath = join(stage, ".env");
    const apiKeyPath = join(secretDirectory, "control-plane-api-key");
    try {
      const compose = await readFile(this.options.composeTemplatePath, "utf8");
      await atomicWriteText(composePath, compose);
      await atomicWriteText(environmentPath, [
        `COMPOSE_PROJECT_NAME=${input.projectName}`,
        `VAULT_BRIDGE_IMAGE=${this.options.config.image}`,
        `CONTROL_PLANE_TUNNEL_ID=${input.tunnelId}`,
        `MCP_VAULT_ID=${input.vaultId}`,
        ""
      ].join("\n"));
      await atomicWriteText(apiKeyPath, `${input.apiKey}\n`);
      const uploader = this.options.sftp.withTarget(target);
      await uploader.ensureDirectory(remoteSecrets);
      await Promise.all([
        uploader.upload(composePath, `${remoteDirectory}/compose.yaml`),
        uploader.upload(environmentPath, `${remoteDirectory}/.env`),
        uploader.upload(apiKeyPath, `${remoteSecrets}/control-plane-api-key`)
      ]);
      const prefix = composePrefix(input.projectName, remoteDirectory);
      await this.options.ssh.runFixed(target, [...prefix, "config", "--quiet"]);
      await this.options.ssh.runFixed(target, [...prefix, "pull", "--quiet"], { timeoutMs: 10 * 60_000 });
      await this.options.ssh.runFixed(target, [...prefix, "up", "--detach", "--no-build"], { timeoutMs: 5 * 60_000 });
      await this.waitHealthy(target, prefix);
      return {
        projectName: input.projectName,
        remoteDirectory,
        sshHost: target.host,
        sshUser: target.user,
        sshPort: target.port,
        ...(target.hostKeyAlgorithm ? { sshHostKeyAlgorithm: target.hostKeyAlgorithm } : {})
      };
    } finally {
      await rm(stage, { recursive: true, force: true });
    }
  }

  async disconnect(input: PrivateInstallation & { readonly server: ServerInput }): Promise<void> {
    const target = await this.target(input.server);
    const prefix = composePrefix(input.projectName, input.remoteDirectory);
    await this.options.ssh.runFixed(target, [...prefix, "stop", "runtime"]);
    await this.options.ssh.runFixed(target, [...prefix, "rm", "--force", "runtime", "runtime_secrets_init"]);
    await this.options.ssh.runFixed(target, ["docker", "volume", "rm", `${input.projectName}_runtime_secrets`]);
    await this.options.ssh.runFixed(target, ["rm", "-f", "--", `${input.remoteDirectory}/secrets/control-plane-api-key`]);
  }

  async remove(input: PrivateInstallation & { readonly server: ServerInput }): Promise<void> {
    const target = await this.target(input.server);
    const prefix = composePrefix(input.projectName, input.remoteDirectory);
    await this.options.ssh.runFixed(target, [...prefix, "down", "--volumes", "--remove-orphans"]);
    await this.options.ssh.runFixed(target, ["find", input.remoteDirectory, "-depth", "-delete"]);
  }

  async health(input: PrivateInstallation & { readonly server: ServerInput }): Promise<{ ssh: true; runtime: boolean }> {
    const target = await this.target(input.server);
    await this.options.ssh.check(target);
    const result = await this.options.ssh.runFixed(target, [
      ...composePrefix(input.projectName, input.remoteDirectory),
      "ps", "--format", "json"
    ]);
    return { ssh: true, runtime: runtimeIsHealthy(result.stdout) };
  }

  private async target(server: ServerInput): Promise<SshTarget> {
    const candidate = OpenSshAdapter.fromInput(server);
    return this.options.ssh.ensurePinned(candidate, this.options.pins, (fingerprint) => this.options.confirmation.confirm(fingerprint, candidate));
  }

  private async waitHealthy(target: SshTarget, prefix: readonly string[]): Promise<void> {
    for (let attempt = 0; attempt < 60; attempt += 1) {
      const result = await this.options.ssh.runFixed(target, [...prefix, "ps", "--format", "json"]);
      if (runtimeIsHealthy(result.stdout)) return;
      await new Promise<void>((resolve) => setTimeout(resolve, 2_000));
    }
    throw new Error("deployment_health_timeout");
  }
}

function composePrefix(projectName: string, remoteDirectory: string): string[] {
  return [
    "docker", "compose", "--project-name", projectName,
    "--env-file", `${remoteDirectory}/.env`,
    "--file", `${remoteDirectory}/compose.yaml`,
    "--ansi", "never"
  ];
}

function runtimeIsHealthy(output: string): boolean {
  const trimmed = output.trim();
  if (!trimmed) return false;
  try {
    const value = JSON.parse(trimmed) as unknown;
    const records = Array.isArray(value) ? value : [value];
    return records.some((entry) => {
      if (!entry || typeof entry !== "object") return false;
      const record = entry as Record<string, unknown>;
      return record.Service === "runtime" && record.State === "running" && record.Health === "healthy";
    });
  } catch {
    return trimmed.split("\n").some((line) => {
      try {
        const record = JSON.parse(line) as Record<string, unknown>;
        return record.Service === "runtime" && record.State === "running" && record.Health === "healthy";
      } catch { return false; }
    });
  }
}

export function availableBytesFromDf(output: string): number {
  const lines = output.trim().split(/\r?\n/u).filter(Boolean);
  const dataLine = lines.at(-1) ?? "";
  const match = dataLine.match(/^.+\s+\d+\s+\d+\s+(\d+)\s+\d+%\s+.+$/u);
  const availableKiB = match ? Number(match[1]) : Number.NaN;
  const availableBytes = availableKiB * 1024;
  if (!Number.isSafeInteger(availableBytes) || availableBytes < 0) throw new Error("server_capacity_check_failed");
  return availableBytes;
}

async function verifyTunnel(tunnelId: string, apiKey: string): Promise<void> {
  const response = await fetch(`https://api.openai.com/v1/tunnels/${tunnelId}`, {
    method: "GET",
    redirect: "error",
    signal: AbortSignal.timeout(15_000),
    headers: { authorization: `Bearer ${apiKey}` }
  });
  if (!response.ok) throw new Error("tunnel_credentials_invalid");
  const bytes = await response.arrayBuffer();
  if (bytes.byteLength > 256 * 1024) throw new Error("tunnel_response_too_large");
}

function opaqueId(prefix: string): string { return `${prefix}_${randomBytes(16).toString("hex")}`; }
function projectNameFor(installationId: string): string {
  return `vmb-${createHash("sha256").update(installationId, "utf8").digest("hex").slice(0, 20)}`;
}

function serverSummary(server: ServerInput, connected = false): ServerSummary {
  return { label: displayServerLabel(server), host: server.host, user: server.user, port: server.port, connected };
}

async function atomicWrite(path: string, value: unknown): Promise<void> {
  await atomicWriteText(path, `${JSON.stringify(value)}\n`);
}

async function atomicWriteText(path: string, value: string): Promise<void> {
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  const temporary = `${path}.${process.pid}.${Date.now()}.tmp`;
  const handle = await open(temporary, "wx", 0o600);
  try {
    await handle.writeFile(value, "utf8");
    await handle.sync();
  } finally {
    await handle.close();
  }
  await chmod(temporary, 0o600);
  await rename(temporary, path);
  await chmod(path, 0o600);
}

async function readRecord(path: string): Promise<PrivateRecord> {
  let value: unknown;
  try {
    value = JSON.parse(await readFile(path, "utf8")) as unknown;
  } catch (error) {
    if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") {
      return { version: 1, phase: "idle", paused: false };
    }
    throw new Error("private_setup_state_invalid");
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("private_setup_state_invalid");
  const record = value as PrivateRecord;
  if (record.version !== 1 || !["idle", "ready", "retained"].includes(record.phase) || typeof record.paused !== "boolean") {
    throw new Error("private_setup_state_invalid");
  }
  if (record.tunnelId !== undefined && !TUNNEL_ID_RE.test(record.tunnelId)) throw new Error("private_setup_state_invalid");
  for (const id of [record.vault?.id, record.installationId, record.deviceId]) {
    if (id !== undefined && !OPAQUE_ID_RE.test(id)) throw new Error("private_setup_state_invalid");
  }
  if (record.lastSyncResult !== undefined && !["published", "unchanged", "failed"].includes(record.lastSyncResult)) {
    throw new Error("private_setup_state_invalid");
  }
  if (record.lastSyncChanges !== undefined && !isSyncChanges(record.lastSyncChanges)) throw new Error("private_setup_state_invalid");
  if (record.sshHostKeyAlgorithm !== undefined && !isKnownHostAlgorithm(record.sshHostKeyAlgorithm)) {
    throw new Error("private_setup_state_invalid");
  }
  if (record.sshHost !== undefined && !SSH_HOST_RE.test(record.sshHost)) throw new Error("private_setup_state_invalid");
  if (record.sshUser !== undefined && !SSH_USER_RE.test(record.sshUser)) throw new Error("private_setup_state_invalid");
  if (record.sshPort !== undefined && (!Number.isInteger(record.sshPort) || record.sshPort < 1 || record.sshPort > 65_535)) {
    throw new Error("private_setup_state_invalid");
  }
  return record;
}

async function readKnownHostRecord(path: string): Promise<{ host: string; port: number; algorithm: SshHostKeyAlgorithm } | undefined> {
  try {
    for (const line of (await readFile(path, "utf8")).split(/\r?\n/u)) {
      const [hostField, algorithm] = line.trim().split(/\s+/u);
      if (!hostField || !isKnownHostAlgorithm(algorithm)) continue;
      const bracketed = hostField.match(/^\[([A-Za-z0-9._-]{1,255})\]:(\d{1,5})$/u);
      const host = bracketed?.[1] ?? hostField;
      const port = bracketed ? Number(bracketed[2]) : 22;
      if (SSH_HOST_RE.test(host) && Number.isInteger(port) && port >= 1 && port <= 65_535) {
        return { host, port, algorithm };
      }
    }
    return undefined;
  } catch (error) {
    if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") return undefined;
    throw new Error("private_known_hosts_invalid");
  }
}

function isKnownHostAlgorithm(value: unknown): value is SshHostKeyAlgorithm {
  return value === "ssh-ed25519" || value === "ecdsa-sha2-nistp256" || value === "ssh-rsa";
}

export function diagnosticFor(error: unknown, fallback: DiagnosticInfo["component"] = "sync"): DiagnosticInfo {
  const message = error instanceof Error ? error.message.toLowerCase() : "";
  if (/host key|known_hosts|fingerprint|server identity/u.test(message)) {
    return { code: "ssh_trust_failed", component: "ssh", retryable: false };
  }
  if (/permission denied|authentication|publickey/u.test(message)) {
    return { code: "ssh_auth_failed", component: "ssh", retryable: false };
  }
  if (/connection (?:refused|timed out)|no route|could not resolve|network is unreachable|server offline/u.test(message)) {
    return { code: "server_unreachable", component: "ssh", retryable: true };
  }
  if (fallback === "openai" || /tunnel|api key/u.test(message)) {
    return { code: "openai_tunnel_unavailable", component: "openai", retryable: true };
  }
  if (fallback === "runtime" || /docker|compose|runtime unavailable|service.*running/u.test(message)) {
    return { code: "runtime_unavailable", component: "runtime", retryable: true };
  }
  if (fallback === "vault" || /vault|scan/u.test(message)) {
    return { code: "vault_unavailable", component: "vault", retryable: true };
  }
  if (/receipt|snapshot|private-import|import failed|rejected/u.test(message)) {
    return { code: "snapshot_rejected", component: "runtime", retryable: true };
  }
  return { code: "sync_failed", component: fallback, retryable: true };
}

function diagnosticMessage(diagnostic: DiagnosticInfo): string {
  switch (diagnostic.code) {
    case "vault_unavailable": return "Vault scan failed";
    case "ssh_trust_failed": return "SSH trust failed";
    case "ssh_auth_failed": return "SSH authentication failed";
    case "server_unreachable": return "Server unavailable";
    case "runtime_unavailable": return "Server runtime unavailable";
    case "openai_tunnel_unavailable": return "OpenAI tunnel unavailable";
    case "snapshot_rejected": return "Snapshot import failed";
    default: return "Synchronization failed";
  }
}

function isDiagnosticInfo(value: unknown): value is DiagnosticInfo {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const diagnostic = value as Record<string, unknown>;
  return [
    "vault_unavailable",
    "ssh_trust_failed",
    "ssh_auth_failed",
    "server_unreachable",
    "runtime_unavailable",
    "openai_tunnel_unavailable",
    "snapshot_rejected",
    "sync_failed"
  ].includes(String(diagnostic.code)) &&
    ["vault", "ssh", "runtime", "openai", "sync"].includes(String(diagnostic.component)) &&
    typeof diagnostic.retryable === "boolean";
}

async function readJournal(path: string): Promise<JournalEntry[]> {
  let value: unknown;
  try {
    value = JSON.parse(await readFile(path, "utf8")) as unknown;
  } catch (error) {
    if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") return [];
    throw new Error("private_journal_invalid");
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("private_journal_invalid");
  const record = value as { version?: unknown; entries?: unknown };
  if (record.version !== 1 || !Array.isArray(record.entries) || record.entries.length > MAX_JOURNAL) {
    throw new Error("private_journal_invalid");
  }
  return record.entries.map((entry) => {
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) throw new Error("private_journal_invalid");
    const candidate = entry as JournalEntry;
    if (
      typeof candidate.at !== "string" || !Number.isFinite(new Date(candidate.at).getTime()) ||
      typeof candidate.message !== "string" || candidate.message.length > 160 ||
      !["info", "warn", "error"].includes(candidate.level) ||
      (candidate.changes !== undefined && !isSyncChanges(candidate.changes)) ||
      (candidate.diagnostic !== undefined && !isDiagnosticInfo(candidate.diagnostic))
    ) throw new Error("private_journal_invalid");
    return cloneJournalEntry(candidate);
  });
}

function isSyncChanges(value: unknown): value is SyncChanges {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const changes = value as Record<string, unknown>;
  return ["added", "modified", "removed", "unchanged", "total", "bytes"].every((key) =>
    Number.isSafeInteger(changes[key]) && Number(changes[key]) >= 0
  );
}

function cloneJournalEntry(entry: JournalEntry): JournalEntry {
  return {
    ...entry,
    ...(entry.changes ? { changes: { ...entry.changes } } : {}),
    ...(entry.diagnostic ? { diagnostic: { ...entry.diagnostic } } : {})
  };
}
