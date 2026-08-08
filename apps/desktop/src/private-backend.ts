import { createHash, randomBytes } from "node:crypto";
import { chmod, mkdir, open, readFile, realpath, rename } from "node:fs/promises";
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
  type SshTarget
} from "./ssh.js";
import {
  EMPTY_STATE,
  cloneState,
  displayServerLabel,
  type AttentionState,
  type DesktopBackend,
  type DesktopState,
  type JournalEntry,
  type ServerInput,
  type ServerSummary,
  type TunnelInput,
  type TunnelSummary,
  type VaultSummary
} from "./types.js";

const RUNTIME_KEY_SECRET = "secure-tunnel.runtime-api-key";
const TUNNEL_ID_RE = /^tunnel_[a-f0-9]{32}$/u;
const OPAQUE_ID_RE = /^[A-Za-z0-9_-]{16,256}$/u;
const IMAGE_RE = /^[a-z0-9][a-z0-9./_-]{0,255}(?:@sha256:[a-f0-9]{64}|:[A-Za-z0-9._-]{1,128})$/u;
const SAFE_REMOTE_HOME_RE = /^\/(?:[A-Za-z0-9._-]+\/?){1,20}$/u;
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
};

export interface PrivateInstallation {
  readonly projectName: string;
  readonly remoteDirectory: string;
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
}

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

  async initialize(): Promise<DesktopState> {
    this.record = await readRecord(this.recordPath());
    if (this.record.vault) {
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
    if (this.record.phase === "ready") {
      this.scheduleSync();
      void this.synchronize();
    }
    return cloneState(this.state);
  }

  close(): void {
    if (this.syncTimer) clearInterval(this.syncTimer);
    this.syncTimer = undefined;
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
    this.append("Vault scanned");
    await this.projectRecord();
    return { ...summary };
  }

  async configureServer(input: ServerInput): Promise<ServerSummary> {
    this.assertConfigurationMutable();
    const target = OpenSshAdapter.fromInput(input);
    const server = { host: target.host, user: target.user, port: target.port };
    this.record = { ...this.record, server, phase: "idle" };
    await this.persist();
    this.append("Server saved");
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
    this.append("OpenAI tunnel verified");
    await this.projectRecord();
    return { configured: true };
  }

  async setup(): Promise<DesktopState> {
    if (this.setupPromise) return this.setupPromise;
    this.setupPromise = this.runSetup().finally(() => { this.setupPromise = undefined; });
    return this.setupPromise;
  }

  async synchronize(): Promise<DesktopState> {
    if (this.syncPromise) return this.syncPromise;
    if (this.record.phase !== "ready" || this.record.paused) return cloneState(this.state);
    this.syncPromise = this.runSync().finally(() => { this.syncPromise = undefined; });
    return this.syncPromise;
  }

  async setPaused(paused: boolean): Promise<DesktopState> {
    this.record = { ...this.record, paused };
    await this.persist();
    this.append(paused ? "Sync paused" : "Sync resumed");
    await this.projectRecord();
    if (!paused) void this.synchronize();
    return cloneState(this.state);
  }

  async getJournal(): Promise<JournalEntry[]> { return this.journal.map((entry) => ({ ...entry })); }
  async setStartAtLogin(_enabled: boolean): Promise<void> {}

  async connectChatGpt(): Promise<DesktopState> {
    if (this.record.phase !== "ready") return this.fail("tunnel-not-configured", "Finish setup first", "retry");
    await this.options.browser?.openExternal("https://chatgpt.com/");
    this.append("ChatGPT opened");
    return cloneState(this.state);
  }

  async disconnect(): Promise<DesktopState> {
    const installation = this.installation();
    if (!installation || !this.record.server || this.record.phase !== "ready") return cloneState(this.state);
    try {
      await this.deployment.disconnect({ ...installation, server: this.record.server });
      this.record = { ...this.record, phase: "retained", paused: true };
      await this.persist();
      this.append("Remote access stopped");
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
      this.append("Server copy removed");
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
      this.record = { ...this.record, installationId, deviceId, projectName: installed.projectName, remoteDirectory: installed.remoteDirectory };
      await this.writeSyncConfig();
      this.state = { ...this.state, mode: "synchronizing", phase: "first-snapshot" };
      this.publish();
      const receipt = await this.syncOnce();
      this.record = {
        ...this.record,
        phase: "ready",
        paused: false,
        lastPublishedAt: this.now().toISOString()
      };
      await this.persist();
      this.append(receipt.status === "uploaded" ? "Vault synchronized" : "Vault unchanged");
      await this.projectRecord();
      this.scheduleSync();
      return cloneState(this.state);
    } catch (error) {
      return this.failFrom(error);
    }
  }

  private async runSync(): Promise<DesktopState> {
    this.state = { ...this.state, mode: "synchronizing", phase: "first-snapshot", attention: null };
    this.publish();
    try {
      const receipt = await this.syncOnce();
      this.record = { ...this.record, lastPublishedAt: this.now().toISOString() };
      await this.persist();
      this.append(receipt.status === "uploaded" ? "Vault synchronized" : "Vault unchanged");
      await this.projectRecord();
      return cloneState(this.state);
    } catch {
      return this.fail("sync-blocked", "Synchronization failed", "retry");
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
      remoteDirectory: installation.remoteDirectory,
      projectName: installation.projectName,
      include: ["**/*.md", "**/*.canvas", "**/*.base"],
      exclude: [".obsidian/**", "**/.obsidian/**", "**/.git/**", "**/.*", "**/node_modules/**"]
    };
    await atomicWrite(this.syncConfigPath(), config);
  }

  private async projectRecord(): Promise<void> {
    const hasKey = Boolean(this.record.tunnelId && await this.secrets.get(RUNTIME_KEY_SECRET));
    const active = this.record.phase === "ready";
    const retained = this.record.phase === "retained";
    const server = this.record.server ? serverSummary(this.record.server, active) : null;
    this.state = {
      ...this.state,
      mode: active ? "ready" : retained ? "onboarding" : "onboarding",
      phase: active ? "ready" : "idle",
      vault: this.record.vault ? { ...this.record.vault.summary } : null,
      server,
      tunnel: hasKey ? { configured: true } : null,
      requiresTunnelConfig: true,
      mcp: active ? { host: "Connected", resourceUrl: `https://api.openai.com/v1/tunnels/${this.record.tunnelId ?? ""}` } : null,
      paused: this.record.paused,
      lastPublishedAt: this.record.lastPublishedAt ?? null,
      attention: null,
      serverCopy: active ? "active" : retained ? "retained" : "none"
    };
    this.publish();
  }

  private installation(): PrivateInstallation | undefined {
    return this.record.projectName && this.record.remoteDirectory
      ? { projectName: this.record.projectName, remoteDirectory: this.record.remoteDirectory }
      : undefined;
  }

  private assertConfigurationMutable(): void {
    if (this.record.phase === "ready" || this.record.phase === "retained") throw new Error("disconnect_and_remove_before_configuration_change");
  }

  private async persist(): Promise<void> { await atomicWrite(this.recordPath(), this.record); }
  private recordPath(): string { return join(this.options.appDataPath, "private-setup.json"); }
  private syncConfigPath(): string { return join(this.options.appDataPath, "private-sync", "config.json"); }
  private now(): Date { return this.options.now?.() ?? new Date(); }

  private scheduleSync(): void {
    if (this.syncTimer) clearInterval(this.syncTimer);
    this.syncTimer = setInterval(() => { void this.synchronize(); }, this.options.config.syncIntervalMinutes * 60_000);
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

  private async fail(code: AttentionState["code"], message: string, action: AttentionState["action"]): Promise<DesktopState> {
    this.state = { ...this.state, mode: "attention", attention: { code, message, action } };
    this.append(message, "error");
    this.publish();
    return cloneState(this.state);
  }

  private append(message: string, level: JournalEntry["level"] = "info"): void {
    this.journal.push({ at: this.now().toISOString(), message: message.slice(0, 160), level });
    if (this.journal.length > MAX_JOURNAL) this.journal.splice(0, this.journal.length - MAX_JOURNAL);
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
    return { projectName: input.projectName, remoteDirectory };
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
  return record;
}
