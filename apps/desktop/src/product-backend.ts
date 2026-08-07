import { createHash } from "node:crypto";
import { join } from "node:path";

import {
  AgentService,
  DefaultVaultScanner,
  buildSnapshot,
  type CredentialStore,
  type PublisherTlsCredentialProvider,
  type RemoteClient,
  type VaultScanner
} from "@vault-mcp-bridge/agent-core";
import { normalizeVaultId, type EndpointBundle } from "@vault-mcp-bridge/contracts";
import {
  assertPreflight,
  evaluatePreflight,
  generateComposeProject,
  projectNameForInstallation,
  stageComposeProject,
  type ComposeProject,
  type DeploymentSpec,
  type HostProbe,
  type ResourceLimits
} from "@vault-mcp-bridge/deployment";
import {
  BoundedJournal,
  JsonFileStateStore,
  SetupOrchestrator,
  type DeployedService,
  type DeploymentPort,
  type DeploymentPreflight,
  type DeploymentPreflightInput,
  type DeploymentStageInput,
  type DeviceBindInput,
  type DeviceBinding,
  type EdgeInstallInput,
  type EdgeInstallation,
  type EndpointVerification,
  type EndpointVerificationPort,
  type EndpointVerifyInput,
  type FirstSnapshotInput,
  type OwnerEdgePort,
  type PublisherPort,
  type ServerSelection,
  type SetupInput,
  type SetupRecord,
  type SyncInput,
  type SyncReceipt,
  type VaultPreview,
  type VaultPreviewPort,
  type VaultPreviewInput,
  type DeploymentDeployInput,
  type DisconnectInput,
  type ReplicaCleanupInput,
  type ReplicaCleanupReceipt,
  type StagedDeployment,
  serverCopyDisposition
} from "@vault-mcp-bridge/orchestrator";

import { EdgeControlClient, type EdgeControlPort } from "./edge-client.js";
import { CredentialLeaseMaterializer } from "./lease.js";
import { SafeStorageOwnerTokenProvider, type BrowserOpener, type NativeOAuthClient, type OwnerTokenProvider } from "./oauth-client.js";
import type { PublisherIdentityProvider } from "./publisher-identity.js";
import { DesktopPublisherClient } from "./publisher-client.js";
import type { ProductConfig } from "./product-config.js";
import { SafeStorageSecretStore, type SecretStore } from "./secret-store.js";
import { FileHostKeyPinStore, OpenSftpAdapter, OpenSshAdapter, type HostKeyPinStore, type SecretUploader, type SshTarget } from "./ssh.js";
import {
  EMPTY_STATE,
  cloneState,
  displayServerLabel,
  type DesktopBackend,
  type DesktopState,
  type JournalEntry,
  type ServerInput,
  type ServerSummary,
  type SetupPhase,
  type VaultSummary
} from "./types.js";

const PUBLISHER_TLS_SECRET = "publisher.mtls.credentials";
const MAX_JOURNAL = 200;
const INSTALLATION_ID_RE = /^[A-Za-z0-9_-]{16,256}$/u;
const BROAD_INSTALLATION_ROOTS = new Set([
  "/",
  "/etc",
  "/home",
  "/opt",
  "/private",
  "/private/tmp",
  "/root",
  "/srv",
  "/tmp",
  "/usr",
  "/Users",
  "/var"
]);

const DEFAULT_LIMITS: ResourceLimits = {
  memoryBytes: 768 * 1024 * 1024,
  cpuCores: 1,
  pids: 256,
  tmpfsBytes: 64 * 1024 * 1024,
  maxBodyBytes: 2 * 1024 * 1024,
  maxVaultBytes: 256 * 1024 * 1024,
  maxDatabaseBytes: 512 * 1024 * 1024,
  maxIndexBytes: 256 * 1024 * 1024,
  maxTempBytes: 128 * 1024 * 1024,
  minFreeBytes: 2 * 1024 * 1024 * 1024,
  maxRetainedGenerations: 5,
  logBytes: 16 * 1024 * 1024,
  logFiles: 3
};

export interface FingerprintConfirmation {
  confirm(fingerprint: string, target: SshTarget): Promise<boolean>;
}

export interface DeviceBinder {
  bind(input: { publisherUrl: string; vaultId: string; publicKey: string; installationId: string }): Promise<{ deviceId: string }>;
}

export interface ProductBackendOptions {
  readonly appDataPath: string;
  readonly config?: ProductConfig;
  readonly secretStore?: SecretStore;
  readonly scanner?: VaultScanner;
  readonly edge?: EdgeControlPort;
  readonly ownerTokens?: OwnerTokenProvider;
  readonly browser?: BrowserOpener;
  readonly oauth?: NativeOAuthClient;
  readonly ssh?: OpenSshAdapter;
  readonly sftp?: OpenSftpAdapter;
  readonly pins?: HostKeyPinStore;
  readonly confirmation?: FingerprintConfirmation;
  readonly agent?: AgentService;
  readonly deviceBinder?: DeviceBinder;
  /** Generates and retains the publisher TLS key on this Mac. */
  readonly publisherIdentity?: PublisherIdentityProvider;
  readonly now?: () => Date;
  readonly allowLoopback?: boolean;
}

export interface DesktopLifecycleBackend extends DesktopBackend {
  initialize(): Promise<DesktopState>;
  close(): void;
  update(): Promise<DesktopState>;
  disconnect(): Promise<DesktopState>;
  removeServerCopy(): Promise<DesktopState>;
}

class ElectronCredentialStore implements CredentialStore {
  readonly kind = "keychain";

  constructor(private readonly secrets: SecretStore) {}

  async getPrivateKey(): Promise<string | undefined> { return (await this.secrets.get("device.ed25519.private")) ?? undefined; }
  async savePrivateKey(privateKey: string): Promise<void> { await this.secrets.put("device.ed25519.private", privateKey); }
  async deletePrivateKey(): Promise<void> { await this.secrets.remove("device.ed25519.private"); }

  async identity() {
    const value = await this.secrets.get("device.ed25519.identity");
    if (!value) return undefined;
    try {
      const parsed: unknown = JSON.parse(value);
      if (!parsed || typeof parsed !== "object") return undefined;
      const record = parsed as Record<string, unknown>;
      if (typeof record.publicKey !== "string" || typeof record.createdAt !== "string") return undefined;
      return { publicKey: record.publicKey, keyAlgorithm: "ed25519" as const, createdAt: record.createdAt };
    } catch {
      return undefined;
    }
  }

  async saveIdentity(privateKey: string, publicKey: string, createdAt: string): Promise<void> {
    await this.savePrivateKey(privateKey);
    await this.secrets.put("device.ed25519.identity", JSON.stringify({ publicKey, createdAt }));
  }
}

class DynamicAgentRemoteClient implements RemoteClient {
  constructor(private readonly current: () => RemoteClient | undefined) {}
  async pair(input: Parameters<RemoteClient["pair"]>[0]) { const client = this.current(); if (!client) throw new Error("publisher_not_configured"); return client.pair(input); }
  async upload(input: Parameters<RemoteClient["upload"]>[0]) { const client = this.current(); if (!client) throw new Error("publisher_not_configured"); return client.upload(input); }
  async status(input: Parameters<RemoteClient["status"]>[0]) { const client = this.current(); if (!client) throw new Error("publisher_not_configured"); return client.status(input); }
}

class VaultAdapter implements VaultPreviewPort {
  constructor(private readonly scanner: VaultScanner, private readonly now: () => Date) {}

  async preview(input: VaultPreviewInput): Promise<VaultPreview> {
    const vaultId = normalizeVaultId(input.vault.vaultId);
    const scan = await this.scanner.scan(input.vault.root, {
      vaultId,
      ...(input.vault.include ? { include: [...input.vault.include] } : {}),
      ...(input.vault.exclude ? { exclude: [...input.vault.exclude] } : {})
    });
    if (scan.errors.length > 0) throw new Error("vault_scan_incomplete");
    return {
      vaultId,
      label: input.vault.label,
      noteCount: scan.files.length,
      byteCount: scan.bytes,
      includedCount: scan.files.length,
      excludedCount: scan.excluded.length,
      projectionDigest: createHash("sha256").update(scan.files.map((file) => `${file.relativePath}:${file.sha256 ?? file.bytes}`).join("\n"), "utf8").digest("base64url"),
      receipt: {
        vaultId,
        displayName: input.vault.label,
        documentCount: scan.files.length,
        totalBytes: scan.bytes,
        scannedAt: this.now().toISOString(),
        unreadableCount: 0,
        projectionVersion: 1
      }
    };
  }
}

class ProductDeploymentAdapter implements DeploymentPort {
  private readonly verified = new Map<string, SshTarget>();
  private readonly projects = new Map<string, { target: SshTarget; composePath: string; project: ComposeProject }>();
  private readonly remoteHomes = new Map<string, string>();
  private currentRecord: SetupRecord | undefined;

  constructor(private readonly options: {
    config: ProductConfig;
    ssh: OpenSshAdapter;
    sftp: OpenSftpAdapter;
    pins: HostKeyPinStore;
    confirmation: FingerprintConfirmation;
    appDataPath: string;
    now: () => Date;
  }) {}

  async preflight(input: DeploymentPreflightInput): Promise<DeploymentPreflight> {
    const target = await this.ensureTarget(input.server);
    await this.options.ssh.check(target);
    const home = await this.remoteHome(target);
    const host = await this.probe(target, home);
    const report = evaluatePreflight(projectNameForInstallation(input.installationId), host, {
      mode: this.options.config.runtimeMode ?? "rootless",
      minimumCpuCores: 1,
      minimumMemoryBytes: DEFAULT_LIMITS.memoryBytes,
      minimumFreeSpaceBytes: DEFAULT_LIMITS.minFreeBytes,
      expectedStagingBytes: Math.min(DEFAULT_LIMITS.maxVaultBytes, input.preview.byteCount)
    });
    assertPreflight(report);
    return {
      os: host.os,
      architecture: host.arch,
      dockerMode: host.docker.rootless ? "rootless" : "rootful",
      ...(host.docker.composeVersion ? { composeVersion: host.docker.composeVersion } : {}),
      availableBytes: host.freeSpaceBytes,
      availableMemoryBytes: host.memoryBytes,
      availableCpuCount: host.cpuCores
    };
  }

  async stage(input: DeploymentStageInput): Promise<StagedDeployment> {
    const target = this.verified.get(input.server.host) ?? await this.ensureTarget(input.server);
    const bundle = requireBundle(input.edge);
    const remoteInstallationId = input.edge.installationRef;
    if (remoteInstallationId !== input.installationId) throw new Error("deployment_installation_mismatch");
    const directory = this.directoryFor(input.server, remoteInstallationId);
    if (!/^\/[A-Za-z0-9._/-]+$/u.test(directory) || directory.includes("..")) throw new Error("installation_directory_invalid");
    const project = generateComposeProject(this.spec(input, bundle, directory, remoteInstallationId));
    const localRoot = join(this.options.appDataPath, "staging", input.installationId);
    const staged = await stageComposeProject(localRoot, project);
    const remoteCompose = `${directory}/compose.yaml`;
    const uploader = this.options.sftp.withTarget(target);
    await uploader.ensureDirectory(directory);
    await uploader.upload(staged.path, remoteCompose);
    this.projects.set(input.installationId, { target, composePath: remoteCompose, project });
    return {
      projectName: project.projectName,
      release: this.release(),
      resourceLabel: input.installationId,
      cleanup: this.cleanupReceipt(input.server, project, directory, remoteCompose)
    };
  }

  async deploy(input: DeploymentDeployInput): Promise<DeployedService> {
    const project = this.projects.get(input.installationId) ?? await this.restoreProject(input.prior);
    const prefix = ["docker", "compose", "--project-name", project.project.projectName, "--file", project.composePath, "--ansi", "never"] as const;
    await this.options.ssh.runFixed(project.target, [...prefix, "config", "--quiet"]);
    await this.options.ssh.runFixed(project.target, [...prefix, "pull", "--quiet"], { timeoutMs: 10 * 60_000 });
    await this.options.ssh.runFixed(project.target, [...prefix, "up", "--detach", "--no-build"], { timeoutMs: 3 * 60_000 });
    await this.waitHealthy(project.target, prefix);
    return { projectName: project.project.projectName, release: input.staged.release, health: "healthy", startedAt: this.options.now().toISOString() };
  }

  async updateCurrent(record?: SetupRecord): Promise<void> {
    const current = record ?? this.currentRecord;
    if (!current?.edge || !current.preview || !current.preflight || !current.staged) throw new Error("deployment_not_staged");
    const previous = [...this.projects.values()][0] ?? await this.restoreProject(current);
    const directory = previous.composePath.replace(/\/compose\.yaml$/u, "");
    const stageInput = this.stageInput(current);
    const nextProject = generateComposeProject(this.spec(stageInput, requireBundle(current.edge), directory, current.edge.installationRef));
    if (nextProject.projectName !== current.staged.projectName) throw new Error("deployment_receipt_mismatch");
    const local = await stageComposeProject(join(this.options.appDataPath, "updates", current.installationId), nextProject);
    const rollbackPath = `${directory}/compose.rollback.yaml`;
    await this.options.ssh.runFixed(previous.target, ["cp", previous.composePath, rollbackPath]);
    await this.options.sftp.withTarget(previous.target).upload(local.path, previous.composePath);
    const prefix = ["docker", "compose", "--project-name", nextProject.projectName, "--file", previous.composePath, "--ansi", "never"] as const;
    try {
      await this.options.ssh.runFixed(previous.target, [...prefix, "config", "--quiet"]);
      await this.options.ssh.runFixed(previous.target, [...prefix, "pull", "--quiet"], { timeoutMs: 10 * 60_000 });
      await this.options.ssh.runFixed(previous.target, [...prefix, "up", "--detach", "--no-build"], { timeoutMs: 3 * 60_000 });
      await this.waitHealthy(previous.target, prefix);
      this.projects.set(current.installationId, { ...previous, project: nextProject });
    } catch (error) {
      await this.options.ssh.runFixed(previous.target, ["cp", rollbackPath, previous.composePath]).catch(() => undefined);
      const rollbackPrefix = ["docker", "compose", "--project-name", previous.project.projectName, "--file", previous.composePath, "--ansi", "never"] as const;
      await this.options.ssh.runFixed(previous.target, [...rollbackPrefix, "up", "--detach", "--no-build"]).catch(() => undefined);
      await this.waitHealthy(previous.target, rollbackPrefix).catch(() => undefined);
      throw error;
    }
  }

  async pairingCode(installationId: string, vaultId: string): Promise<string> {
    const project = this.projects.get(installationId) ?? (this.currentRecord ? await this.restoreProject(this.currentRecord) : undefined);
    if (!project) throw new Error("deployment_not_staged");
    const prefix = ["docker", "compose", "--project-name", project.project.projectName, "--file", project.composePath, "--ansi", "never"] as const;
    const result = await this.options.ssh.runFixed(project.target, [...prefix, "exec", "-T", "server", "node", "dist/cli.js", "pairing-code", "--vault-id", vaultId]);
    if (result.stdout.length > 64 * 1024) throw new Error("pairing_response_too_large");
    let value: unknown;
    try { value = JSON.parse(result.stdout.trim()) as unknown; } catch { throw new Error("pairing_response_invalid"); }
    if (!value || typeof value !== "object" || typeof (value as Record<string, unknown>).code !== "string") throw new Error("pairing_response_invalid");
    const code = (value as Record<string, unknown>).code;
    if (typeof code !== "string" || !/^[A-Za-z0-9_-]{16,256}$/u.test(code)) throw new Error("pairing_code_invalid");
    return code;
  }

  directoryFor(server: ServerSelection, installationId: string): string {
    if (this.options.config.installationDirectory) {
      return installationScopedDirectory(this.options.config.installationDirectory, installationId);
    }
    const home = this.remoteHomes.get(serverKey(server));
    if (!home) throw new Error("remote_home_unavailable");
    return installationScopedDirectory(`${home}/.local/share/vault-bridge/installations`, installationId, home);
  }

  setRecord(record: SetupRecord): void { this.currentRecord = record; }

  async disconnect(input: DisconnectInput): Promise<void> {
    if (!input.prior.edge || !input.prior.staged) return;
    const receipt = input.prior.staged.cleanup;
    if (!receipt) throw new Error("deployment_cleanup_scope_missing");
    const target = await this.assertCleanupReceipt(receipt, input.prior.request.server, input.installationId);
    if (input.projectName !== undefined && receipt.projectName !== input.projectName) {
      throw new Error("deployment_project_mismatch");
    }
    if (input.resourceLabel !== undefined && receipt.resourceLabel !== input.resourceLabel) {
      throw new Error("deployment_resource_mismatch");
    }
    if (input.prior.edge.installationRef !== input.installationId) {
      throw new Error("deployment_installation_mismatch");
    }
    const directory = receipt.installationDirectory;
    const exists = await this.remoteDirectoryExists(target, directory);
    if (exists) {
      // Do not issue Docker Compose against an unexpected or manually removed
      // file. This prevents a stale receipt from widening the operation.
      const composeExists = await this.remoteFileExists(target, receipt.composePath);
      if (!composeExists) throw new Error("deployment_compose_missing");
      const prefix = ["docker", "compose", "--project-name", receipt.projectName, "--file", receipt.composePath, "--ansi", "never"] as const;
      await this.options.ssh.runFixed(target, [...prefix, "down", "--timeout", "30"]);
    }

    // Revoked credentials are never retained with the data replica. Exact
    // named-volume removal is version-stable even after the Compose directory
    // is deleted, which makes a crash before the local commit retryable.
    await this.assertNoOwnedContainersOrNetworks(target, receipt);
    await this.assertOwnedVolumes(target, receipt, new Set(Object.values(receipt.volumes)));
    await this.removeExactVolume(target, receipt, "serverRuntime");
    await this.removeExactVolume(target, receipt, "tunnelRuntime");
    if (!input.keepReplica) await this.removeExactVolume(target, receipt, "replica");
    await this.assertOwnedVolumes(target, receipt, input.keepReplica ? new Set([receipt.volumes.replica]) : new Set());
    if (await this.remoteDirectoryExists(target, directory)) {
      await this.options.ssh.runFixed(target, ["rm", "-rf", "--", directory]);
    }
    if (await this.remoteDirectoryExists(target, directory)) throw new Error("installation_directory_not_removed");
    this.projects.delete(input.installationId);
  }

  async removeReplica(input: ReplicaCleanupInput): Promise<void> {
    const receipt = input.receipt;
    const target = await this.assertCleanupReceipt(receipt, input.request.server, input.installationId);
    // Establish that the cleanup directory is either present or provably
    // absent before deleting any data volume. Probe failures are not absence.
    await this.remoteDirectoryExists(target, receipt.installationDirectory);
    await this.assertNoOwnedContainersOrNetworks(target, receipt);
    await this.assertOwnedVolumes(target, receipt, new Set(Object.values(receipt.volumes)));
    await this.removeExactVolume(target, receipt, "serverRuntime");
    await this.removeExactVolume(target, receipt, "tunnelRuntime");
    await this.removeExactVolume(target, receipt, "replica");
    await this.assertOwnedVolumes(target, receipt, new Set());
    if (await this.remoteDirectoryExists(target, receipt.installationDirectory)) {
      await this.options.ssh.runFixed(target, ["rm", "-rf", "--", receipt.installationDirectory]);
    }
    if (await this.remoteDirectoryExists(target, receipt.installationDirectory)) {
      throw new Error("installation_directory_not_removed");
    }
    this.projects.delete(input.installationId);
  }

  private cleanupReceipt(
    server: ServerSelection,
    project: ComposeProject,
    installationDirectory: string,
    composePath: string
  ): ReplicaCleanupReceipt {
    const resourceLabel = project.labels["com.vault-mcp-bridge.installation-id"];
    if (resourceLabel !== project.installationId) throw new Error("deployment_resource_mismatch");
    return {
      schemaVersion: 1,
      installationId: project.installationId,
      server: cloneServerSelection(server),
      projectName: project.projectName,
      resourceLabel,
      installationDirectory,
      composePath,
      volumes: {
        replica: `${project.projectName}_replica_data`,
        serverRuntime: `${project.projectName}_server_secrets`,
        tunnelRuntime: `${project.projectName}_tunnel_secrets`
      }
    };
  }

  private async assertCleanupReceipt(
    receipt: ReplicaCleanupReceipt,
    requestServer: ServerSelection,
    installationId: string,
    existingTarget?: SshTarget
  ): Promise<SshTarget> {
    if (receipt.schemaVersion !== 1 || receipt.installationId !== installationId || !INSTALLATION_ID_RE.test(installationId)) {
      throw new Error("deployment_installation_mismatch");
    }
    if (serverKey(receipt.server) !== serverKey(requestServer)) throw new Error("deployment_server_mismatch");
    const projectName = projectNameForInstallation(installationId);
    if (receipt.projectName !== projectName || receipt.resourceLabel !== installationId) {
      throw new Error("deployment_project_mismatch");
    }
    const expectedVolumes = {
      replica: `${projectName}_replica_data`,
      serverRuntime: `${projectName}_server_secrets`,
      tunnelRuntime: `${projectName}_tunnel_secrets`
    };
    if (
      receipt.volumes.replica !== expectedVolumes.replica ||
      receipt.volumes.serverRuntime !== expectedVolumes.serverRuntime ||
      receipt.volumes.tunnelRuntime !== expectedVolumes.tunnelRuntime
    ) {
      throw new Error("deployment_volume_mismatch");
    }
    const target = existingTarget ?? await this.ensureTarget(receipt.server);
    const parent = receipt.installationDirectory.slice(0, -(installationId.length + 1));
    let expectedDirectory: string;
    try {
      expectedDirectory = installationScopedDirectory(parent, installationId);
    } catch {
      throw new Error("installation_directory_invalid");
    }
    if (
      receipt.installationDirectory !== expectedDirectory ||
      receipt.composePath !== `${expectedDirectory}/compose.yaml` ||
      !expectedDirectory.endsWith(`/${installationId}`) ||
      expectedDirectory.includes("..")
    ) {
      throw new Error("installation_directory_invalid");
    }
    return target;
  }

  private async assertNoOwnedContainersOrNetworks(target: SshTarget, receipt: ReplicaCleanupReceipt): Promise<void> {
    const label = `label=com.vault-mcp-bridge.installation-id=${receipt.resourceLabel}`;
    const containers = await this.options.ssh.runFixed(target, ["docker", "ps", "--all", "--quiet", "--filter", label]);
    if (containers.stdout.trim()) throw new Error("deployment_containers_remain");
    const networks = await this.options.ssh.runFixed(target, ["docker", "network", "ls", "--quiet", "--filter", label]);
    if (networks.stdout.trim()) throw new Error("deployment_networks_remain");
  }

  private async assertOwnedVolumes(
    target: SshTarget,
    receipt: ReplicaCleanupReceipt,
    allowed: ReadonlySet<string>
  ): Promise<void> {
    const label = `label=com.vault-mcp-bridge.installation-id=${receipt.resourceLabel}`;
    const result = await this.options.ssh.runFixed(target, ["docker", "volume", "ls", "--quiet", "--filter", label]);
    const names = result.stdout.split("\n").map((value) => value.trim()).filter(Boolean);
    if (names.some((name) => !/^[a-z0-9][a-z0-9_.-]{0,254}$/u.test(name) || !allowed.has(name))) {
      throw new Error("deployment_volumes_remain");
    }
    for (const key of ["replica", "serverRuntime", "tunnelRuntime"] as const) {
      const exact = receipt.volumes[key];
      const exists = await this.exactVolumeExists(target, receipt, key);
      if (exists && !allowed.has(exact)) throw new Error("deployment_volumes_remain");
    }
  }

  private async removeExactVolume(
    target: SshTarget,
    receipt: ReplicaCleanupReceipt,
    key: keyof ReplicaCleanupReceipt["volumes"]
  ): Promise<void> {
    const volume = receipt.volumes[key];
    if (!/^[a-z0-9][a-z0-9_.-]{0,254}$/u.test(volume)) throw new Error("deployment_volume_mismatch");
    if (!(await this.exactVolumeExists(target, receipt, key))) return;
    await this.options.ssh.runFixed(target, ["docker", "volume", "rm", volume]);
    if (await this.exactVolumeExists(target, receipt, key)) throw new Error("deployment_volume_not_removed");
  }

  private async exactVolumeExists(
    target: SshTarget,
    receipt: ReplicaCleanupReceipt,
    key: keyof ReplicaCleanupReceipt["volumes"]
  ): Promise<boolean> {
    const volume = receipt.volumes[key];
    const listed = await this.options.ssh.runFixed(target, ["docker", "volume", "ls", "--quiet", "--filter", `name=${volume}`]);
    const matches = listed.stdout.split("\n").map((value) => value.trim()).filter(Boolean);
    if (!matches.includes(volume)) return false;
    const output = (await this.options.ssh.runFixed(target, ["docker", "volume", "inspect", volume])).stdout;
    let value: unknown;
    try { value = JSON.parse(output) as unknown; } catch { throw new Error("deployment_volume_inspect_invalid"); }
    const item = Array.isArray(value) ? value[0] : undefined;
    if (!item || typeof item !== "object") throw new Error("deployment_volume_inspect_invalid");
    const metadata = item as Record<string, unknown>;
    const labels = metadata.Labels;
    const expectedComponent = key === "replica" ? "replica" : key === "serverRuntime" ? "server-secrets" : "tunnel-secrets";
    if (
      metadata.Name !== volume ||
      !labels ||
      typeof labels !== "object" ||
      (labels as Record<string, unknown>)["com.vault-mcp-bridge.installation-id"] !== receipt.resourceLabel ||
      (labels as Record<string, unknown>)["com.vault-mcp-bridge.project"] !== receipt.projectName ||
      (labels as Record<string, unknown>)["com.vault-mcp-bridge.component"] !== expectedComponent
    ) {
      throw new Error("deployment_volume_ownership_mismatch");
    }
    return true;
  }

  private async remoteDirectoryExists(target: SshTarget, directory: string): Promise<boolean> {
    return this.remotePathExists(target, directory, "d");
  }

  private async remoteFileExists(target: SshTarget, path: string): Promise<boolean> {
    return this.remotePathExists(target, path, "f");
  }

  private async remotePathExists(target: SshTarget, path: string, type: "d" | "f"): Promise<boolean> {
    const separator = path.lastIndexOf("/");
    const parent = separator === 0 ? "/" : path.slice(0, separator);
    const name = path.slice(separator + 1);
    if (!path.startsWith("/") || !parent || !/^[A-Za-z0-9._-]+$/u.test(name)) throw new Error("installation_path_invalid");
    // Listing the exact child through its parent produces a successful empty
    // result for absence, while inaccessible or missing parents stay errors.
    // This avoids treating an arbitrary SSH exit code 1 as proof of deletion.
    const result = await this.options.ssh.runFixed(target, [
      "find", parent, "-maxdepth", "1", "-mindepth", "1", "-name", name, "-type", type, "-print"
    ]);
    const matches = result.stdout.split("\n").map((value) => value.trim()).filter(Boolean);
    if (matches.some((value) => value !== path)) throw new Error("installation_path_probe_invalid");
    return matches.length === 1;
  }

  private async ensureTarget(input: ServerSelection): Promise<SshTarget> {
    const candidate = OpenSshAdapter.fromInput({ host: input.host, user: input.user, port: input.port ?? 22, ...(input.hostKeyFingerprint ? { hostKeyFingerprint: input.hostKeyFingerprint } : {}) });
    const resolved = await this.options.ssh.ensurePinned(candidate, this.options.pins, (fingerprint) => this.options.confirmation.confirm(fingerprint, candidate));
    this.verified.set(input.host, resolved);
    return resolved;
  }

  private async waitHealthy(target: SshTarget, prefix: readonly string[]): Promise<void> {
    for (let attempt = 0; attempt < 60; attempt += 1) {
      const result = await this.options.ssh.runFixed(target, [...prefix, "ps", "--format", "json"]);
      if (composeHealthy(result.stdout)) return;
      await new Promise<void>((resolve) => setTimeout(resolve, 2000));
    }
    throw new Error("deployment_health_timeout");
  }

  private async probe(target: SshTarget, home: string): Promise<HostProbe> {
    const read = async (command: readonly string[]): Promise<string> => (await this.options.ssh.runFixed(target, command)).stdout.trim();
    const os = await read(["uname", "-s"]);
    const arch = await read(["uname", "-m"]);
    const dockerVersion = await read(["docker", "version"]);
    const composeVersion = await read(["docker", "compose", "version"]);
    const dockerInfo = await read(["docker", "info"]);
    const cpu = Number.parseInt(await read(["nproc"]), 10);
    const memory = parseMemory(await read(["free", "-b"]));
    const freeSpace = parseDisk(await read(["df", "-Pk", home]));
    const projects = parseProjects(await read(["docker", "compose", "ls", "--format", "json"]));
    let outboundHttps = false;
    try {
      await this.options.ssh.runFixed(target, ["curl", "--silent", "--show-error", "--output", "/dev/null", "--max-time", "10", "https://api.cloudflare.com/client/v4"]);
      outboundHttps = true;
    } catch { /* preflight reports a concise outbound failure */ }
    return { os, arch, docker: { available: Boolean(dockerVersion), version: dockerVersion.slice(0, 128), rootless: /rootless/iu.test(dockerInfo), composeAvailable: Boolean(composeVersion), composeVersion: composeVersion.slice(0, 128) }, cpuCores: Number.isFinite(cpu) && cpu > 0 ? cpu : 1, memoryBytes: memory, freeSpaceBytes: freeSpace, outboundHttps, projectNames: projects, filesystemQuota: "unknown" };
  }

  private async remoteHome(target: SshTarget): Promise<string> {
    const key = serverKey(target);
    const cached = this.remoteHomes.get(key);
    if (cached) return cached;
    const result = await this.options.ssh.runFixed(target, ["pwd"]);
    const home = result.stdout.trim();
    if (!/^\/[A-Za-z0-9._/-]+$/u.test(home) || home.includes("..") || home.length > 1024) throw new Error("remote_home_invalid");
    this.remoteHomes.set(key, home.replace(/\/$/u, "") || "/");
    return this.remoteHomes.get(key)!;
  }

  private async restoreProject(record: SetupRecord): Promise<{ target: SshTarget; composePath: string; project: ComposeProject }> {
    const existing = this.projects.get(record.installationId);
    if (existing) return existing;
    if (!record.edge || !record.preview || !record.preflight || !record.staged) throw new Error("deployment_not_staged");
    const target = await this.ensureTarget(record.request.server);
    await this.remoteHome(target);
    const directory = this.directoryFor(record.request.server, record.edge.installationRef);
    const stageInput = this.stageInput(record);
    const project = generateComposeProject(this.spec(stageInput, requireBundle(record.edge), directory, record.edge.installationRef));
    if (project.projectName !== record.staged.projectName) throw new Error("deployment_receipt_mismatch");
    const restored = { target, composePath: `${directory}/compose.yaml`, project };
    this.projects.set(record.installationId, restored);
    return restored;
  }

  private stageInput(record: SetupRecord): DeploymentStageInput {
    if (!record.edge || !record.preview || !record.preflight) throw new Error("deployment_not_staged");
    return {
      setupId: record.setupId,
      installationId: record.installationId,
      idempotencyKey: `${record.setupId}:restore-stage`,
      request: record.request,
      prior: record,
      server: record.request.server,
      preview: record.preview,
      preflight: record.preflight,
      edge: record.edge,
    };
  }


  private spec(input: DeploymentStageInput, bundle: EndpointBundle, directory: string, installationId: string): DeploymentSpec {
    const secret = (name: string, file: string, uid: number) => ({ name, file, uid, gid: uid, mode: 0o440 });
    return {
      installationId,
      vaultId: normalizeVaultId(input.preview.vaultId),
      installationDirectory: directory,
      images: { server: { repository: this.options.config.images.serverRepository, digest: this.options.config.images.serverDigest }, tunnel: { repository: this.options.config.images.tunnelRepository, digest: this.options.config.images.tunnelDigest } },
      endpoints: { mcpHost: bundle.mcpHost, publisherHost: bundle.publisherHost },
      environment: { nodeEnvironment: "production", mcpResourceUrl: bundle.mcpResourceUrl, publisherUrl: bundle.publisherUrl, jwtIssuer: bundle.oauthIssuer, jwtAudience: bundle.oauthAudience, allowedHosts: `${bundle.mcpHost},${bundle.publisherHost}` },
      tunnelCredential: secret(bundle.tunnelCredential.id, `secrets/${bundle.tunnelCredential.id}`, 65_532),
      publisherEdgeAttestationSecret: secret(bundle.publisherEdgeAttestation.id, `secrets/${bundle.publisherEdgeAttestation.id}`, 10_001),
      mcpEdgeAttestationSecret: secret(bundle.mcpEdgeAttestation.id, `secrets/${bundle.mcpEdgeAttestation.id}`, 10_001),
      oauthVerificationBundle: secret("oauth-verification", "secrets/oauth-verification", 10_001),
      limits: DEFAULT_LIMITS,
      ...(this.options.config.runtimeMode ? { runtimeMode: this.options.config.runtimeMode } : {})
    };
  }

  private release(): string { return `${this.options.config.images.serverRepository}@${this.options.config.images.serverDigest}`; }
}

class ProductOwnerEdgeAdapter implements OwnerEdgePort {
  constructor(private readonly options: {
    edge: EdgeControlPort;
    secrets: SecretStore;
    uploader: (server: ServerSelection) => Promise<SecretUploader>;
    appDataPath: string;
    directoryFor: (server: ServerSelection, installationId: string) => string;
    publisherIdentity?: PublisherIdentityProvider;
  }) {}

  async install(input: EdgeInstallInput): Promise<EdgeInstallation> {
    const identity = await this.options.publisherIdentity?.ensure(input.installationId);
    const edge = await this.options.edge.createInstallation({ installationId: input.installationId, vaultId: input.request.vault.vaultId, idempotencyKey: input.idempotencyKey, ...(identity ? { publisherCsr: identity.csr } : {}) });
    const bundle = requireBundle(edge);
    const remoteInstallationId = edge.installationRef;
    const directory = this.options.directoryFor(input.server, remoteInstallationId);
    const uploader = await this.options.uploader(input.server);
    const materializer = new CredentialLeaseMaterializer(this.options.edge, uploader, join(this.options.appDataPath, "staging", remoteInstallationId));
    await materializer.materializeAndUpload({ installationId: remoteInstallationId, remoteDirectory: `${directory}/secrets`, secretName: bundle.tunnelCredential.id, kind: "tunnel" });
    await materializer.materializeAndUpload({ installationId: remoteInstallationId, remoteDirectory: `${directory}/secrets`, secretName: bundle.publisherEdgeAttestation.id, kind: "publisher-edge-attestation" });
    await materializer.materializeAndUpload({ installationId: remoteInstallationId, remoteDirectory: `${directory}/secrets`, secretName: bundle.mcpEdgeAttestation.id, kind: "mcp-edge-attestation" });
    // The verification bundle contains public signing keys, but it is still
    // staged with the same private 0600 boundary before it reaches the VPS.
    const staging = join(this.options.appDataPath, "staging", input.installationId, "oauth-verification");
    const { mkdir, open, unlink } = await import("node:fs/promises");
    await mkdir(join(this.options.appDataPath, "staging", input.installationId), { recursive: true, mode: 0o700 });
    let handle: Awaited<ReturnType<typeof open>> | undefined;
    try {
      handle = await open(staging, "wx", 0o600);
      await handle.writeFile(JSON.stringify(bundle.oauthVerificationBundle), "utf8");
      await handle.sync();
      await uploader.ensureDirectory(`${directory}/secrets`);
      await uploader.upload(staging, `${directory}/secrets/oauth-verification`);
    } finally {
      if (handle) await handle.close().catch(() => undefined);
      await unlink(staging).catch(() => undefined);
    }
    // mTLS private material is kept in safeStorage and is never copied to the
    // VPS. The lease is one-use and the plaintext exists only in this scope.
    const localMaterializer = new CredentialLeaseMaterializer(this.options.edge, uploader, join(this.options.appDataPath, "staging", remoteInstallationId));
    const tls = await localMaterializer.redeemInMemory(remoteInstallationId, "publisher-mtls");
    let certificate = tls.value;
    let caCertificate: string | undefined;
    try {
      const parsed: unknown = JSON.parse(tls.value);
      if (parsed && typeof parsed === "object" && typeof (parsed as Record<string, unknown>).certificate === "string") {
        const record = parsed as Record<string, unknown>;
        certificate = record.certificate as string;
        caCertificate = typeof record.caCertificate === "string" ? record.caCertificate : undefined;
      }
    } catch { /* certificate-only payloads are accepted below */ }
    const privateKey = identity?.privateKey;
    if (!privateKey) throw new Error("publisher_private_key_required");
    await this.options.secrets.put(PUBLISHER_TLS_SECRET, JSON.stringify({ certificate, privateKey, ...(caCertificate ? { caCertificate } : {}) }));
    return edge;
  }

  async disconnect(input: DisconnectInput): Promise<void> {
    const installationId = input.prior.edge?.installationRef;
    if (!installationId || installationId !== input.installationId) throw new Error("edge_installation_mismatch");
    await this.options.edge.revokeInstallation(installationId, input.idempotencyKey);
    // Delete locally retained mTLS material only after edge revocation has
    // succeeded. A failed revoke must leave the receipt retryable.
    await this.options.secrets.remove(PUBLISHER_TLS_SECRET);
  }
}

class ProductPublisherAdapter implements PublisherPort {
  private agent: AgentService | undefined;

  constructor(private readonly options: { agent?: AgentService; agentFactory: () => Promise<AgentService>; credentials: CredentialStore; scanner: VaultScanner; remote: RemoteClient; binder?: DeviceBinder }) { this.agent = options.agent; }

  private async service(): Promise<AgentService> { if (!this.agent) this.agent = await this.options.agentFactory(); return this.agent; }

  async bindDevice(input: DeviceBindInput): Promise<DeviceBinding> {
    const agent = await this.service();
    const identity = agent.getIdentity() ?? (await agent.generateIdentity()).identity;
    if (!this.options.binder) throw new Error("publisher_device_bind_required");
    const bundle = requireBundle(input.edge);
    const bound = await this.options.binder.bind({ publisherUrl: bundle.publisherUrl, vaultId: bundle.vaultId, publicKey: identity.publicKey, installationId: bundle.installationId });
    return { deviceId: bound.deviceId, publisherCredentialRef: bundle.publisherMtlsCredential.id };
  }

  async publishFirstSnapshot(input: FirstSnapshotInput) {
    const bundle = requireBundle(input.edge);
    const vaultId = normalizeVaultId(input.vault.vaultId);
    const agent = await this.service();
    await agent.configure({ vaultRoot: input.vault.root, vaultId, remoteServerUrl: bundle.publisherUrl });
    const preview = await agent.preview({ accept: true });
    if (!preview.accepted) throw new Error("preview_required");
    const privateKey = await this.options.credentials.getPrivateKey();
    if (!privateKey) throw new Error("device_identity_required");
    const status = await this.options.remote.status({ url: bundle.publisherUrl, deviceId: input.device.deviceId, vaultId, privateKey });
    const scan = await this.options.scanner.scan(input.vault.root, { vaultId });
    if (scan.errors.length > 0) throw new Error("vault_scan_incomplete");
    const payload = buildSnapshot(scan, vaultId, (status.generation ?? 0) + 1, new Date().toISOString());
    const value = await this.options.remote.upload({ url: bundle.publisherUrl, deviceId: input.device.deviceId, vaultId, snapshot: payload, privateKey });
    const receipt = value as { snapshotId: string; generation: number; digest: string; documentCount: number; receivedAt: string };
    return { snapshotId: receipt.snapshotId, generation: receipt.generation, digest: receipt.digest, documentCount: receipt.documentCount, publishedAt: new Date(receipt.receivedAt).toISOString() };
  }

  async syncNow(input: SyncInput): Promise<SyncReceipt> {
    const receipt = await this.publishFirstSnapshot({ ...input, device: input.device });
    return { generation: receipt.generation, documentCount: receipt.documentCount, digest: receipt.digest, publishedAt: receipt.publishedAt };
  }
}

class HiddenDeviceBinder implements DeviceBinder {
  constructor(private readonly options: { deployment: ProductDeploymentAdapter; vaultId: string; credentials: CredentialStore; remote: RemoteClient }) {}

  async bind(input: { publisherUrl: string; vaultId: string; publicKey: string; installationId: string }): Promise<{ deviceId: string }> {
    const code = await this.options.deployment.pairingCode(input.installationId, input.vaultId);
    const privateKey = await this.options.credentials.getPrivateKey();
    if (!privateKey) throw new Error("device_identity_required");
    const deviceId = `device_${createHash("sha256").update(input.publicKey, "utf8").digest("base64url")}`;
    const result = await this.options.remote.pair({ url: input.publisherUrl, code, agentId: deviceId, publicKey: input.publicKey, vaultId: input.vaultId, label: "Vault Bridge desktop" });
    return { deviceId: result.deviceId };
  }
}

class EndpointAdapter implements EndpointVerificationPort {
  constructor(private readonly fetcher: typeof fetch = fetch) {}

  async verify(input: EndpointVerifyInput): Promise<EndpointVerification> {
    const bundle = requireBundle(input.edge);
    const protectedMetadata = await this.fetcher(bundle.oauthProtectedResourceMetadataUrl, { method: "GET", redirect: "error" });
    if (!protectedMetadata.ok) throw new Error("oauth_resource_metadata_unreachable");
    const protectedValue: unknown = await boundedJson(protectedMetadata);
    if (!protectedValue || typeof protectedValue !== "object") throw new Error("oauth_resource_metadata_invalid");
    const authorizationServer = await this.fetcher(new URL("/.well-known/oauth-authorization-server", bundle.oauthIssuer).toString(), { method: "GET", redirect: "error" });
    if (!authorizationServer.ok) throw new Error("oauth_authorization_metadata_unreachable");
    const metadata: unknown = await boundedJson(authorizationServer);
    if (!metadata || typeof metadata !== "object" || (metadata as Record<string, unknown>).issuer !== bundle.oauthIssuer) throw new Error("oauth_issuer_mismatch");
    const jwks = await this.fetcher(bundle.oauthJwksUri, { method: "GET", redirect: "error" });
    if (!jwks.ok) throw new Error("oauth_jwks_unreachable");
    const jwksValue = await boundedJson(jwks);
    const keys = jwksValue && typeof jwksValue === "object" ? (jwksValue as Record<string, unknown>).keys : undefined;
    if (!Array.isArray(keys) || keys.length === 0) throw new Error("oauth_jwks_invalid");
    const probe = await this.fetcher(input.endpointUrl, { method: "POST", redirect: "error", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: "probe", method: "initialize", params: {} }) });
    if (probe.status !== 401 || !probe.headers.get("www-authenticate")) throw new Error("mcp_auth_unverified");
    return { endpointUrl: input.endpointUrl, mcp: "ok", oauth: "ok", verifiedAt: new Date().toISOString() };
  }
}

async function boundedJson(response: Response): Promise<unknown> {
  const length = Number(response.headers.get("content-length") ?? 0);
  if (Number.isFinite(length) && length > 256 * 1024) throw new Error("endpoint_response_too_large");
  const bytes = await response.arrayBuffer();
  if (bytes.byteLength > 256 * 1024) throw new Error("endpoint_response_too_large");
  try { return JSON.parse(new TextDecoder().decode(bytes)) as unknown; } catch { throw new Error("endpoint_response_invalid"); }
}

export class ProductDesktopBackend implements DesktopLifecycleBackend {
  private state = cloneState(EMPTY_STATE);
  private vaultRoot: string | undefined;
  private serverInput: ServerInput | undefined;
  private readonly listeners = new Set<(state: DesktopState) => void>();
  private readonly journal: JournalEntry[] = [];
  private setupPromise: Promise<DesktopState> | undefined;
  private readonly scanner: VaultScanner;
  private readonly secrets: SecretStore;
  private readonly edge: EdgeControlPort | undefined;
  private readonly ownerTokens: OwnerTokenProvider | undefined;
  private readonly stateStore: JsonFileStateStore;
  private orchestrator: SetupOrchestrator | undefined;
  private deployment: ProductDeploymentAdapter | undefined;
  private syncTimer: NodeJS.Timeout | undefined;

  public constructor(private readonly options: ProductBackendOptions) {
    this.secrets = options.secretStore ?? new SafeStorageSecretStore(join(options.appDataPath, "secrets.json"), { isEncryptionAvailable: () => false });
    this.scanner = options.scanner ?? new DefaultVaultScanner();
    this.ownerTokens = options.ownerTokens ?? (options.secretStore ? new SafeStorageOwnerTokenProvider(options.secretStore) : undefined);
    this.edge = options.edge ?? (options.config && this.ownerTokens ? new EdgeControlClient(options.config, this.ownerTokens, { ...(options.allowLoopback !== undefined ? { allowLoopback: options.allowLoopback } : {}) }) : undefined);
    this.stateStore = new JsonFileStateStore(join(options.appDataPath, "setup.json"));
    if (!options.config) this.setAttention("oauth-not-linked", "Edge not configured", "connect");
  }

  async initialize(): Promise<DesktopState> {
    const record = await this.stateStore.load();
    if (!record) return cloneState(this.state);
    this.vaultRoot = record.request.vault.root;
    this.serverInput = { host: record.request.server.host, user: record.request.server.user, port: record.request.server.port ?? 22 };
    this.state = {
      ...this.state,
      vault: { name: record.request.vault.label, noteCount: record.preview?.noteCount ?? 0, bytes: record.preview?.byteCount ?? 0 },
      server: { label: displayServerLabel(this.serverInput), host: this.serverInput.host, user: this.serverInput.user, port: this.serverInput.port, connected: record.phase === "ready" }
    };
    this.applyRecord(record);
    if (!this.options.config || !this.edge) {
      if (serverCopyDisposition(record) !== "unknown") {
        this.setAttention("oauth-not-linked", "Edge not configured", "connect");
        this.publish();
      }
      return cloneState(this.state);
    }
    const orchestrator = await this.ensureOrchestrator();
    this.deployment?.setRecord(record);
    const lifecycleSettled = record.phase === "idle" && record.journal.some((entry) => entry.event === "disconnected" || entry.event === "server-copy-removed");
    if (!lifecycleSettled && record.phase !== "ready" && record.phase !== "needs-attention") {
      return this.applyRecord(await orchestrator.start());
    }
    return this.applyRecord(record);
  }

  close(): void {
    if (this.syncTimer) clearInterval(this.syncTimer);
    this.syncTimer = undefined;
  }

  async getState(): Promise<DesktopState> { return cloneState(this.state); }

  async selectVault(root: string): Promise<VaultSummary> {
    const scan = await this.scanner.scan(root, {});
    this.vaultRoot = root;
    const name = root.split(/[\\/]/u).filter(Boolean).at(-1) ?? "Vault";
    const summary = { name, noteCount: scan.files.length, bytes: scan.bytes };
    this.state = { ...this.state, mode: "onboarding", phase: "idle", vault: summary, attention: this.options.config ? null : this.state.attention };
    this.append("Vault scanned");
    this.publish();
    return summary;
  }

  async configureServer(input: ServerInput): Promise<ServerSummary> {
    const active = await this.stateStore.load();
    if (active && serverCopyDisposition(active) !== "none") throw new Error("disconnect_before_server_change");
    OpenSshAdapter.fromInput(input);
    this.serverInput = { ...input };
    const server = { label: displayServerLabel(input), host: input.host.trim(), user: input.user.trim(), port: input.port, connected: false };
    this.state = { ...this.state, server, attention: this.options.config ? null : this.state.attention };
    this.append("Server saved");
    this.publish();
    return server;
  }

  async getJournal(): Promise<JournalEntry[]> { return this.journal.map((entry) => ({ ...entry })); }
  async setStartAtLogin(_enabled: boolean): Promise<void> {}

  async connectChatGpt(): Promise<DesktopState> {
    if (!this.state.mcp) return this.fail("oauth-not-linked", "ChatGPT not connected", "connect");
    await this.options.browser?.openExternal("https://chatgpt.com/");
    this.append("ChatGPT opened");
    this.publish();
    return cloneState(this.state);
  }

  async connectOwner(): Promise<DesktopState> {
    if (!this.options.oauth) return this.fail("oauth-not-linked", "Owner sign-in unavailable", "connect");
    try {
      await this.options.oauth.connect();
      this.state = { ...this.state, attention: null };
      this.append("Owner connected");
      this.publish();
      return cloneState(this.state);
    } catch {
      return this.fail("oauth-not-linked", "Sign in to owner account", "connect");
    }
  }

  subscribe(listener: (state: DesktopState) => void): () => void { this.listeners.add(listener); return () => this.listeners.delete(listener); }

  async setup(): Promise<DesktopState> {
    if (this.setupPromise) return this.setupPromise;
    if (!this.vaultRoot || !this.state.vault) return this.fail("vault-missing", "Vault not found", "choose-vault");
    if (!this.serverInput || !this.state.server) return this.fail("ssh-failed", "Server not configured", "change-server");
    if (this.state.serverCopy === "retained" || this.state.serverCopy === "unknown") {
      return this.fail("deployment-failed", "Remove server copy first", "retry");
    }
    if (!this.options.config || !this.edge) return this.fail("oauth-not-linked", "Edge not configured", "connect");
    if (this.ownerTokens && !(await this.ownerTokens.getAccessToken())) return this.fail("oauth-not-linked", "Sign in to owner account", "connect");
    this.state = { ...this.state, mode: "synchronizing", phase: "preflight", attention: null };
    this.publish();
    this.setupPromise = this.runSetup().finally(() => { this.setupPromise = undefined; });
    return this.setupPromise;
  }

  async synchronize(): Promise<DesktopState> {
    if (!this.orchestrator) return this.setup();
    try { return this.applyRecord(await this.orchestrator.syncNow()); } catch { return cloneState(this.state); }
  }

  async setPaused(paused: boolean): Promise<DesktopState> {
    if (!this.orchestrator) {
      this.state = { ...this.state, paused, mode: paused ? "ready" : this.state.mode };
      this.publish();
      return cloneState(this.state);
    }
    return this.applyRecord(await (paused ? this.orchestrator.pauseSync() : this.orchestrator.resumeSync()));
  }

  async update(): Promise<DesktopState> {
    if (!this.deployment) return this.fail("deployment-failed", "Update unavailable", "retry");
    try { await this.deployment.updateCurrent(await this.orchestrator?.getInternalState() ?? undefined); this.append("Deployment updated"); return cloneState(this.state); } catch { return this.fail("deployment-failed", "Update failed", "retry"); }
  }

  async disconnect(): Promise<DesktopState> {
    if (!this.orchestrator) return cloneState(this.state);
    try {
      const record = await this.orchestrator.disconnect(true);
      if (!record) return cloneState(this.state);
      if (record.phase === "needs-attention" || serverCopyDisposition(record) !== "retained") {
        return this.applyRecord(record);
      }
      this.append("Disconnected");
      return this.applyRecord(record);
    } catch { return this.fail("deployment-failed", "Disconnect failed", "retry"); }
  }

  async removeServerCopy(): Promise<DesktopState> {
    if (!this.orchestrator) return cloneState(this.state);
    try {
      const record = await this.orchestrator.removeServerCopy();
      if (!record) return cloneState(this.state);
      if (record.phase === "needs-attention" || serverCopyDisposition(record) !== "none") {
        return this.applyRecord(record);
      }
      this.append("Server copy removed");
      return this.applyRecord(record);
    } catch { return this.fail("deployment-failed", "Removal failed", "retry"); }
  }

  private async runSetup(): Promise<DesktopState> {
    const config = this.options.config;
    if (!config || !this.edge || !this.serverInput || !this.vaultRoot) return this.fail("oauth-not-linked", "Edge not configured", "connect");
    const orchestrator = await this.ensureOrchestrator();
    const input: SetupInput = { vault: { vaultId: normalizeVaultId(this.state.vault?.name ?? "local-vault"), label: this.state.vault?.name ?? "Vault", root: this.vaultRoot }, server: { host: this.serverInput.host, user: this.serverInput.user, port: this.serverInput.port } };
    return this.applyRecord(await orchestrator.start(input));
  }

  private async ensureOrchestrator(): Promise<SetupOrchestrator> {
    if (this.orchestrator) return this.orchestrator;
    const config = this.options.config;
    if (!config || !this.edge || !this.serverInput || !this.vaultRoot) throw new Error("desktop_runtime_not_configured");
    const ssh = this.options.ssh ?? new OpenSshAdapter(undefined, join(this.options.appDataPath, "ssh", "known_hosts"));
    const pins = this.options.pins ?? new FileHostKeyPinStore(join(this.options.appDataPath, "ssh", "pins.json"));
    const confirmation = this.options.confirmation ?? { confirm: async () => false };
    const sftp = this.options.sftp ?? new OpenSftpAdapter(undefined, join(this.options.appDataPath, "ssh", "known_hosts"));
    const uploader = async (server: ServerSelection): Promise<SecretUploader> => {
      const candidate = OpenSshAdapter.fromInput({ host: server.host, user: server.user, port: server.port ?? 22, ...(server.hostKeyFingerprint ? { hostKeyFingerprint: server.hostKeyFingerprint } : {}) });
      const target = await ssh.ensurePinned(candidate, pins, (fingerprint) => confirmation.confirm(fingerprint, candidate));
      return sftp.withTarget(target);
    };
    const tlsProvider: PublisherTlsCredentialProvider = {
      get: async () => {
        const value = await this.secrets.get(PUBLISHER_TLS_SECRET);
        if (!value) return undefined;
        try {
          const parsed: unknown = JSON.parse(value);
          if (!parsed || typeof parsed !== "object") return undefined;
          const record = parsed as Record<string, unknown>;
          return typeof record.certificate === "string" && typeof record.privateKey === "string" ? { certificate: record.certificate, privateKey: record.privateKey, ...(typeof record.caCertificate === "string" ? { caCertificate: record.caCertificate } : {}) } : undefined;
        } catch { return undefined; }
      }
    };
    const credentials = new ElectronCredentialStore(this.secrets);
    const deployment = new ProductDeploymentAdapter({ config, ssh, sftp, pins, confirmation, appDataPath: this.options.appDataPath, now: () => this.options.now?.() ?? new Date() });
    const owner = new ProductOwnerEdgeAdapter({ edge: this.edge, secrets: this.secrets, uploader, appDataPath: this.options.appDataPath, directoryFor: (server, id) => deployment.directoryFor(server, id), ...(this.options.publisherIdentity ? { publisherIdentity: this.options.publisherIdentity } : {}) });
    const publisherRemote = new DesktopPublisherClient(Boolean(config.development), tlsProvider);
    const binder = this.options.deviceBinder ?? new HiddenDeviceBinder({ deployment, vaultId: normalizeVaultId(this.state.vault?.name ?? "local-vault"), credentials, remote: publisherRemote });
    const publisher = new ProductPublisherAdapter({
      ...(this.options.agent ? { agent: this.options.agent } : {}),
      agentFactory: () => AgentService.create({ mode: "production", dataDir: join(this.options.appDataPath, "agent"), scanner: this.scanner, credentials, remoteClient: new DynamicAgentRemoteClient(() => publisherRemote), publisherTlsCredentialProvider: tlsProvider }),
      credentials,
      scanner: this.scanner,
      remote: publisherRemote,
      binder
    });
    const orchestrator = new SetupOrchestrator({ stateStore: this.stateStore, vault: new VaultAdapter(this.scanner, () => this.options.now?.() ?? new Date()), edge: owner, deployment, publisher, endpoint: new EndpointAdapter(), journal: new BoundedJournal({ maxEntries: MAX_JOURNAL }) });
    this.orchestrator = orchestrator;
    this.deployment = deployment;
    const existing = await orchestrator.getInternalState();
    if (existing) deployment.setRecord(existing);
    return orchestrator;
  }

  private applyRecord(record: SetupRecord): DesktopState {
    const phase = record.phase === "needs-attention" ? (record.resumePhase ?? "idle") : record.phase;
    const copy = serverCopyDisposition(record);
    const mode = copy === "unknown" ? "attention" : record.phase === "ready" ? "ready" : record.phase === "needs-attention" ? "attention" : record.phase === "idle" ? "onboarding" : "synchronizing";
    const attention = record.attention
      ? { code: mapAttentionCode(record.attention.code), message: conciseAttention(record.attention.code), action: "retry" as const }
      : copy === "unknown"
        ? { code: "deployment-failed" as const, message: "Server copy status unknown", action: "retry" as const }
        : null;
    this.state = { ...this.state, mode, phase: phase as SetupPhase, paused: record.sync.paused, attention, serverCopy: copy, server: this.state.server ? { ...this.state.server, connected: record.phase === "ready" } : null, mcp: record.edge?.endpointBundle ? { host: record.edge.endpointBundle.mcpHost, resourceUrl: record.edge.endpointBundle.mcpResourceUrl } : null, lastPublishedAt: record.snapshot?.publishedAt ?? record.sync.last?.publishedAt ?? null };
    this.deployment?.setRecord(record);
    this.scheduleSync(record);
    this.publish();
    return cloneState(this.state);
  }

  private setAttention(code: NonNullable<DesktopState["attention"]>["code"], message: string, action: NonNullable<DesktopState["attention"]>["action"]): void { this.state = { ...this.state, mode: "attention", attention: { code, message, action } }; }
  private async fail(code: NonNullable<DesktopState["attention"]>["code"], message: string, action: NonNullable<DesktopState["attention"]>["action"]): Promise<DesktopState> { this.setAttention(code, message, action); this.append(message, "error"); this.publish(); return cloneState(this.state); }
  private append(message: string, level: JournalEntry["level"] = "info"): void { this.journal.push({ at: new Date().toISOString(), message: redact(message), level }); if (this.journal.length > MAX_JOURNAL) this.journal.splice(0, this.journal.length - MAX_JOURNAL); }
  private publish(): void { const snapshot = cloneState(this.state); for (const listener of this.listeners) listener(snapshot); }

  private scheduleSync(record: SetupRecord): void {
    if (this.syncTimer) clearInterval(this.syncTimer);
    this.syncTimer = undefined;
    if (!this.orchestrator || record.phase !== "ready" || record.sync.paused) return;
    const minutes = this.options.config?.syncIntervalMinutes ?? 5;
    this.syncTimer = setInterval(() => { void this.synchronize(); }, minutes * 60_000);
    this.syncTimer.unref();
  }
}

function requireBundle(edge: EdgeInstallation): EndpointBundle {
  if (!edge.endpointBundle) throw new Error("endpoint_bundle_missing");
  return edge.endpointBundle;
}

function parseMemory(output: string): number {
  const match = /Mem:\s+(\d+)/iu.exec(output);
  const value = Number(match?.[1] ?? 0);
  return Number.isFinite(value) && value > 0 ? value : 0;
}

function parseDisk(output: string): number {
  const fields = output.trim().split("\n").at(-1)?.trim().split(/\s+/u) ?? [];
  const value = Number(fields[3] ?? 0);
  return Number.isFinite(value) ? value * 1024 : 0;
}

function parseProjects(output: string): string[] {
  try {
    const value: unknown = JSON.parse(output);
    if (!Array.isArray(value)) return [];
    return value.flatMap((item) => {
      const name = item && typeof item === "object" ? (item as Record<string, unknown>).Name : undefined;
      return typeof name === "string" ? [name] : [];
    });
  } catch { return []; }
}

function serverKey(server: Pick<ServerSelection, "host" | "user" | "port">): string {
  return `${server.user}\n${server.host}\n${server.port ?? 22}`;
}

function cloneServerSelection(server: ServerSelection): ServerSelection {
  return {
    host: server.host,
    user: server.user,
    ...(server.port === undefined ? {} : { port: server.port }),
    ...(server.authRef === undefined ? {} : { authRef: server.authRef }),
    ...(server.hostKeyFingerprint === undefined ? {} : { hostKeyFingerprint: server.hostKeyFingerprint })
  };
}

/**
 * Resolve a configured directory as one installation-owned subtree.
 *
 * The configured value is treated as a base unless it already ends in the
 * opaque installation id.  This prevents a broad configured path from ever
 * becoming the target of a recursive remote removal.
 */
function installationScopedDirectory(base: string, installationId: string, remoteHome?: string): string {
  if (!INSTALLATION_ID_RE.test(installationId)) throw new Error("installation_id_invalid");
  const normalized = base.trim().replace(/\/+$/u, "") || "/";
  const parts = normalized.split("/").filter(Boolean);
  if (
    !normalized.startsWith("/") ||
    normalized.length > 2048 ||
    /[\0\r\n$`;&|<>]/u.test(normalized) ||
    parts.some((part) => part === "." || part === ".." || !/^[A-Za-z0-9._-]+$/u.test(part))
  ) {
    throw new Error("installation_directory_invalid");
  }
  const home = remoteHome?.replace(/\/+$/u, "") || undefined;
  const isUserHome = /^\/(?:home\/[^/]+|Users\/[^/]+)$/u.test(normalized) || normalized === "/root";
  if (BROAD_INSTALLATION_ROOTS.has(normalized) || isUserHome || (home !== undefined && normalized === home)) {
    throw new Error("installation_directory_invalid");
  }
  const candidate = parts.at(-1) === installationId ? normalized : `${normalized}/${installationId}`;
  const candidateParts = candidate.split("/").filter(Boolean);
  if (
    candidate === "/" ||
    candidateParts.at(-1) !== installationId ||
    candidateParts.some((part) => part === "." || part === "..") ||
    (home !== undefined && candidate === home)
  ) {
    throw new Error("installation_directory_invalid");
  }
  return candidate;
}

function composeHealthy(output: string): boolean {
  try {
    let value: unknown;
    try { value = JSON.parse(output); } catch { value = output.trim().split("\n").filter(Boolean).map((line) => JSON.parse(line) as unknown); }
    const records = Array.isArray(value) ? value : [value];
    const services = records.filter((item): item is Record<string, unknown> => Boolean(item && typeof item === "object"));
    if (services.length < 2) return false;
    return services.every((service) => {
      const state = String(service.State ?? service.state ?? "").toLowerCase();
      const health = String(service.Health ?? service.health ?? "").toLowerCase();
      return state.includes("running") && (health === "" || health.includes("healthy"));
    });
  } catch {
    return false;
  }
}

function mapAttentionCode(code: string): NonNullable<DesktopState["attention"]>["code"] {
  if (code === "vault_scan_incomplete") return "vault-missing";
  if (/host|fingerprint/iu.test(code)) return "host-key-changed";
  if (/docker|preflight/iu.test(code)) return "docker-unavailable";
  if (/capacity|disk|memory/iu.test(code)) return "capacity";
  if (/oauth|owner_auth/iu.test(code)) return "oauth-not-linked";
  if (/sync/iu.test(code)) return "sync-blocked";
  return "deployment-failed";
}

function conciseAttention(code: string): string {
  if (/oauth|owner_auth/iu.test(code)) return "Sign in to owner account";
  if (/host|fingerprint/iu.test(code)) return "Review server identity";
  if (/docker|preflight/iu.test(code)) return "Docker unavailable";
  if (/capacity|disk|memory/iu.test(code)) return "Server capacity is insufficient";
  if (/vault/iu.test(code)) return "Vault needs attention";
  return "Setup failed";
}

function redact(value: string): string {
  return value.replace(/(?:bearer\s+|token[=:]\s*|password[=:]\s*)[^\s,;]+/giu, "[redacted]").replace(/(?:\/Users\/|\/home\/|[A-Za-z]:\\)[^\s]*/gu, "[path]").slice(0, 240);
}

export { ElectronCredentialStore, ProductDeploymentAdapter, ProductOwnerEdgeAdapter, ProductPublisherAdapter, VaultAdapter, installationScopedDirectory };
