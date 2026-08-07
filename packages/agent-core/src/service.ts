import { createPublicKey, generateKeyPairSync } from "node:crypto";
import { resolve } from "node:path";
import { CONTRACT_VERSION, normalizeVaultId, sha256Base64Url, UploadReceiptSchema, type JournalEvent, type VaultPreviewReceipt } from "@vault-mcp-bridge/contracts";
import { JsonAgentStateStore, defaultAgentConfig, defaultAgentRuntime, DEFAULT_MAX_JOURNAL_ENTRIES } from "./persistence.js";
import { buildSnapshot, policyDigest, receiptMatches, safeErrorMessage, scanIsIncomplete, toPreview } from "./snapshot.js";
import { assertCredential } from "./transport.js";
import type {
  AgentConfig,
  AgentMode,
  AgentPreview,
  AgentServiceOptions,
  AgentState,
  AgentStatus,
  ConfigureInput,
  CredentialStore,
  DeviceIdentity,
  IdentityResult,
  PairResult,
  PreviewOptions,
  PublisherStatus,
  SyncResult
} from "./types.js";

type Operation = NonNullable<AgentStatus["operation"]>;

function clone<T>(value: T): T {
  return structuredClone(value);
}

function generateDeviceKeypair(): { privateKey: string; publicKey: string } {
  const keyPair = generateKeyPairSync("ed25519", {
    privateKeyEncoding: { format: "pem", type: "pkcs8" },
    publicKeyEncoding: { format: "pem", type: "spki" }
  });
  const publicKey = createPublicKey(keyPair.publicKey).export({ format: "der", type: "spki" }).toString("base64url");
  return { privateKey: keyPair.privateKey, publicKey };
}

function identityPublic(identity?: DeviceIdentity): DeviceIdentity | undefined {
  return identity ? clone(identity) : undefined;
}

function validInterval(value: number): boolean {
  return Number.isInteger(value) && value >= 0 && value <= 1440;
}

function loopbackHost(host: string): boolean {
  const normalized = host.replace(/^\[/u, "").replace(/\]$/u, "").toLowerCase();
  return normalized === "localhost" || normalized === "127.0.0.1" || normalized === "::1";
}

function validateRemoteUrl(value: string, mode: AgentMode): void {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error("remote_server_invalid");
  }
  if (url.username || url.password) throw new Error("remote_server_credentials_forbidden");
  if (url.protocol === "https:") return;
  if (mode === "development" && url.protocol === "http:" && loopbackHost(url.hostname)) return;
  throw new Error("remote_server_https_required");
}

function installId(config: AgentConfig): string {
  const candidate = config.agentId || config.vaultId || "local-agent";
  try {
    return normalizeVaultId(candidate);
  } catch {
    return normalizeVaultId("local-agent");
  }
}

function redactedStatus(status: PublisherStatus): PublisherStatus {
  return {
    ok: status.ok,
    checkedAt: status.checkedAt,
    ...(status.vaultId ? { vaultId: status.vaultId } : {}),
    ...(status.generation !== undefined ? { generation: status.generation } : {}),
    ...(status.snapshotId ? { snapshotId: status.snapshotId } : {}),
    ...(status.freshnessSeconds !== undefined ? { freshnessSeconds: status.freshnessSeconds } : {}),
    ...(status.message ? { message: safeErrorMessage(status.message) } : {})
  };
}

function isKeychainCredentialStore(credentials: CredentialStore): boolean {
  return credentials.kind === "keychain";
}

function mergeConfig(base: AgentConfig, input: ConfigureInput): AgentConfig {
  const next: AgentConfig = {
    ...base,
    ...(input.vaultRoot !== undefined ? { vaultRoot: input.vaultRoot } : {}),
    ...(input.include !== undefined ? { include: [...input.include] } : {}),
    ...(input.exclude !== undefined ? { exclude: [...input.exclude] } : {}),
    ...(input.remoteServerUrl !== undefined ? { remoteServerUrl: input.remoteServerUrl } : {}),
    ...(input.vaultId !== undefined ? { vaultId: input.vaultId } : {}),
    ...(input.syncIntervalMinutes !== undefined ? { syncIntervalMinutes: input.syncIntervalMinutes } : {}),
    ...(input.agentId !== undefined ? { agentId: input.agentId } : {}),
    ...(input.label !== undefined ? { label: input.label } : {})
  };
  if (!next.include.length || next.include.some((pattern) => pattern.length === 0 || pattern.length > 1024)) throw new Error("include_invalid");
  if (next.exclude.some((pattern) => pattern.length === 0 || pattern.length > 1024)) throw new Error("exclude_invalid");
  if (!validInterval(next.syncIntervalMinutes)) throw new Error("sync_interval_invalid");
  if (next.vaultRoot !== undefined && next.vaultRoot.trim().length === 0) throw new Error("vault_root_invalid");
  if (next.remoteServerUrl !== undefined && next.remoteServerUrl.trim().length === 0) throw new Error("remote_server_invalid");
  if (next.vaultId !== undefined) normalizeVaultId(next.vaultId);
  return next;
}

function completePreview(preview: AgentPreview, config: AgentConfig): boolean {
  return !preview.incomplete && preview.policyDigest === policyDigest(config) && preview.receipt.vaultId === normalizeVaultId(config.vaultId ?? "local-vault");
}

export class AgentService {
  private readonly now: () => Date;
  private readonly mode: AgentMode;
  private readonly credentials: CredentialStore;
  private readonly scanner: AgentServiceOptions["scanner"];
  private readonly remoteClient: AgentServiceOptions["remoteClient"];
  private readonly stateStore: NonNullable<AgentServiceOptions["stateStore"]>;
  private readonly maxJournalEntries: number;
  private state: AgentState;
  private operation?: Operation;
  private syncTimer?: NodeJS.Timeout;

  private constructor(options: AgentServiceOptions, state: AgentState) {
    this.now = options.now ?? (() => new Date());
    this.mode = options.mode ?? "development";
    this.credentials = options.credentials;
    this.scanner = options.scanner;
    this.remoteClient = options.remoteClient;
    this.stateStore = options.stateStore ?? new JsonAgentStateStore(options.dataDir ?? "./.data/agent-core", this.now);
    this.maxJournalEntries = Math.max(10, Math.min(options.maxJournalEntries ?? DEFAULT_MAX_JOURNAL_ENTRIES, 500));
    this.state = state;
  }

  static async create(options: AgentServiceOptions): Promise<AgentService> {
    const now = options.now ?? (() => new Date());
    const mode = options.mode ?? "development";
    if (mode === "production" && !isKeychainCredentialStore(options.credentials)) throw new Error("production_credential_store_required");
    if (mode === "production") {
      if (!options.publisherTlsCredentialProvider) throw new Error("publisher_mtls_credentials_required");
      const tls = await options.publisherTlsCredentialProvider.get();
      if (!tls) throw new Error("publisher_mtls_credentials_required");
      assertCredential(tls);
    }
    const stateStore = options.stateStore ?? new JsonAgentStateStore(options.dataDir ?? "./.data/agent-core", now);
    const stored = await stateStore.load();
    const config = stored.config ? mergeConfig(defaultAgentConfig(), stored.config) : defaultAgentConfig();
    if (config.remoteServerUrl) validateRemoteUrl(config.remoteServerUrl, mode);
    const runtime = stored.runtime ?? defaultAgentRuntime(now());
    if (runtime.phase === "synchronizing") runtime.phase = "needs-attention";
    const pairing = stored.pairing ?? runtime.pairing ?? { paired: false };
    runtime.pairing = pairing;
    const identity = stored.identity ?? await options.credentials.identity?.();
    const service = new AgentService({ ...options, stateStore }, { config, runtime, pairing, ...(identity ? { identity } : {}) });
    service.schedule();
    return service;
  }

  /** Privileged main-process state; includes the local vaultRoot and never belongs in renderer/public status. */
  getState(): Readonly<AgentState> {
    return clone(this.state);
  }

  getStatus(): AgentStatus {
    const { config, runtime, pairing } = this.state;
    const productStatus = runtime.paused
      ? "paused"
      : runtime.phase === "synchronizing"
        ? "synchronizing"
        : runtime.phase === "ready"
          ? "ready"
          : runtime.phase === "needs-attention"
            ? "needs-attention"
            : "idle";
    return {
      readOnly: true,
      mode: this.mode,
      phase: runtime.paused ? "paused" : runtime.phase,
      productStatus,
      paused: runtime.paused,
      configured: Boolean(config.vaultRoot && config.remoteServerUrl && config.vaultId),
      vaultConfigured: Boolean(config.vaultRoot),
      remoteConfigured: Boolean(config.remoteServerUrl),
      pairingConfigured: pairing.paired,
      credentialStore: this.credentials.kind,
      ...(config.vaultId ? { vaultId: config.vaultId } : {}),
      ...(runtime.lastPreview ? { preview: clone(runtime.lastPreview) } : {}),
      ...(runtime.lastScanAt ? { lastScanAt: runtime.lastScanAt } : {}),
      ...(runtime.lastUploadAt ? { lastUploadAt: runtime.lastUploadAt } : {}),
      ...(runtime.lastReceipt !== undefined ? { lastReceipt: clone(runtime.lastReceipt) } : {}),
      ...(runtime.lastPublisherStatus ? { lastPublisherStatus: clone(runtime.lastPublisherStatus) } : {}),
      ...(runtime.lastError ? { lastError: runtime.lastError } : {}),
      ...(this.operation ? { operation: this.operation } : {})
    };
  }

  getJournal(): JournalEvent[] {
    return clone(this.state.runtime.journal);
  }

  getIdentity(): DeviceIdentity | undefined {
    return identityPublic(this.state.identity);
  }

  getConfig(): AgentConfig {
    return clone(this.state.config);
  }

  async configure(input: ConfigureInput): Promise<AgentStatus> {
    return this.run("configure", async () => {
      const previousPolicy = policyDigest(this.state.config);
      const previousRemote = this.state.config.remoteServerUrl;
      const previousVaultId = this.state.config.vaultId;
      const next = mergeConfig(this.state.config, input);
      if (next.remoteServerUrl) validateRemoteUrl(next.remoteServerUrl, this.mode);
      this.state.config = next;
      if (previousRemote !== next.remoteServerUrl || previousVaultId !== next.vaultId) {
        this.state.pairing = { paired: false };
        this.state.runtime.pairing = this.state.pairing;
      }
      if (previousPolicy !== policyDigest(next) || previousRemote !== next.remoteServerUrl || previousVaultId !== next.vaultId) {
        delete this.state.runtime.lastPreview;
        if (!this.state.runtime.paused) this.state.runtime.phase = next.vaultRoot ? "vault-selected" : "idle";
      }
      await this.persist();
      this.schedule();
      return this.getStatus();
    });
  }

  async preview(options: PreviewOptions = {}): Promise<AgentPreview> {
    return this.run("preview", async () => {
      if (!this.state.config.vaultRoot) throw new Error("vault_root_required");
      try {
        const scan = await this.scanner.scan(resolve(this.state.config.vaultRoot), {
          include: [...this.state.config.include],
          exclude: [...this.state.config.exclude],
          ...(this.state.config.vaultId ? { vaultId: normalizeVaultId(this.state.config.vaultId) } : {})
        });
        const preview = toPreview(scan, this.state.config, this.now(), options.accept === true);
        this.state.runtime.lastPreview = preview;
        this.state.runtime.lastScanAt = preview.receipt.scannedAt;
        this.state.runtime.phase = preview.incomplete ? "needs-attention" : "preview-ready";
        delete this.state.runtime.lastError;
        await this.persist();
        return clone(preview);
      } catch (error) {
        await this.fail(error);
        throw error;
      }
    });
  }

  async acceptPreview(receipt?: VaultPreviewReceipt): Promise<AgentPreview> {
    return this.run("preview", async () => {
      const preview = this.state.runtime.lastPreview;
      if (!preview || !completePreview(preview, this.state.config)) throw new Error("preview_required");
      if (receipt && JSON.stringify(receipt) !== JSON.stringify(preview.receipt)) throw new Error("preview_receipt_mismatch");
      preview.accepted = true;
      this.state.runtime.lastPreview = preview;
      this.state.runtime.phase = "preview-ready";
      await this.persist();
      return clone(preview);
    });
  }

  async generateIdentity(options: { rotate?: boolean } = {}): Promise<IdentityResult> {
    return this.run("identity", async () => {
      if (this.mode === "production" && !isKeychainCredentialStore(this.credentials)) throw new Error("production_credential_store_required");
      if (this.state.identity && options.rotate !== true) throw new Error("device_identity_exists");
      if (!this.credentials.saveIdentity) throw new Error("credential_store_identity_unsupported");
      const keys = generateDeviceKeypair();
      const createdAt = this.now().toISOString();
      await this.credentials.saveIdentity(keys.privateKey, keys.publicKey, createdAt);
      this.state.identity = { publicKey: keys.publicKey, keyAlgorithm: "ed25519", createdAt };
      this.state.config.agentId = sha256Base64Url(keys.publicKey).slice(0, 32);
      this.state.pairing = { paired: false };
      this.state.runtime.pairing = this.state.pairing;
      if (options.rotate === true) delete this.state.runtime.lastPreview;
      this.state.runtime.phase = this.state.config.vaultRoot ? "vault-selected" : "idle";
      delete this.state.runtime.lastError;
      await this.persist();
      return { identity: identityPublic(this.state.identity)!, credentialStore: this.credentials.kind };
    });
  }

  async pair(code: string): Promise<PairResult> {
    return this.run("pair", async () => {
      const pairCode = code.trim();
      if (!pairCode || pairCode.length > 128) throw new Error("pairing_code_required");
      if (!this.state.config.remoteServerUrl) throw new Error("remote_server_required");
      if (!this.state.identity || !this.state.config.agentId) throw new Error("device_identity_required");
      if (!(await this.credentials.getPrivateKey())) throw new Error("device_identity_required");
      try {
        const response = await this.remoteClient.pair({
          url: this.state.config.remoteServerUrl,
          code: pairCode,
          agentId: this.state.config.agentId,
          publicKey: this.state.identity.publicKey,
          ...(this.state.config.vaultId ? { vaultId: normalizeVaultId(this.state.config.vaultId) } : {}),
          ...(this.state.config.label ? { label: this.state.config.label } : {})
        });
        this.state.pairing = { paired: true, deviceId: response.deviceId, publicKey: this.state.identity.publicKey, pairedAt: this.now().toISOString() };
        this.state.runtime.pairing = this.state.pairing;
        if (response.vaultId) this.state.config.vaultId = normalizeVaultId(response.vaultId);
        this.state.runtime.phase = "device-bound";
        delete this.state.runtime.lastError;
        this.appendJournal("device-bound");
        await this.persist();
        return { pairing: clone(this.state.pairing), ...(response.receipt !== undefined ? { receipt: clone(response.receipt) } : {}) };
      } catch (error) {
        await this.fail(error);
        throw error;
      }
    });
  }

  async publisherStatus(): Promise<PublisherStatus> {
    return this.run("status", async () => {
      if (!this.state.config.remoteServerUrl || !this.state.config.vaultId) throw new Error("remote_and_id_required");
      if (!this.state.pairing.deviceId) throw new Error("device_identity_required");
      const privateKey = await this.credentials.getPrivateKey();
      if (!privateKey) throw new Error("device_identity_required");
      try {
        const status = redactedStatus(await this.remoteClient.status({ url: this.state.config.remoteServerUrl, deviceId: this.state.pairing.deviceId, vaultId: normalizeVaultId(this.state.config.vaultId), privateKey }));
        this.state.runtime.lastPublisherStatus = status;
        delete this.state.runtime.lastError;
        await this.persist();
        return clone(status);
      } catch (error) {
        await this.fail(error);
        throw error;
      }
    });
  }

  async syncNow(): Promise<SyncResult> {
    return this.run("sync", async () => {
      if (this.state.runtime.paused) throw new Error("sync_paused");
      if (!this.state.config.vaultRoot || !this.state.config.remoteServerUrl || !this.state.config.vaultId) throw new Error("vault_remote_and_id_required");
      const currentPreview = this.state.runtime.lastPreview;
      if (!currentPreview || !currentPreview.accepted || !completePreview(currentPreview, this.state.config)) throw new Error("preview_required");
      if (!this.state.identity || !this.state.pairing.deviceId) throw new Error("device_identity_required");
      const privateKey = await this.credentials.getPrivateKey();
      if (!privateKey) throw new Error("device_identity_required");
      this.state.runtime.phase = "synchronizing";
      await this.persist();
      try {
        const vaultId = normalizeVaultId(this.state.config.vaultId);
        const publisherStatus = redactedStatus(await this.remoteClient.status({ url: this.state.config.remoteServerUrl, deviceId: this.state.pairing.deviceId, vaultId, privateKey }));
        this.state.runtime.lastPublisherStatus = publisherStatus;
        if (publisherStatus.vaultId && publisherStatus.vaultId !== vaultId) throw new Error("publisher_status_mismatch");
        const scan = await this.scanner.scan(resolve(this.state.config.vaultRoot), { include: [...this.state.config.include], exclude: [...this.state.config.exclude], vaultId });
        const preview = toPreview(scan, this.state.config, this.now(), true);
        this.state.runtime.lastPreview = preview;
        this.state.runtime.lastScanAt = preview.receipt.scannedAt;
        if (scanIsIncomplete(scan)) throw new Error("scan_incomplete");
        const previous = this.state.runtime.lastReceipt && typeof this.state.runtime.lastReceipt === "object" ? this.state.runtime.lastReceipt as Record<string, unknown> : {};
        const previousGeneration = Math.max(previous.vaultId === vaultId ? Number(previous.generation ?? 0) : 0, publisherStatus.generation ?? 0);
        const payload = buildSnapshot(scan, vaultId, previousGeneration + 1, this.now().toISOString());
        const receipt = await this.remoteClient.upload({ url: this.state.config.remoteServerUrl, deviceId: this.state.pairing.deviceId, vaultId, snapshot: payload, privateKey });
        if (!receiptMatches(receipt, payload, vaultId)) throw new Error("receipt_mismatch");
        const safeReceipt = UploadReceiptSchema.parse(receipt);
        this.state.runtime.lastUploadAt = this.now().toISOString();
        this.state.runtime.lastReceipt = safeReceipt;
        this.state.runtime.phase = "ready";
        delete this.state.runtime.lastError;
        this.appendJournal("vault-synchronized");
        await this.persist();
        return { receipt: clone(safeReceipt), preview: clone(preview), snapshotId: payload.snapshotId };
      } catch (error) {
        await this.fail(error);
        throw error;
      }
    });
  }

  async setPaused(paused: boolean): Promise<AgentStatus> {
    return this.run("configure", async () => {
      this.state.runtime.paused = paused;
      this.state.runtime.phase = paused ? "paused" : this.state.runtime.lastReceipt ? "ready" : this.state.config.vaultRoot ? "vault-selected" : "idle";
      this.appendJournal(paused ? "paused" : "resumed");
      await this.persist();
      this.schedule();
      return this.getStatus();
    });
  }

  async disconnect(): Promise<AgentStatus> {
    return this.run("configure", async () => {
      this.state.pairing = { paired: false };
      this.state.runtime.pairing = this.state.pairing;
      delete this.state.runtime.lastPreview;
      this.state.runtime.phase = this.state.config.vaultRoot ? "vault-selected" : "idle";
      await this.persist();
      return this.getStatus();
    });
  }

  async close(): Promise<void> {
    if (this.syncTimer) clearInterval(this.syncTimer);
    delete this.syncTimer;
  }

  private async run<T>(operation: Operation, callback: () => Promise<T>): Promise<T> {
    if (this.operation) throw new Error("operation_in_progress");
    this.operation = operation;
    try {
      return await callback();
    } finally {
      delete this.operation;
    }
  }

  private async persist(): Promise<void> {
    await this.stateStore.save({ config: this.state.config, runtime: this.state.runtime, pairing: this.state.pairing, ...(this.state.identity ? { identity: this.state.identity } : {}) });
  }

  private appendJournal(code: JournalEvent["code"]): void {
    const entry: JournalEvent = { at: this.now().toISOString(), code, installationId: installId(this.state.config) };
    this.state.runtime.journal = [...this.state.runtime.journal, entry].slice(-this.maxJournalEntries);
  }

  private async fail(error: unknown): Promise<void> {
    const message = safeErrorMessage(error);
    this.state.runtime.lastError = message;
    this.state.runtime.phase = this.state.runtime.paused ? "paused" : "needs-attention";
    this.appendJournal("failed");
    await this.persist().catch(() => undefined);
  }

  private schedule(): void {
    if (this.syncTimer) clearInterval(this.syncTimer);
    delete this.syncTimer;
    const minutes = Number(this.state.config.syncIntervalMinutes || 0);
    if (this.state.runtime.paused || minutes <= 0) return;
    const timer = setInterval(() => {
      void this.syncNow().catch(() => undefined);
    }, minutes * 60_000);
    timer.unref();
    this.syncTimer = timer;
  }
}

export async function createAgentService(options: AgentServiceOptions): Promise<AgentService> {
  return AgentService.create(options);
}

export { generateDeviceKeypair, CONTRACT_VERSION };
