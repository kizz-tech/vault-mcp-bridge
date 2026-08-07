import { randomUUID } from "node:crypto";
import {
  errorCode,
  OrchestratorError,
  safeErrorMessage
} from "./errors.js";
import { BoundedJournal } from "./journal.js";
import { serverCopyDisposition, toInstallationState } from "./projection.js";
import type { InstallationState } from "./types.js";
import type {
  DeploymentPort,
  EndpointVerificationPort,
  JournalEntry,
  OperationContext,
  OwnerEdgePort,
  PublisherPort,
  ResumableSetupPhase,
  SetupInput,
  SetupRecord,
  SetupStateStore,
  VaultPreviewPort,
  DisconnectInput,
  ReplicaCleanupInput,
  ReplicaCleanupReceipt,
  OrchestratorOptions,
  RedactedJournal
} from "./types.js";

const MAX_TRANSITIONS_PER_RUN = 16;

type DisconnectOperation = "edge" | "publisher" | "deployment";

interface DisconnectAttempt {
  operation: DisconnectOperation;
  run: () => Promise<void>;
}

interface DisconnectFailure {
  operation: DisconnectOperation;
  error: unknown;
}

/**
 * Durable orchestration boundary for the desktop process.
 *
 * The adapters are intentionally narrow and receive deterministic idempotency
 * keys. A process crash before a commit leaves the previous phase on disk; a
 * retry therefore repeats the same adapter operation rather than skipping a
 * side effect.
 */
export class SetupOrchestrator {
  private readonly stateStore: SetupStateStore;
  private readonly vault: VaultPreviewPort;
  private readonly edge: OwnerEdgePort;
  private readonly deployment: DeploymentPort;
  private readonly publisher: PublisherPort;
  private readonly endpoint: EndpointVerificationPort;
  private readonly journal: RedactedJournal;
  private readonly now: () => Date;
  private readonly createId: () => string;
  private running: Promise<unknown> | undefined;

  constructor(options: OrchestratorOptions) {
    this.stateStore = options.stateStore;
    this.vault = options.vault;
    this.edge = options.edge;
    this.deployment = options.deployment;
    this.publisher = options.publisher;
    this.endpoint = options.endpoint;
    this.journal = options.journal ?? new BoundedJournal();
    this.now = options.now ?? (() => new Date());
    this.createId = options.createId ?? randomUUID;
  }

  /** Start a new installation or resume the durable one already on disk. */
  async start(input?: SetupInput): Promise<SetupRecord> {
    return this.exclusive(async () => {
      let record = await this.load();
      if (record === null) {
        if (input === undefined) throw new OrchestratorError("setup-input-required", "Vault and server are required");
        record = await this.create(input);
      } else if (serverCopyDisposition(record) === "retained" || serverCopyDisposition(record) === "unknown") {
        if (input !== undefined) {
          throw new OrchestratorError("server-copy-retained", "Remove the retained server copy before starting another setup", {
            retryable: false
          });
        }
        return record;
      } else if (isDisconnectedTombstone(record)) {
        if (input === undefined) return record;
        record = await this.create(input);
      }
      return this.advance(record, record.phase === "needs-attention");
    });
  }

  /** Explicit UI retry after a needs-attention state. */
  async resume(input?: SetupInput): Promise<SetupRecord> {
    return this.start(input);
  }

  async getState(): Promise<SetupRecord | null> {
    return this.load();
  }

  /** Explicit renderer-facing alias; it never exposes local paths or refs. */
  async getInstallationState(): Promise<InstallationState | null> {
    return this.getPublicState();
  }

  /** Explicit privileged/diagnostic alias for the durable internal record. */
  async getInternalState(): Promise<SetupRecord | null> {
    return this.getState();
  }

  async getPublicState(): Promise<InstallationState | null> {
    const record = await this.load();
    return record === null ? null : toInstallationState(record);
  }

  async getJournal(): Promise<readonly JournalEntry[]> {
    const record = await this.load();
    return record?.journal ?? [];
  }

  async pauseSync(): Promise<SetupRecord> {
    return this.exclusive(async () => {
      const record = await this.requireState();
      if (record.sync.paused) return record;
      this.journal.replace(record.journal);
      this.journal.append({ level: "info", event: "paused", detail: { phase: record.phase } });
      return this.commit({ ...record, sync: { ...record.sync, paused: true } });
    });
  }

  async resumeSync(): Promise<SetupRecord> {
    return this.exclusive(async () => {
      const record = await this.requireState();
      if (!record.sync.paused) return record;
      this.journal.replace(record.journal);
      this.journal.append({ level: "info", event: "resumed", detail: { phase: record.phase } });
      return this.commit({ ...record, sync: { ...record.sync, paused: false } });
    });
  }

  /**
   * Publish one current snapshot. Normal background scheduling can call this
   * method; it never uses SSH or changes setup stages.
   */
  async syncNow(): Promise<SetupRecord> {
    return this.exclusive(async () => {
      const record = await this.requireState();
      if (record.phase !== "ready") throw new OrchestratorError("not-ready", "Setup is not ready");
      if (record.sync.paused) throw new OrchestratorError("sync-paused", "Synchronization is paused");
      if (this.publisher.syncNow === undefined) throw new OrchestratorError("sync-unavailable", "Publisher does not support synchronization");
      this.journal.replace(record.journal);
      try {
        const receipt = await this.publisher.syncNow({
          ...this.context(record, "sync-" + String((record.sync.last?.generation ?? 0) + 1)),
          vault: record.request.vault,
          preview: this.required(record.preview, "preview"),
          device: this.required(record.device, "device"),
          edge: this.required(record.edge, "edge")
        });
        this.journal.append({
          level: "info",
          event: "vault-synchronized",
          detail: { generation: receipt.generation, documentCount: receipt.documentCount }
        });
        return this.commit({ ...record, sync: { ...record.sync, last: receipt } });
      } catch (error) {
        return this.fail(record, error, "ready");
      }
    });
  }

  /**
   * Revoke public access and remove only the installation's resources. The
   * local vault remains untouched. Replica deletion is an explicit argument.
   */
  async disconnect(keepReplica: boolean): Promise<SetupRecord | null> {
    return this.exclusive(async () => {
      const record = await this.load();
      if (record === null) return null;
      const disposition = serverCopyDisposition(record);
      if (disposition === "retained") {
        return keepReplica ? record : this.removeRetainedReplica(record);
      }
      if (disposition === "unknown") {
        throw new OrchestratorError("replica-cleanup-unavailable", "The retained server copy cannot be scoped safely", {
          retryable: false
        });
      }
      if (isDisconnectedTombstone(record)) return record;
      return this.disconnectActive(record, keepReplica);
    });
  }

  /** Delete a retained replica without replaying already-completed revocations. */
  async removeServerCopy(): Promise<SetupRecord | null> {
    return this.exclusive(async () => {
      const record = await this.load();
      if (record === null) return null;
      const disposition = serverCopyDisposition(record);
      if (disposition === "retained") return this.removeRetainedReplica(record);
      if (disposition === "unknown") {
        throw new OrchestratorError("replica-cleanup-unavailable", "The retained server copy cannot be scoped safely", {
          retryable: false
        });
      }
      if (disposition === "active") return this.disconnectActive(record, false);
      return record;
    });
  }

  private async disconnectActive(record: SetupRecord, keepReplica: boolean): Promise<SetupRecord> {
    const cleanup = keepReplica ? record.staged?.cleanup : undefined;
    if (keepReplica && cleanup === undefined) {
      throw new OrchestratorError("replica-cleanup-unavailable", "The server copy cannot be retained without an exact cleanup receipt", {
        retryable: false
      });
    }
    this.journal.replace(record.journal);
    const input: DisconnectInput = {
      ...this.context(record, "disconnect"),
      keepReplica,
      ...(record.staged?.projectName === undefined ? {} : { projectName: record.staged.projectName }),
      ...(record.staged?.resourceLabel === undefined ? {} : { resourceLabel: record.staged.resourceLabel })
    };

    // Disconnect is a security kill switch. One failed revoke must not
    // short-circuit the remaining adapters.
    const attempts: readonly DisconnectAttempt[] = [
      ...(this.edge.disconnect === undefined
        ? []
        : [{ operation: "edge" as const, run: () => this.edge.disconnect!(input) }]),
      ...(this.publisher.disconnect === undefined
        ? []
        : [{ operation: "publisher" as const, run: () => this.publisher.disconnect!(input) }]),
      ...(this.deployment.disconnect === undefined
        ? []
        : [{ operation: "deployment" as const, run: () => this.deployment.disconnect!(input) }])
    ];
    const failures: DisconnectFailure[] = [];
    for (const attempt of attempts) {
      try {
        await attempt.run();
      } catch (error) {
        failures.push({ operation: attempt.operation, error });
        this.journal.append({
          level: "error",
          event: "disconnect-failed",
          detail: { operation: attempt.operation, code: errorCode(error), retryable: true }
        });
      }
    }

    if (failures.length > 0) {
      const phase = record.phase === "needs-attention" ? record.resumePhase ?? "idle" : record.phase;
      const firstFailure = failures.at(0);
      if (firstFailure === undefined) throw new OrchestratorError("disconnect-failed", "Disconnect failed");
      return this.fail(record, firstFailure.error, phase, { retryable: true });
    }

    this.journal.append({ level: "info", event: "disconnected", detail: { keepReplica } });
    const retained = cleanup === undefined
      ? undefined
      : { ...clone(cleanup), retainedAt: this.now().toISOString() } satisfies ReplicaCleanupReceipt;
    return this.commit(clearRemoteState(record, retained));
  }

  private async removeRetainedReplica(record: SetupRecord): Promise<SetupRecord> {
    const receipt = record.replicaCleanup;
    if (receipt === undefined || this.deployment.removeReplica === undefined) {
      throw new OrchestratorError("replica-cleanup-unavailable", "Replica cleanup is unavailable", { retryable: false });
    }
    this.journal.replace(record.journal);
    const input: ReplicaCleanupInput = {
      setupId: record.setupId,
      installationId: record.installationId,
      idempotencyKey: `${record.setupId}:remove-replica`,
      request: record.request,
      receipt: clone(receipt)
    };
    try {
      await this.deployment.removeReplica(input);
      this.journal.append({ level: "info", event: "server-copy-removed" });
      return this.commit(clearRemoteState(record));
    } catch (error) {
      return this.fail(record, error, "idle", { retryable: true });
    }
  }

  private async create(input: SetupInput): Promise<SetupRecord> {
    this.journal.clear();
    const installationId = input.installationId ?? this.createId();
    const record: SetupRecord = {
      schemaVersion: 1,
      setupId: this.createId(),
      revision: 0,
      phase: "idle",
      installationId,
      request: {
        installationId,
        vault: clone(input.vault),
        server: clone(input.server)
      },
      serverCopy: "none",
      sync: { paused: false },
      journal: [],
      updatedAt: this.now().toISOString()
    };
    this.journal.append({ level: "info", event: "setup-created" });
    return this.commit(record);
  }

  private async advance(initial: SetupRecord, retryAttention: boolean): Promise<SetupRecord> {
    let record = initial;
    this.journal.replace(record.journal);
    for (let transition = 0; transition < MAX_TRANSITIONS_PER_RUN; transition += 1) {
      if (record.phase === "ready") return record;
      if (record.phase === "needs-attention") {
        const resumePhase = record.resumePhase;
        if (!retryAttention || resumePhase === undefined) return record;
        this.journal.append({ level: "info", event: "resumed", detail: { phase: resumePhase } });
        const resumed = clearAttention(record, resumePhase);
        record = await this.commit(resumed);
        retryAttention = false;
        continue;
      }
      record = await this.transition(record);
      if (record.phase === "needs-attention") return record;
    }
    throw new OrchestratorError("transition-limit", "Setup exceeded the transition limit", { retryable: false });
  }

  private async transition(record: SetupRecord): Promise<SetupRecord> {
    switch (record.phase) {
      case "idle":
        return this.transitionPreflight(record);
      case "preflight":
        return this.transitionStaged(record);
      case "staged":
        return this.transitionDeployed(record);
      case "deployed":
        return this.transitionDeviceBound(record);
      case "device-bound":
        return this.transitionFirstSnapshot(record);
      case "first-snapshot":
        return this.transitionEndpointVerified(record);
      case "endpoint-verified":
        this.journal.append({ level: "info", event: "ready", detail: { phase: record.phase } });
        return this.commit({ ...record, phase: "ready" });
      case "ready":
      case "needs-attention":
        return record;
    }
  }

  private async transitionPreflight(record: SetupRecord): Promise<SetupRecord> {
    this.journal.replace(record.journal);
    try {
      const preview = await this.vault.preview({
        ...this.context(record, "preview"),
        vault: record.request.vault
      });
      const preflight = await this.deployment.preflight({
        ...this.context(record, "preflight"),
        vault: record.request.vault,
        preview,
        server: record.request.server
      });
      this.journal.append({
        level: "info",
        event: "server-checked",
        detail: { phase: "preflight", host: record.request.server.host, status: preflight.dockerMode }
      });
      return this.commit({ ...record, phase: "preflight", preview, preflight });
    } catch (error) {
      return this.fail(record, error, "idle");
    }
  }

  private async transitionStaged(record: SetupRecord): Promise<SetupRecord> {
    this.journal.replace(record.journal);
    try {
      const edgeContext = this.context(record, "edge");
      const edge = await this.edge.install({
        ...edgeContext,
        server: record.request.server,
        preview: this.required(record.preview, "preview"),
        preflight: this.required(record.preflight, "preflight")
      });
      const staged = await this.deployment.stage({
        ...this.context(record, "stage"),
        server: record.request.server,
        preview: this.required(record.preview, "preview"),
        preflight: this.required(record.preflight, "preflight"),
        edge
      });
      this.journal.append({ level: "info", event: "deployment-staged", detail: { project: staged.projectName } });
      return this.commit({ ...record, phase: "staged", edge, staged, serverCopy: "active" });
    } catch (error) {
      return this.fail(record, error, "preflight");
    }
  }

  private async transitionDeployed(record: SetupRecord): Promise<SetupRecord> {
    this.journal.replace(record.journal);
    try {
      const deployment = await this.deployment.deploy({
        ...this.context(record, "deployed"),
        staged: this.required(record.staged, "staged"),
        edge: this.required(record.edge, "edge")
      });
      this.journal.append({ level: "info", event: "container-started", detail: { project: deployment.projectName } });
      return this.commit({ ...record, phase: "deployed", deployment });
    } catch (error) {
      return this.fail(record, error, "staged");
    }
  }

  private async transitionDeviceBound(record: SetupRecord): Promise<SetupRecord> {
    this.journal.replace(record.journal);
    try {
      const device = await this.publisher.bindDevice({
        ...this.context(record, "device-bind"),
        edge: this.required(record.edge, "edge"),
        deployment: this.required(record.deployment, "deployment")
      });
      this.journal.append({ level: "info", event: "device-bound", detail: { phase: "device-bound" } });
      return this.commit({ ...record, phase: "device-bound", device });
    } catch (error) {
      return this.fail(record, error, "deployed");
    }
  }

  private async transitionFirstSnapshot(record: SetupRecord): Promise<SetupRecord> {
    this.journal.replace(record.journal);
    try {
      const snapshot = await this.publisher.publishFirstSnapshot({
        ...this.context(record, "first-snapshot"),
        vault: record.request.vault,
        preview: this.required(record.preview, "preview"),
        device: this.required(record.device, "device"),
        edge: this.required(record.edge, "edge")
      });
      this.journal.append({
        level: "info",
        event: "vault-synchronized",
        detail: { generation: snapshot.generation, documentCount: snapshot.documentCount }
      });
      return this.commit({ ...record, phase: "first-snapshot", snapshot, sync: { ...record.sync, last: snapshot } });
    } catch (error) {
      return this.fail(record, error, "device-bound");
    }
  }

  private async transitionEndpointVerified(record: SetupRecord): Promise<SetupRecord> {
    this.journal.replace(record.journal);
    try {
      const edge = this.required(record.edge, "edge");
      const deployment = this.required(record.deployment, "deployment");
      const endpoint = await this.endpoint.verify({
        ...this.context(record, "endpoint-verify"),
        endpointUrl: edge.endpointUrl,
        deployment,
        edge
      });
      this.journal.append({ level: "info", event: "endpoint-verified", detail: { status: endpoint.mcp } });
      return this.commit({ ...record, phase: "endpoint-verified", endpoint });
    } catch (error) {
      return this.fail(record, error, "first-snapshot");
    }
  }

  private async load(): Promise<SetupRecord | null> {
    const record = await this.stateStore.load();
    if (record !== null) this.journal.replace(record.journal);
    return record;
  }

  private async requireState(): Promise<SetupRecord> {
    const record = await this.load();
    if (record === null) throw new OrchestratorError("setup-not-found", "Set up a vault and server first");
    return record;
  }

  private async commit(record: SetupRecord): Promise<SetupRecord> {
    const next: SetupRecord = {
      ...record,
      revision: record.revision + 1,
      journal: this.journal.entries(),
      updatedAt: this.now().toISOString()
    };
    await this.stateStore.save(next);
    return next;
  }

  private async fail(
    record: SetupRecord,
    error: unknown,
    phase: ResumableSetupPhase,
    options: { retryable?: boolean } = {}
  ): Promise<SetupRecord> {
    const retryable = options.retryable ?? (error instanceof OrchestratorError ? error.retryable : true);
    this.journal.append({
      level: "error",
      event: "failed",
      detail: { phase, code: errorCode(error), retryable }
    });
    const next: SetupRecord = {
      ...record,
      phase: "needs-attention",
      resumePhase: phase,
      attention: {
        code: errorCode(error),
        message: safeErrorMessage(error),
        phase,
        retryable,
        at: this.now().toISOString()
      }
    };
    return this.commit(next);
  }

  private context(record: SetupRecord, step: string): OperationContext {
    return {
      setupId: record.setupId,
      installationId: record.installationId,
      idempotencyKey: record.setupId + ":" + step,
      request: record.request,
      prior: record
    };
  }

  private required<T>(value: T | undefined, name: string): T {
    if (value === undefined) throw new OrchestratorError("invalid-state", "Missing " + name + " receipt", { retryable: false });
    return value;
  }

  private async exclusive<T>(operation: () => Promise<T>): Promise<T> {
    if (this.running !== undefined) return this.running as Promise<T>;
    const pending = operation();
    this.running = pending;
    try {
      return await pending;
    } finally {
      if (this.running === pending) this.running = undefined;
    }
  }
}

function isDisconnectedTombstone(record: SetupRecord): boolean {
  return (
    record.phase === "idle" &&
    record.resumePhase === undefined &&
    record.attention === undefined &&
    record.preview === undefined &&
    record.preflight === undefined &&
    record.edge === undefined &&
    record.staged === undefined &&
    record.deployment === undefined &&
    record.device === undefined &&
    record.snapshot === undefined &&
    record.endpoint === undefined &&
    record.journal.some((entry) => entry.event === "disconnected")
  );
}

function clone<T>(value: T): T {
  return structuredClone(value);
}

function clearAttention(record: SetupRecord, phase: ResumableSetupPhase): SetupRecord {
  const next = clone(record);
  next.phase = phase;
  delete next.attention;
  delete next.resumePhase;
  return next;
}

function clearRemoteState(record: SetupRecord, replicaCleanup?: ReplicaCleanupReceipt): SetupRecord {
  const next = clone(record);
  next.phase = "idle";
  next.serverCopy = replicaCleanup === undefined ? "none" : "retained";
  next.sync = { paused: false };
  delete next.preview;
  delete next.preflight;
  delete next.edge;
  delete next.staged;
  delete next.deployment;
  delete next.device;
  delete next.snapshot;
  delete next.endpoint;
  delete next.attention;
  delete next.resumePhase;
  if (replicaCleanup === undefined) delete next.replicaCleanup;
  else next.replicaCleanup = clone(replicaCleanup);
  return next;
}
