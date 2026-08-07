import type { EndpointBundle, InstallationState, SetupStage, VaultPreviewReceipt } from "@vault-mcp-bridge/contracts";

/**
 * The orchestrator deliberately owns only metadata.  Secret material (SSH
 * credentials, tunnel tokens, publisher certificates, and private keys) is
 * exchanged through the injected adapters and a platform keychain.  It is not
 * represented by any persisted type in this package.
 */

export const SETUP_PHASES = [
  "idle",
  "preflight",
  "staged",
  "deployed",
  "device-bound",
  "first-snapshot",
  "endpoint-verified",
  "ready",
  "needs-attention"
] as const;

export type SetupPhase = (typeof SETUP_PHASES)[number];
export type ResumableSetupPhase = SetupStage;
export type { EndpointBundle, InstallationState, SetupStage, VaultPreviewReceipt };

export const SERVER_COPY_DISPOSITIONS = ["none", "active", "retained", "unknown"] as const;
export type ServerCopyDisposition = (typeof SERVER_COPY_DISPOSITIONS)[number];

export const JOURNAL_LEVELS = ["info", "warn", "error"] as const;
export type JournalLevel = (typeof JOURNAL_LEVELS)[number];

export interface VaultSelection {
  vaultId: string;
  label: string;
  /** The local canonical source. It is never sent to a remote adapter. */
  root: string;
  include?: readonly string[];
  exclude?: readonly string[];
}

export interface ServerSelection {
  host: string;
  user: string;
  port?: number;
  /** A keychain/SSH-agent reference, never private key material. */
  authRef?: string;
  /** A previously accepted host-key fingerprint. */
  hostKeyFingerprint?: string;
}

export interface SetupInput {
  /** An installation id can be restored by the desktop shell; otherwise one is generated. */
  installationId?: string;
  vault: VaultSelection;
  server: ServerSelection;
}

export interface PersistedSetupInput {
  installationId: string;
  vault: VaultSelection;
  server: ServerSelection;
}

export interface VaultPreview {
  vaultId: string;
  label: string;
  noteCount: number;
  byteCount: number;
  /** Hash of the selected projection, if the scanner can provide it. */
  projectionDigest?: string;
  includedCount?: number;
  excludedCount?: number;
  /** Optional canonical receipt from @vault-mcp-bridge/contracts. */
  receipt?: VaultPreviewReceipt;
}

export interface DeploymentPreflight {
  os: string;
  architecture: string;
  dockerMode: "rootless" | "rootful" | "unavailable";
  composeVersion?: string;
  availableBytes?: number;
  availableMemoryBytes?: number;
  availableCpuCount?: number;
}

export interface EdgeInstallation {
  installationRef: string;
  endpointUrl: string;
  oauthIssuerUrl?: string;
  provider: string;
  /** The managed-edge public bundle is a reference-only object. */
  endpointBundle?: EndpointBundle;
}

export interface StagedDeployment {
  projectName: string;
  release: string;
  /** Resource labels are useful for exact-scope lifecycle operations. */
  resourceLabel: string;
  /** Exact remote scope captured before the active installation is cleared. */
  cleanup?: ReplicaCleanupReceipt;
}

/**
 * Durable, cleanup-only authority for a retained server replica.
 *
 * This is intentionally separate from the active edge/publisher receipts. It
 * contains only exact identifiers needed to inspect and remove this
 * installation's Docker resources after a process restart; it is never a
 * license to revoke public access or to discover broad remote state.
 */
export interface ReplicaCleanupReceipt {
  /** Optional-field compatible receipt version; currently the only version. */
  schemaVersion: 1;
  installationId: string;
  server: ServerSelection;
  projectName: string;
  resourceLabel: string;
  installationDirectory: string;
  composePath: string;
  volumes: {
    replica: string;
    /** Exact named volume formerly owned by the server secret-init job. */
    serverRuntime: string;
    /** Exact named volume formerly owned by the tunnel secret-init job. */
    tunnelRuntime: string;
  };
  retainedAt?: string;
}

export interface DeployedService {
  projectName: string;
  release: string;
  health: "healthy";
  startedAt: string;
}

export interface DeviceBinding {
  deviceId: string;
  publisherCredentialRef: string;
}

export interface SnapshotReceipt {
  snapshotId: string;
  generation: number;
  documentCount: number;
  digest: string;
  publishedAt: string;
}

export interface EndpointVerification {
  endpointUrl: string;
  mcp: "ok";
  oauth: "ok";
  verifiedAt: string;
}

export interface SyncReceipt {
  generation: number;
  documentCount: number;
  digest: string;
  publishedAt: string;
}

export interface SyncState {
  paused: boolean;
  last?: SyncReceipt;
}

export interface JournalEntry {
  at: string;
  level: JournalLevel;
  event: string;
  detail?: Readonly<Record<string, string | number | boolean>>;
}

export interface AttentionState {
  code: string;
  message: string;
  phase: ResumableSetupPhase;
  retryable: boolean;
  at: string;
}

export interface SetupRecord {
  schemaVersion: 1;
  setupId: string;
  revision: number;
  phase: SetupPhase;
  /** The phase to return to after a needs-attention record is retried. */
  resumePhase?: ResumableSetupPhase;
  installationId: string;
  request: PersistedSetupInput;
  /** Explicit for new records; older prerelease records are derived fail-closed. */
  serverCopy?: ServerCopyDisposition;
  /** Present only while a server-side replica remains for cleanup. */
  replicaCleanup?: ReplicaCleanupReceipt;
  preview?: VaultPreview;
  preflight?: DeploymentPreflight;
  edge?: EdgeInstallation;
  staged?: StagedDeployment;
  deployment?: DeployedService;
  device?: DeviceBinding;
  snapshot?: SnapshotReceipt;
  endpoint?: EndpointVerification;
  sync: SyncState;
  attention?: AttentionState;
  journal: readonly JournalEntry[];
  updatedAt: string;
}

export type PublicInstallationState = InstallationState;

export interface OperationContext {
  setupId: string;
  installationId: string;
  idempotencyKey: string;
  request: PersistedSetupInput;
  prior: SetupRecord;
}

export interface VaultPreviewInput extends OperationContext {
  vault: VaultSelection;
}

export interface DeploymentPreflightInput extends OperationContext {
  vault: VaultSelection;
  preview: VaultPreview;
  server: ServerSelection;
}

export interface EdgeInstallInput extends OperationContext {
  server: ServerSelection;
  preview: VaultPreview;
  preflight: DeploymentPreflight;
}

export interface DeploymentStageInput extends OperationContext {
  server: ServerSelection;
  preview: VaultPreview;
  preflight: DeploymentPreflight;
  edge: EdgeInstallation;
}

export interface DeploymentDeployInput extends OperationContext {
  staged: StagedDeployment;
  edge: EdgeInstallation;
}

export interface DeviceBindInput extends OperationContext {
  edge: EdgeInstallation;
  deployment: DeployedService;
}

export interface FirstSnapshotInput extends OperationContext {
  vault: VaultSelection;
  preview: VaultPreview;
  device: DeviceBinding;
  edge: EdgeInstallation;
}

export interface EndpointVerifyInput extends OperationContext {
  endpointUrl: string;
  deployment: DeployedService;
  edge: EdgeInstallation;
}

export interface SyncInput extends OperationContext {
  vault: VaultSelection;
  preview: VaultPreview;
  device: DeviceBinding;
  edge: EdgeInstallation;
}

export interface DisconnectInput extends OperationContext {
  keepReplica: boolean;
  projectName?: string;
  resourceLabel?: string;
}

/** Cleanup-only operation. It deliberately carries no active edge/publisher receipts. */
export interface ReplicaCleanupInput {
  setupId: string;
  installationId: string;
  idempotencyKey: string;
  request: PersistedSetupInput;
  receipt: ReplicaCleanupReceipt;
}

export interface VaultPreviewPort {
  preview(input: VaultPreviewInput): Promise<VaultPreview>;
}

export interface OwnerEdgePort {
  install(input: EdgeInstallInput): Promise<EdgeInstallation>;
  disconnect?(input: DisconnectInput): Promise<void>;
}

export interface DeploymentPort {
  preflight(input: DeploymentPreflightInput): Promise<DeploymentPreflight>;
  stage(input: DeploymentStageInput): Promise<StagedDeployment>;
  deploy(input: DeploymentDeployInput): Promise<DeployedService>;
  disconnect?(input: DisconnectInput): Promise<void>;
  /** Remove the exact retained replica and its installation-owned resources. */
  removeReplica?(input: ReplicaCleanupInput): Promise<void>;
}

export interface PublisherPort {
  bindDevice(input: DeviceBindInput): Promise<DeviceBinding>;
  publishFirstSnapshot(input: FirstSnapshotInput): Promise<SnapshotReceipt>;
  syncNow?(input: SyncInput): Promise<SyncReceipt>;
  disconnect?(input: DisconnectInput): Promise<void>;
}

export interface EndpointVerificationPort {
  verify(input: EndpointVerifyInput): Promise<EndpointVerification>;
}

export interface SetupStateStore {
  load(): Promise<SetupRecord | null>;
  save(record: SetupRecord): Promise<void>;
  clear(): Promise<void>;
}

export interface JournalOptions {
  maxEntries?: number;
  maxEventChars?: number;
  maxDetailChars?: number;
}

export interface OrchestratorOptions {
  stateStore: SetupStateStore;
  vault: VaultPreviewPort;
  edge: OwnerEdgePort;
  deployment: DeploymentPort;
  publisher: PublisherPort;
  endpoint: EndpointVerificationPort;
  journal?: RedactedJournal;
  now?: () => Date;
  createId?: () => string;
}

/** The concrete journal type is declared here to keep the public options cohesive. */
export interface RedactedJournal {
  append(entry: Omit<JournalEntry, "at"> & { at?: string }): JournalEntry;
  entries(): readonly JournalEntry[];
  replace(entries: readonly JournalEntry[]): void;
  clear(): void;
}
