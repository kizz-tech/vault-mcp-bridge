import type { JournalEvent, ProductStatus, VaultPreviewReceipt } from "@vault-mcp-bridge/contracts";
import type { PublisherTlsCredentialProvider } from "./transport.js";

export type AgentMode = "development" | "production";

/** User-editable local settings. Secrets and private keys are never part of this shape. */
export interface AgentConfig {
  vaultRoot?: string;
  include: string[];
  exclude: string[];
  remoteServerUrl?: string;
  vaultId?: string;
  syncIntervalMinutes: number;
  agentId?: string;
  label?: string;
}

export interface ScanFile {
  id?: string;
  title?: string;
  relativePath: string;
  bytes: number;
  content: string;
  contentType: "markdown" | "canvas" | "base";
  sha256?: string;
  modifiedAt?: string;
  metadata?: Record<string, string | number | boolean | null | Array<string | number | boolean | null>>;
}

export interface ScanIssue {
  path: string;
  message: string;
  reason?: string;
}

/** Local-only scan result. Relative paths are safe for the desktop disclosure; absolute paths are not exposed. */
export interface ScanResult {
  files: ScanFile[];
  excluded: Array<{ path: string; reason: string }>;
  hidden: number;
  symlinks: number;
  errors: ScanIssue[];
  warnings?: Array<{ path: string; message: string }>;
  bytes: number;
}

export interface ScanOptions {
  include?: string[];
  exclude?: string[];
  vaultId?: string;
}

export interface VaultScanner {
  scan(root: string, options: ScanOptions): Promise<ScanResult>;
}

export interface SnapshotPayload {
  snapshot: unknown;
  body: string;
  snapshotId: string;
  generation: number;
}

export interface PublisherStatus {
  ok: boolean;
  checkedAt: string;
  vaultId?: string;
  generation?: number;
  snapshotId?: string;
  freshnessSeconds?: number;
  message?: string;
}

export interface RemoteClient {
  pair(input: {
    url: string;
    code: string;
    agentId: string;
    publicKey: string;
    vaultId?: string;
    label?: string;
  }): Promise<{ deviceId: string; vaultId?: string; receipt?: unknown }>;
  upload(input: {
    url: string;
    deviceId: string;
    vaultId: string;
    snapshot: SnapshotPayload;
    privateKey: string;
  }): Promise<unknown>;
  status(input: { url: string; deviceId: string; vaultId: string; privateKey: string }): Promise<PublisherStatus>;
}

/**
 * Credential values are intentionally not representable in status or persisted
 * state. A production implementation must advertise `kind: "keychain"`.
 */
export interface CredentialStore {
  readonly kind: string;
  getPrivateKey(): Promise<string | undefined>;
  savePrivateKey(privateKey: string): Promise<void>;
  deletePrivateKey(): Promise<void>;
  identity?(): Promise<DeviceIdentity | undefined>;
  saveIdentity?(privateKey: string, publicKey: string, createdAt: string): Promise<void>;
  getOrCreateIdKey?(): Promise<string>;
}

export interface DeviceIdentity {
  publicKey: string;
  keyAlgorithm: "ed25519";
  createdAt: string;
}

export interface PairingState {
  paired: boolean;
  deviceId?: string;
  publicKey?: string;
  pairedAt?: string;
}

export type AgentPhase = "idle" | "vault-selected" | "preview-ready" | "device-bound" | "synchronizing" | "ready" | "paused" | "needs-attention";

export interface AgentRuntime {
  startedAt: string;
  phase: AgentPhase;
  paused: boolean;
  lastScanAt?: string;
  lastUploadAt?: string;
  lastReceipt?: unknown;
  lastPublisherStatus?: PublisherStatus;
  lastPreview?: AgentPreview;
  lastError?: string;
  pairing: PairingState;
  journal: JournalEvent[];
}

/**
 * The canonical contract receipt is deliberately small. `details` remains
 * local-only and is bounded for the disclosure panel.
 */
export interface AgentPreview {
  receipt: VaultPreviewReceipt;
  policyDigest: string;
  accepted: boolean;
  files: number;
  documents: number;
  bytes: number;
  excluded: number;
  exclusions: Array<{ path: string; reason: string }>;
  hidden: number;
  symlinks: number;
  errors: ScanIssue[];
  included: Array<{ path: string; bytes: number }>;
  includedTotal: number;
  includedOmitted: number;
  excludedTotal: number;
  excludedOmitted: number;
  incomplete: boolean;
  warnings: Array<{ path: string; message: string }>;
}

export interface AgentStatus {
  readOnly: true;
  mode: AgentMode;
  phase: AgentPhase;
  productStatus: ProductStatus;
  paused: boolean;
  configured: boolean;
  vaultConfigured: boolean;
  remoteConfigured: boolean;
  pairingConfigured: boolean;
  credentialStore: string;
  vaultId?: string;
  preview?: AgentPreview;
  lastScanAt?: string;
  lastUploadAt?: string;
  lastReceipt?: unknown;
  lastPublisherStatus?: PublisherStatus;
  lastError?: string;
  operation?: "configure" | "preview" | "identity" | "pair" | "sync" | "status";
}

export interface AgentStateStore {
  load(): Promise<Partial<Pick<AgentState, "config" | "runtime" | "identity" | "pairing">>>;
  save(state: Pick<AgentState, "config" | "runtime" | "identity" | "pairing">): Promise<void>;
}

export interface AgentState {
  config: AgentConfig;
  runtime: AgentRuntime;
  identity?: DeviceIdentity;
  pairing: PairingState;
}

export interface AgentServiceOptions {
  dataDir?: string;
  mode?: AgentMode;
  scanner: VaultScanner;
  remoteClient: RemoteClient;
  credentials: CredentialStore;
  /** Required in production; credentials are read ephemerally for publisher requests. */
  publisherTlsCredentialProvider?: PublisherTlsCredentialProvider;
  now?: () => Date;
  stateStore?: AgentStateStore;
  maxJournalEntries?: number;
}

export interface ConfigureInput {
  vaultRoot?: string;
  include?: string[];
  exclude?: string[];
  remoteServerUrl?: string;
  vaultId?: string;
  syncIntervalMinutes?: number;
  agentId?: string;
  label?: string;
}

export interface PreviewOptions {
  /** Mark a complete preview as accepted by the setup action. */
  accept?: boolean;
}

export interface SyncResult {
  receipt: unknown;
  preview: AgentPreview;
  snapshotId: string;
}

export interface IdentityResult {
  identity: DeviceIdentity;
  credentialStore: string;
}

export interface PairResult {
  pairing: PairingState;
  receipt?: unknown;
}
