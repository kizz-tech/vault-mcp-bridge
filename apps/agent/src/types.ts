import type { AgentConfig as ContractAgentConfig, Metadata } from '@vault-mcp-bridge/contracts';

/** User-editable settings. This shape intentionally contains no credentials. */
export interface AgentConfig extends Partial<ContractAgentConfig> {
  vaultRoot?: string;
  include?: string[];
  exclude?: string[];
  remoteServerUrl?: string;
  vaultId?: string;
  syncIntervalMinutes?: number;
  label?: string;
}

export interface RuntimeState {
  startedAt: string;
  lastScanAt?: string;
  lastUploadAt?: string;
  lastReceipt?: unknown;
  lastError?: string;
  lastPreview?: PreviewResult;
  lastPublisherStatus?: PublisherStatus;
  /** Current bounded set of old server device identities awaiting revocation. */
  pendingRevocations?: PendingRevocation[];
  /** Legacy v0.1 single-record field; loadRuntime migrates it into the array. */
  pendingRevocation?: PendingRevocation;
}

export interface PendingRevocation {
  deviceId: string;
  agentId: string;
  publicKey: string;
  createdAt: string;
  status: 'pending';
}

export interface PreviewResult {
  files: number;
  documents: number;
  bytes: number;
  excluded: number;
  exclusions: Array<{ path: string; reason: string }>;
  hidden: number;
  symlinks: number;
  errors: Array<{ path: string; message: string }>;
  included: Array<{ path: string; bytes: number }>;
  policyDigest: string;
  includedTotal: number;
  includedOmitted: number;
  excludedTotal: number;
  excludedOmitted: number;
  incomplete: boolean;
  incompleteErrors: Array<ScanIssue>;
  warnings: Array<{ path: string; message: string }>;
}

export type ScanIssueReason =
  | 'unstable'
  | 'read-error'
  | 'unreadable-directory'
  | 'file-limit'
  | 'file-too-large'
  | 'total-bytes-limit'
  | 'other';

export interface ScanIssue {
  path: string;
  message: string;
  reason?: ScanIssueReason;
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

export interface PublicStatus {
  readOnly: true;
  configured: boolean;
  vaultConfigured: boolean;
  remoteConfigured: boolean;
  pairingConfigured: boolean;
  credentialStore: 'file-development' | 'keychain-unavailable';
  dataDir: string;
  vaultId?: string;
  vaultRootConfigured: boolean;
  lastScanAt?: string;
  lastUploadAt?: string;
  lastReceipt?: unknown;
  lastPreview?: PreviewResult;
  lastPublisherStatus?: PublisherStatus;
  lastError?: string;
  intervalSyncEnabled: boolean;
  previewValid: boolean;
  pendingRevocations?: Array<Pick<PendingRevocation, 'deviceId' | 'agentId' | 'createdAt' | 'status'>>;
}

export interface DeviceIdentity {
  publicKey: string;
  keyAlgorithm: 'ed25519';
  createdAt: string;
}

export interface PairingState {
  paired: boolean;
  deviceId?: string;
  publicKey?: string;
  pairedAt?: string;
}

export interface AgentDeps {
  scanVault?: VaultScanner;
  remoteClient?: RemoteClient;
  credentials?: CredentialStore;
  now?: () => Date;
}

export interface ScanOptions {
  include?: string[];
  exclude?: string[];
  vaultId?: string;
}

export interface ScanFile {
  id?: string;
  title?: string;
  relativePath: string;
  bytes: number;
  content: string;
  contentType: 'markdown' | 'canvas' | 'base';
  sha256?: string;
  modifiedAt?: string;
  metadata?: Metadata;
}

export interface ScanResult {
  files: ScanFile[];
  excluded: Array<{ path: string; reason: string }>;
  hidden: number;
  symlinks: number;
  errors: Array<ScanIssue>;
  warnings?: Array<{ path: string; message: string }>;
  bytes: number;
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

export interface CredentialStore {
  readonly kind: 'file-development' | 'keychain-unavailable';
  getPrivateKey(): Promise<string | undefined>;
  savePrivateKey(privateKey: string): Promise<void>;
  deletePrivateKey(): Promise<void>;
  getOrCreateIdKey?(): Promise<string>;
}
