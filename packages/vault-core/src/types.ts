import type { AgentConfig, Metadata, MediaType, Snapshot, SnapshotDocument } from "@vault-mcp-bridge/contracts";

export type IdKey = string | Uint8Array;

export type ScanExclusionReason =
  | "hidden"
  | "symlink"
  | "outside-root"
  | "unsupported"
  | "include"
  | "exclude"
  | "file-limit"
  | "file-too-large"
  | "total-bytes-limit"
  | "not-regular"
  | "unstable"
  | "read-error";

export interface VaultScanLimits {
  maxFiles: number;
  maxFileBytes: number;
  maxTotalBytes: number;
  maxReadRetries: number;
}

export interface VaultScanOptions {
  /** HMAC key kept local to the publisher; it must never be uploaded. */
  idKey: IdKey;
  vaultId?: string;
  include?: readonly string[];
  exclude?: readonly string[];
  limits?: Partial<VaultScanLimits>;
}

/** Local preview extends a remote-safe document with paths; never upload it directly. */
export type ScannedDocument = SnapshotDocument & {
  relativePath: string;
  absolutePath: string;
  searchableText?: string;
};

export interface ScanExclusion {
  relativePath: string;
  reason: ScanExclusionReason;
  detail?: string;
}

export interface ScanResult {
  vaultRoot: string;
  vaultId: string;
  documents: readonly ScannedDocument[];
  filesSeen: number;
  filesIncluded: number;
  bytesRead: number;
  completedAt: string;
  warnings: readonly string[];
  exclusions: readonly ScanExclusion[];
  exclusionCounts: Readonly<Record<ScanExclusionReason, number>>;
  limits: VaultScanLimits;
}

export interface BuildSnapshotOptions {
  vaultId?: string;
  generation?: number;
  snapshotId?: string;
  createdAt?: string;
}

export interface ScanDocumentLocalPreview {
  id: string;
  title: string;
  mediaType: MediaType;
  relativePath: string;
  sourceHash: string;
  modifiedAt: string;
  metadata?: Metadata;
}

export type { AgentConfig, Metadata, MediaType, Snapshot, SnapshotDocument };
