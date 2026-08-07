import type {
  FetchOutput as ContractFetchOutput,
  PairDeviceRequest,
  SearchResult as ContractSearchResult,
  SearchOutput as ContractSearchOutput,
  Snapshot as ContractSnapshot,
  SnapshotDocument as ContractSnapshotDocument,
} from "@vault-mcp-bridge/contracts";

export type SnapshotDocument = ContractSnapshotDocument;
export type Snapshot = ContractSnapshot;

export type SnapshotUploadEnvelope = {
  deviceId: string;
  vaultId: string;
  timestamp: number;
  nonce: string;
  signature: string;
  snapshot: Snapshot;
};

export type PairingConsumeInput = {
  version: PairDeviceRequest["version"];
  pairCode: PairDeviceRequest["pairCode"];
  agentId: PairDeviceRequest["agentId"];
  publicKey: PairDeviceRequest["publicKey"];
  vaultId?: PairDeviceRequest["vaultId"];
  label?: PairDeviceRequest["label"];
};

export type SearchResult = ContractSearchResult;

export type SearchOutput = ContractSearchOutput;
export type FetchOutput = ContractFetchOutput;

export type Principal = {
  subject: string;
  scope: string;
  /** OAuth client bound to this installation. Required for production MCP. */
  clientId?: string;
  /** Installation and vault claims are retained for per-request guards. */
  installationId?: string;
  vaultId?: string;
};
