import { randomUUID } from "node:crypto";
import {
  CONTRACT_VERSION,
  SnapshotSchema,
  computeSnapshotDigest,
  type Snapshot,
  type SnapshotDocument
} from "@vault-mcp-bridge/contracts";
import type { BuildSnapshotOptions, ScanResult } from "./types.js";

/** Strip local paths/search helpers before creating a remote-safe snapshot. */
export function buildSnapshot(scan: ScanResult, options: BuildSnapshotOptions = {}): Snapshot {
  const documents: SnapshotDocument[] = scan.documents.map((document) => {
    const remote: SnapshotDocument = {
      id: document.id,
      title: document.title,
      mediaType: document.mediaType,
      text: document.text,
      sourceHash: document.sourceHash,
      modifiedAt: document.modifiedAt
    };
    if (document.metadata) remote.metadata = document.metadata;
    return remote;
  });
  const snapshotBase = {
    version: CONTRACT_VERSION,
    snapshotId: options.snapshotId ?? randomUUID(),
    vaultId: options.vaultId ?? scan.vaultId,
    generation: options.generation ?? 1,
    createdAt: options.createdAt ?? new Date().toISOString(),
    documents
  } as const;
  const snapshot: Snapshot = {
    ...snapshotBase,
    digest: computeSnapshotDigest(snapshotBase)
  };
  return SnapshotSchema.parse(snapshot);
}
