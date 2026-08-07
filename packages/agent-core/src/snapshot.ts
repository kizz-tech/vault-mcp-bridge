import { basename, resolve } from "node:path";
import { randomUUID } from "node:crypto";
import {
  CONTRACT_VERSION,
  computeSnapshotDigest,
  normalizeVaultId,
  sha256Base64Url,
  UploadReceiptSchema,
  VaultPreviewReceiptSchema,
  type Snapshot,
  type SnapshotDocument
} from "@vault-mcp-bridge/contracts";
import type { AgentConfig, AgentPreview, ScanResult, SnapshotPayload } from "./types.js";

export function policyDigest(config: AgentConfig): string {
  return sha256Base64Url(JSON.stringify({
    vaultRoot: config.vaultRoot ? resolve(config.vaultRoot) : "",
    remoteServerUrl: config.remoteServerUrl ?? "",
    vaultId: config.vaultId ? normalizeVaultId(config.vaultId) : "",
    include: [...config.include],
    exclude: [...config.exclude]
  }));
}

export function scanIsIncomplete(scan: ScanResult): boolean {
  return scan.errors.length > 0;
}

export function safeErrorMessage(error: unknown): string {
  const raw = error instanceof Error ? error.message : String(error);
  return raw
    .replace(/(?:[A-Za-z]:)?[\\/](?:Users|home|private|tmp|var)[\\/][^\s"']+/giu, "[local path]")
    .replace(/(?:bearer|authorization|token|pairing code|x-bridge-signature|private key|secret)\s*[:=]\s*[^\s,;]+/giu, "$1=[redacted]")
    .slice(0, 400);
}

function safeDocumentId(file: ScanResult["files"][number]): string {
  const candidate = file.id?.trim();
  return candidate && /^[A-Za-z0-9_-]{16,256}$/u.test(candidate)
    ? candidate
    : sha256Base64Url(`vault-document:v1:${file.relativePath}`);
}

function mediaType(file: ScanResult["files"][number]): SnapshotDocument["mediaType"] {
  return file.contentType === "markdown"
    ? "text/markdown"
    : file.contentType === "canvas"
      ? "application/vnd.obsidian.canvas+json"
      : "application/vnd.obsidian.base+yaml";
}

export function buildSnapshot(scan: ScanResult, vaultId: string, generation: number, createdAt: string): SnapshotPayload {
  const safeVaultId = normalizeVaultId(vaultId);
  const documents: SnapshotDocument[] = scan.files.map((file) => {
    const document: SnapshotDocument = {
      id: safeDocumentId(file),
      title: file.title?.trim() || basename(file.relativePath).replace(/\.(?:md|canvas|base)$/iu, "") || "Untitled",
      mediaType: mediaType(file),
      text: file.content,
      sourceHash: file.sha256 && /^[A-Za-z0-9_-]{43}$/u.test(file.sha256) ? file.sha256 : sha256Base64Url(file.content),
      modifiedAt: file.modifiedAt ?? createdAt
    };
    if (file.metadata) document.metadata = file.metadata;
    return document;
  });
  const snapshotBase = {
    version: CONTRACT_VERSION,
    snapshotId: randomUUID(),
    vaultId: safeVaultId,
    generation,
    createdAt,
    documents
  } as const;
  const snapshot: Snapshot = {
    ...snapshotBase,
    digest: computeSnapshotDigest(snapshotBase)
  };
  return {
    snapshot,
    body: JSON.stringify(snapshot),
    snapshotId: snapshot.snapshotId,
    generation
  };
}

export function toPreview(scan: ScanResult, config: AgentConfig, now: Date, accept = false): AgentPreview {
  const vaultId = normalizeVaultId(config.vaultId ?? "local-vault");
  const includedTotal = scan.files.length;
  const excludedTotal = scan.excluded.length;
  const errors = scan.errors.slice(0, 100);
  const incomplete = scanIsIncomplete(scan);
  const receipt = VaultPreviewReceiptSchema.parse({
    vaultId,
    displayName: basename(resolve(config.vaultRoot ?? "vault")) || "Vault",
    documentCount: scan.files.length,
    totalBytes: scan.bytes,
    scannedAt: now.toISOString(),
    unreadableCount: errors.length,
    projectionVersion: CONTRACT_VERSION
  });
  return {
    receipt,
    policyDigest: policyDigest(config),
    accepted: accept && !incomplete,
    files: scan.files.length,
    documents: scan.files.length,
    bytes: scan.bytes,
    excluded: scan.excluded.length,
    exclusions: scan.excluded.slice(0, 200),
    hidden: scan.hidden,
    symlinks: scan.symlinks,
    errors,
    included: scan.files.slice(0, 200).map((file) => ({ path: file.relativePath, bytes: file.bytes })),
    includedTotal,
    includedOmitted: Math.max(0, includedTotal - 200),
    excludedTotal,
    excludedOmitted: Math.max(0, excludedTotal - 200),
    incomplete,
    warnings: (scan.warnings ?? []).slice(0, 100)
  };
}

export function receiptMatches(receipt: unknown, payload: SnapshotPayload, vaultId: string): boolean {
  const parsed = UploadReceiptSchema.safeParse(receipt);
  if (!parsed.success) return false;
  const candidate = parsed.data as Record<string, unknown>;
  const snapshot = payload.snapshot as Record<string, unknown>;
  return candidate.accepted === true
    && candidate.snapshotId === payload.snapshotId
    && candidate.vaultId === normalizeVaultId(vaultId)
    && candidate.generation === payload.generation
    && candidate.digest === snapshot.digest;
}
