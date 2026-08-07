import { randomBytes } from "node:crypto";
import { scanVault as coreScanVault } from "@vault-mcp-bridge/vault-core";
import type { ScanIssue, ScanOptions, ScanResult, VaultScanner } from "./types.js";

function incompleteIssue(reason: string): reason is NonNullable<ScanIssue["reason"]> {
  return reason === "unstable" || reason === "read-error" || reason === "file-limit" || reason === "file-too-large" || reason === "total-bytes-limit";
}

/** Strict adapter around vault-core. It never falls back to an unsafe filesystem reader. */
export class DefaultVaultScanner implements VaultScanner {
  constructor(private readonly idKey: Uint8Array | string = randomBytes(32)) {}

  async scan(root: string, options: ScanOptions): Promise<ScanResult> {
    const result = await coreScanVault(root, {
      idKey: this.idKey,
      ...(options.include ? { include: options.include } : {}),
      ...(options.exclude ? { exclude: options.exclude } : {}),
      ...(options.vaultId ? { vaultId: options.vaultId } : {})
    });
    const errors: ScanIssue[] = result.exclusions
      .map((entry): ScanIssue | undefined => incompleteIssue(entry.reason)
        ? { path: entry.relativePath, reason: entry.reason, message: entry.detail ?? `Scan excluded ${entry.reason}` }
        : undefined)
      .filter((entry): entry is ScanIssue => entry !== undefined);
    const warnings: Array<{ path: string; message: string }> = [];
    for (const warning of result.warnings) {
      const directory = /^Unable to read directory\s+(.+)$/u.exec(warning);
      if (directory) errors.push({ path: directory[1] ?? "", reason: "unreadable-directory", message: warning });
      else if (/^Skipped unstable file:/u.test(warning) || /^Unable to read file\s+/u.test(warning)) continue;
      else warnings.push({ path: "", message: warning });
    }
    return {
      files: result.documents.map((document) => ({
        id: document.id,
        title: document.title,
        relativePath: document.relativePath,
        bytes: Buffer.byteLength(document.text, "utf8"),
        content: document.text,
        contentType: document.mediaType === "text/markdown" ? "markdown" : document.mediaType === "application/vnd.obsidian.canvas+json" ? "canvas" : "base",
        sha256: document.sourceHash,
        modifiedAt: document.modifiedAt,
        ...(document.metadata ? { metadata: document.metadata } : {})
      })),
      excluded: result.exclusions.map((entry) => ({ path: entry.relativePath, reason: entry.reason })),
      hidden: result.exclusionCounts.hidden,
      symlinks: result.exclusionCounts.symlink,
      errors,
      ...(warnings.length > 0 ? { warnings } : {}),
      bytes: result.bytesRead
    };
  }
}
