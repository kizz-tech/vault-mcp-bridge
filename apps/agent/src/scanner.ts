import { randomBytes } from 'node:crypto';
import { scanVault as coreScanVault } from '@vault-mcp-bridge/vault-core';
import type { ScanIssue, ScanOptions, ScanResult, VaultScanner } from './types.js';

function isIncompleteExclusion(reason: string): reason is NonNullable<ScanIssue['reason']> {
  return reason === 'unstable'
    || reason === 'read-error'
    || reason === 'file-limit'
    || reason === 'file-too-large'
    || reason === 'total-bytes-limit';
}

/**
 * Strict adapter around vault-core. Scanner errors are deliberately propagated:
 * a symlink, containment, stability, or limit failure must never switch the
 * publisher to a weaker filesystem implementation.
 */
export class DefaultVaultScanner implements VaultScanner {
  constructor(private readonly idKey: Uint8Array | string = randomBytes(32)) {}

  async scan(root: string, options: ScanOptions): Promise<ScanResult> {
    const result = await coreScanVault(root, {
      idKey: this.idKey,
      ...(options.include ? { include: options.include } : {}),
      ...(options.exclude ? { exclude: options.exclude } : {}),
      ...(options.vaultId ? { vaultId: options.vaultId } : {}),
    });

    const incompleteErrors: ScanIssue[] = result.exclusions
      .map((entry): ScanIssue | undefined => {
        if (!isIncompleteExclusion(entry.reason)) return undefined;
        return { path: entry.relativePath, reason: entry.reason, message: entry.detail || `Scan excluded ${entry.reason}` };
      })
      .filter((issue): issue is ScanIssue => issue !== undefined);
    const warnings: Array<{ path: string; message: string }> = [];
    for (const message of result.warnings) {
      const directory = /^Unable to read directory\s+(.+)$/u.exec(message);
      if (directory) {
        incompleteErrors.push({ path: directory[1] || '', reason: 'unreadable-directory', message });
      } else if (/^Skipped unstable file:/u.test(message) || /^Unable to read file\s+/u.test(message)) {
        // The structured exclusion above is the authoritative fatal record.
        continue;
      } else {
        // Frontmatter and Canvas parse warnings preserve the source document
        // and are intentionally non-fatal to a read-only publication.
        warnings.push({ path: '', message });
      }
    }
    return {
      files: result.documents.map((document) => ({
        id: document.id,
        title: document.title,
        relativePath: document.relativePath,
        bytes: Buffer.byteLength(document.text, 'utf8'),
        content: document.text,
        contentType: document.mediaType === 'text/markdown'
          ? 'markdown'
          : document.mediaType === 'application/vnd.obsidian.canvas+json'
            ? 'canvas'
            : 'base',
        sha256: document.sourceHash,
        modifiedAt: document.modifiedAt,
        ...(document.metadata ? { metadata: document.metadata } : {}),
      })),
      excluded: result.exclusions.map((entry) => ({ path: entry.relativePath, reason: entry.reason })),
      hidden: result.exclusionCounts.hidden,
      symlinks: result.exclusionCounts.symlink,
      errors: incompleteErrors,
      ...(warnings.length ? { warnings } : {}),
      bytes: result.bytesRead,
    };
  }
}
