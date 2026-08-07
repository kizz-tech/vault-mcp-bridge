import { constants as fsConstants } from "node:fs";
import { lstat, open, readdir, realpath, type FileHandle } from "node:fs/promises";
import { basename, dirname, extname, isAbsolute, join, relative, resolve, sep } from "node:path";
import {
  LIMITS,
  OpaqueIdSchema,
  sha256Base64Url,
  type MediaType,
  type Metadata
} from "@vault-mcp-bridge/contracts";
import { parseFrontmatter } from "./frontmatter.js";
import { extractCanvasText } from "./canvas.js";
import { normalizeRelativePath, stableDocumentId } from "./ids.js";
import type {
  ScanExclusion,
  ScanExclusionReason,
  ScanResult,
  ScannedDocument,
  VaultScanLimits,
  VaultScanOptions
} from "./types.js";

const DEFAULT_INCLUDE = ["*.md", "**/*.md", "*.canvas", "**/*.canvas", "*.base", "**/*.base"] as const;
const DEFAULT_EXCLUDE = [
  "**/.obsidian/**",
  "**/.git/**",
  "**/.trash/**",
  "**/node_modules/**"
] as const;
const SUPPORTED_EXTENSIONS = new Map<string, MediaType>([
  [".md", "text/markdown"],
  [".canvas", "application/vnd.obsidian.canvas+json"],
  [".base", "application/vnd.obsidian.base+yaml"]
]);

const DEFAULT_LIMITS: VaultScanLimits = {
  maxFiles: LIMITS.maxSnapshotDocuments,
  maxFileBytes: LIMITS.maxDocumentTextBytes,
  maxTotalBytes: LIMITS.maxSnapshotBytes,
  maxReadRetries: 2
};

function normalizeLimits(input: VaultScanOptions["limits"]): VaultScanLimits {
  const merged = { ...DEFAULT_LIMITS, ...input };
  if (!Number.isInteger(merged.maxFiles) || merged.maxFiles < 1) throw new RangeError("maxFiles must be positive");
  if (merged.maxFiles > LIMITS.maxSnapshotDocuments) throw new RangeError("maxFiles exceeds protocol limit");
  if (!Number.isInteger(merged.maxFileBytes) || merged.maxFileBytes < 1) throw new RangeError("maxFileBytes must be positive");
  if (merged.maxFileBytes > LIMITS.maxDocumentTextBytes) throw new RangeError("maxFileBytes exceeds protocol limit");
  if (!Number.isInteger(merged.maxTotalBytes) || merged.maxTotalBytes < 1) throw new RangeError("maxTotalBytes must be positive");
  if (merged.maxTotalBytes > LIMITS.maxSnapshotBytes) throw new RangeError("maxTotalBytes exceeds protocol limit");
  if (!Number.isInteger(merged.maxReadRetries) || merged.maxReadRetries < 0 || merged.maxReadRetries > 5) {
    throw new RangeError("maxReadRetries must be between 0 and 5");
  }
  return merged;
}

function isHiddenPath(relativePath: string): boolean {
  return relativePath.split("/").some((part) => part.startsWith("."));
}

function isInside(root: string, candidate: string): boolean {
  const rel = relative(root, candidate);
  return rel === "" || (!rel.startsWith("../") && rel !== ".." && !isAbsolute(rel));
}

function reasonMap(): Record<ScanExclusionReason, number> {
  return {
    hidden: 0,
    symlink: 0,
    "outside-root": 0,
    unsupported: 0,
    include: 0,
    exclude: 0,
    "file-limit": 0,
    "file-too-large": 0,
    "total-bytes-limit": 0,
    "not-regular": 0,
    unstable: 0,
    "read-error": 0
  };
}

function addExclusion(
  exclusions: ScanExclusion[],
  counts: Record<ScanExclusionReason, number>,
  relativePath: string,
  reason: ScanExclusionReason,
  detail?: string
): void {
  counts[reason] += 1;
  exclusions.push(detail ? { relativePath, reason, detail } : { relativePath, reason });
}

function titleFor(relativePath: string, metadata?: Metadata): string {
  const candidate = metadata?.title;
  if (typeof candidate === "string" && candidate.trim()) return candidate.trim().slice(0, LIMITS.maxTitleChars);
  return basename(relativePath, extname(relativePath)) || "Untitled";
}

function mediaTypeFor(relativePath: string): MediaType | undefined {
  return SUPPORTED_EXTENSIONS.get(extname(relativePath).toLowerCase());
}

/** Small dependency-free glob matcher for the vault policy surface. It
 * supports `*`, `**` and `?`; patterns are always matched against POSIX
 * relative paths and cannot inspect an absolute filesystem path. */
function globMatcher(patterns: readonly string[]): (value: string) => boolean {
  const regexes = patterns.map((pattern) => {
    const normalized = pattern.replaceAll("\\", "/");
    let source = "";
    for (let index = 0; index < normalized.length; index += 1) {
      const character = normalized[index];
      if (character === undefined) continue;
      if (character === "*" && normalized[index + 1] === "*") {
        index += 1;
        if (normalized[index + 1] === "/") {
          index += 1;
          source += "(?:.*/)?";
        } else {
          source += ".*";
        }
      } else if (character === "*") {
        source += "[^/]*";
      } else if (character === "?") {
        source += "[^/]";
      } else {
        source += character.replace(/[|\\{}()[\]^$+?.]/g, "\\$&");
      }
    }
    return new RegExp(`^${source}$`, "u");
  });
  return (value: string) => regexes.some((regex) => regex.test(value));
}

export interface StableReadHandle {
  stat(): Promise<Awaited<ReturnType<FileHandle["stat"]>>>;
  readFile(): Promise<Buffer>;
  close(): Promise<void>;
}

/** Injectable only for deterministic tests; production always uses fs.open. */
export type OpenStableReadHandle = (filePath: string, flags: number) => Promise<StableReadHandle>;

interface PathIdentity {
  dev: number | bigint;
  ino: number | bigint;
}

function sameIdentity(left: PathIdentity, right: PathIdentity): boolean {
  return String(left.dev) === String(right.dev) && String(left.ino) === String(right.ino);
}

function identity(stats: PathIdentity): PathIdentity {
  return { dev: stats.dev, ino: stats.ino };
}

function sameStat(left: Awaited<ReturnType<FileHandle["stat"]>>, right: Awaited<ReturnType<FileHandle["stat"]>>): boolean {
  return sameIdentity(left, right) &&
    left.size === right.size &&
    left.mtimeMs === right.mtimeMs &&
    left.ctimeMs === right.ctimeMs;
}

async function ancestorIdentities(root: string, filePath: string): Promise<readonly PathIdentity[]> {
  const parent = dirname(filePath);
  if (!isInside(root, parent)) throw new Error("outside-root");
  const parentRelative = relative(root, parent);
  const parts = parentRelative ? parentRelative.split(sep) : [];
  const identities: PathIdentity[] = [];
  let current = root;
  for (const part of parts) {
    current = join(current, part);
    const ancestor = await lstat(current);
    if (ancestor.isSymbolicLink()) throw new Error("symlink ancestor");
    if (!ancestor.isDirectory()) throw new Error("ancestor is not a directory");
    identities.push(identity(ancestor));
  }
  const rootStat = await lstat(root);
  if (rootStat.isSymbolicLink() || !rootStat.isDirectory()) throw new Error("invalid vault root");
  identities.unshift(identity(rootStat));
  return identities;
}

function sameAncestors(left: readonly PathIdentity[], right: readonly PathIdentity[]): boolean {
  return left.length === right.length && left.every((entry, index) => {
    const other = right[index];
    return other !== undefined && sameIdentity(entry, other);
  });
}

function noFollowReadFlags(): number {
  const noFollow = fsConstants.O_NOFOLLOW;
  if (typeof noFollow !== "number") throw new Error("platform does not support O_NOFOLLOW");
  return fsConstants.O_RDONLY | noFollow;
}

/**
 * Read one vault file through a single descriptor. Path checks are repeated
 * around the descriptor operation so a parent-directory or final-entry swap
 * cannot turn the read into an outside-vault read.
 */
export async function readStableFile(
  filePath: string,
  root: string,
  limits: VaultScanLimits,
  openStableHandle: OpenStableReadHandle = async (path, flags) => open(path, flags)
): Promise<{ text: string; size: number; mtimeMs: number }> {
  const rootLink = await lstat(root);
  if (rootLink.isSymbolicLink()) throw new Error("Vault root may not be a symlink");
  if (!rootLink.isDirectory()) throw new Error("Vault root must be a directory");
  const lexicalRoot = resolve(root);
  const lexicalFile = resolve(filePath);
  if (!isInside(lexicalRoot, lexicalFile)) throw new Error("outside-root");
  const canonicalRoot = await realpath(root);
  const canonicalRootStat = await lstat(canonicalRoot);
  if (!sameIdentity(rootLink, canonicalRootStat)) throw new Error("vault root changed while resolving");
  const canonicalRelative = relative(lexicalRoot, lexicalFile);
  const canonicalCandidate = join(canonicalRoot, canonicalRelative);
  let lastError: unknown;
  for (let attempt = 0; attempt <= limits.maxReadRetries; attempt += 1) {
    let handle: StableReadHandle | undefined;
    try {
      const beforePath = await lstat(filePath);
      if (beforePath.isSymbolicLink()) throw new Error("symlink entry");
      if (!beforePath.isFile()) throw new Error("not a regular file");
      const beforeResolved = await realpath(filePath);
      if (!isInside(canonicalRoot, beforeResolved)) throw new Error("outside-root");
      const beforeAncestors = await ancestorIdentities(canonicalRoot, canonicalCandidate);
      try {
        handle = await openStableHandle(filePath, noFollowReadFlags());
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === "ELOOP") throw new Error("symlink entry");
        throw error;
      }
      const beforeDescriptor = await handle.stat();
      if (!beforeDescriptor.isFile()) throw new Error("not a regular file");
      if (beforeDescriptor.size > limits.maxFileBytes) throw new RangeError("file too large");
      if (!sameStat(beforePath, beforeDescriptor)) throw new Error("file changed while reading");
      const afterOpenAncestors = await ancestorIdentities(canonicalRoot, canonicalCandidate);
      if (!sameAncestors(beforeAncestors, afterOpenAncestors)) throw new Error("file changed while reading");
      const afterOpenPath = await lstat(filePath);
      if (afterOpenPath.isSymbolicLink()) throw new Error("symlink entry");
      if (!sameStat(afterOpenPath, beforeDescriptor)) throw new Error("file changed while reading");
      const content = await handle.readFile();
      const afterDescriptor = await handle.stat();
      if (!sameStat(beforeDescriptor, afterDescriptor)) throw new Error("file changed while reading");
      const afterReadPath = await lstat(filePath);
      if (afterReadPath.isSymbolicLink()) throw new Error("symlink entry");
      if (!sameStat(afterReadPath, afterDescriptor)) throw new Error("file changed while reading");
      const afterResolved = await realpath(filePath);
      if (!isInside(canonicalRoot, afterResolved) || afterResolved !== beforeResolved) throw new Error("outside-root");
      const afterReadAncestors = await ancestorIdentities(canonicalRoot, canonicalCandidate);
      if (!sameAncestors(beforeAncestors, afterReadAncestors)) throw new Error("file changed while reading");
      return { text: content.toString("utf8"), size: content.byteLength, mtimeMs: Number(afterDescriptor.mtimeMs) };
    } catch (error) {
      lastError = error;
      if (error instanceof RangeError || (error instanceof Error && error.message === "not a regular file")) throw error;
      if (error instanceof Error && ["symlink entry", "symlink ancestor", "outside-root", "invalid vault root", "ancestor is not a directory", "platform does not support O_NOFOLLOW"].includes(error.message)) {
        throw error;
      }
    } finally {
      if (handle) await handle.close().catch(() => undefined);
    }
  }
  throw lastError instanceof Error ? lastError : new Error("unable to read file");
}

/** Test seam kept alongside the reader so swap defenses can be deterministic. */
export const __testing = { readStableFile };

/**
 * The second overload keeps a small compatibility seam for callers that only
 * need a local preview. Such calls fail closed at runtime because an idKey is
 * required before a remote-safe snapshot can be produced.
 */
export function scanVault(rootPath: string, options: VaultScanOptions): Promise<ScanResult>;
export function scanVault(rootPath: string, options: Pick<VaultScanOptions, "include" | "exclude">): Promise<ScanResult>;
export async function scanVault(
  rootPath: string,
  options: VaultScanOptions | Pick<VaultScanOptions, "include" | "exclude">
): Promise<ScanResult> {
  if (!("idKey" in options) || !options.idKey) throw new TypeError("scanVault requires a non-empty idKey");
  if ((typeof options.idKey === "string" && options.idKey.length === 0) ||
      (options.idKey instanceof Uint8Array && options.idKey.byteLength === 0)) {
    throw new TypeError("scanVault requires a non-empty idKey");
  }
  const idKey = options.idKey;
  const root = resolve(rootPath);
  const rootLstat = await lstat(root);
  if (rootLstat.isSymbolicLink()) throw new Error("Vault root may not be a symlink");
  if (!rootLstat.isDirectory()) throw new Error("Vault root must be a directory");
  const canonicalRoot = await realpath(root);
  const canonicalRootStat = await lstat(canonicalRoot);
  if (!sameIdentity(rootLstat, canonicalRootStat)) throw new Error("vault root changed while resolving");
  if (typeof fsConstants.O_NOFOLLOW !== "number") throw new Error("platform does not support O_NOFOLLOW");
  const limits = normalizeLimits(options.limits);
  const include = options.include?.length ? [...options.include] : [...DEFAULT_INCLUDE];
  const exclude = [...DEFAULT_EXCLUDE, ...(options.exclude ?? [])];
  const includeMatch = globMatcher(include);
  const excludeMatch = globMatcher(exclude);
  const vaultId = options.vaultId ?? stableDocumentId(idKey, "__vault__");
  if (!OpaqueIdSchema.safeParse(vaultId).success) throw new TypeError("vaultId must be an opaque identifier");

  const documents: ScannedDocument[] = [];
  const exclusions: ScanExclusion[] = [];
  const exclusionCounts = reasonMap();
  const warnings: string[] = [];
  let filesSeen = 0;
  let bytesRead = 0;

  async function visit(directory: string): Promise<void> {
    let entries;
    try {
      entries = await readdir(directory, { withFileTypes: true });
    } catch (error) {
      const rel = normalizeRelativePath(relative(canonicalRoot, directory) || ".");
      warnings.push(`Unable to read directory ${rel}: ${error instanceof Error ? error.message : "unknown error"}`);
      return;
    }
    entries.sort((a, b) => a.name.localeCompare(b.name));
    for (const entry of entries) {
      const candidate = join(directory, entry.name);
      const relRaw = relative(canonicalRoot, candidate);
      const rel = relRaw ? normalizeRelativePath(relRaw) : ".";
      if (!isInside(canonicalRoot, candidate)) {
        addExclusion(exclusions, exclusionCounts, rel, "outside-root");
        continue;
      }
      if (entry.isSymbolicLink()) {
        addExclusion(exclusions, exclusionCounts, rel, "symlink");
        continue;
      }
      if (isHiddenPath(rel)) {
        addExclusion(exclusions, exclusionCounts, rel, "hidden");
        continue;
      }
      if (entry.isDirectory()) {
        await visit(candidate);
        continue;
      }
      filesSeen += 1;
      const mediaType = mediaTypeFor(rel);
      if (!mediaType) {
        addExclusion(exclusions, exclusionCounts, rel, "unsupported");
        continue;
      }
      if (!includeMatch(rel)) {
        addExclusion(exclusions, exclusionCounts, rel, "include");
        continue;
      }
      if (excludeMatch(rel)) {
        addExclusion(exclusions, exclusionCounts, rel, "exclude");
        continue;
      }
      if (documents.length >= limits.maxFiles) {
        addExclusion(exclusions, exclusionCounts, rel, "file-limit");
        continue;
      }
      let preview;
      try {
        preview = await readStableFile(candidate, canonicalRoot, limits);
      } catch (error) {
        if (error instanceof Error && ["vault root changed while resolving", "invalid vault root", "platform does not support O_NOFOLLOW"].includes(error.message)) {
          throw error;
        }
        if (error instanceof RangeError) {
          addExclusion(exclusions, exclusionCounts, rel, "file-too-large");
        } else if (error instanceof Error && error.message === "file changed while reading") {
          addExclusion(exclusions, exclusionCounts, rel, "unstable");
          warnings.push(`Skipped unstable file: ${rel}`);
        } else if (error instanceof Error && (error.message === "symlink entry" || error.message === "symlink ancestor")) {
          addExclusion(exclusions, exclusionCounts, rel, "symlink");
        } else if (error instanceof Error && error.message === "outside-root") {
          addExclusion(exclusions, exclusionCounts, rel, "outside-root");
        } else if (error instanceof Error && error.message === "not a regular file") {
          addExclusion(exclusions, exclusionCounts, rel, "not-regular");
        } else {
          addExclusion(exclusions, exclusionCounts, rel, "read-error");
          warnings.push(`Unable to read file ${rel}`);
        }
        continue;
      }
      if (bytesRead + preview.size > limits.maxTotalBytes) {
        addExclusion(exclusions, exclusionCounts, rel, "total-bytes-limit");
        continue;
      }
      bytesRead += preview.size;
      const frontmatter = mediaType === "text/markdown" ? parseFrontmatter(preview.text) : { warnings: [] };
      warnings.push(...frontmatter.warnings.map((warning) => `${rel}: ${warning}`));
      let searchableText: string | undefined;
      if (mediaType === "application/vnd.obsidian.canvas+json") {
        const canvas = extractCanvasText(preview.text);
        searchableText = canvas.searchableText;
        if (canvas.warning) warnings.push(`${rel}: ${canvas.warning}`);
      }
      const metadata = frontmatter.metadata;
      const document: ScannedDocument = {
        id: stableDocumentId(idKey, rel),
        title: titleFor(rel, metadata),
        mediaType,
        text: preview.text,
        sourceHash: sha256Base64Url(preview.text),
        modifiedAt: new Date(preview.mtimeMs).toISOString(),
        relativePath: rel,
        absolutePath: candidate
      };
      if (metadata) document.metadata = metadata;
      if (searchableText) document.searchableText = searchableText;
      documents.push(document);
    }
  }

  await visit(canonicalRoot);
  documents.sort((a, b) => a.id.localeCompare(b.id));
  return {
    vaultRoot: canonicalRoot,
    vaultId,
    documents,
    filesSeen,
    filesIncluded: documents.length,
    bytesRead,
    completedAt: new Date().toISOString(),
    warnings,
    exclusions,
    exclusionCounts,
    limits
  };
}
