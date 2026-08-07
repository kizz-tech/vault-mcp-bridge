/** Limits shared by the publisher, server and MCP adapter. Keep these small
 * until a production storage/quota policy is explicitly designed. */
export const LIMITS = Object.freeze({
  maxQueryChars: 512,
  maxResults: 10,
  maxFetchedTextBytes: 256 * 1024,
  maxDocumentTextBytes: 256 * 1024,
  maxSnapshotDocuments: 5_000,
  maxSnapshotBytes: 16 * 1024 * 1024,
  maxMetadataKeys: 64,
  maxMetadataArrayItems: 64,
  maxTitleChars: 512,
  maxIdChars: 256,
  maxPairCodeChars: 128,
  maxRequestNonceChars: 256
} as const);

// Named aliases make limits convenient in adapters while retaining one source
// of truth for schema validation.
export const MAX_QUERY_CHARS = LIMITS.maxQueryChars;
export const MAX_RESULTS = LIMITS.maxResults;
export const MAX_FETCHED_TEXT_BYTES = LIMITS.maxFetchedTextBytes;
export const MAX_DOCUMENT_TEXT_BYTES = LIMITS.maxDocumentTextBytes;
export const MAX_SNAPSHOT_DOCUMENTS = LIMITS.maxSnapshotDocuments;
export const MAX_SNAPSHOT_BYTES = LIMITS.maxSnapshotBytes;

export const CONTRACT_VERSION = 1 as const;

/** OAuth scope required by both read-only MCP tools. */
export const MCP_READ_SCOPE = "vault:read" as const;

export type MediaType =
  | "text/markdown"
  | "application/vnd.obsidian.canvas+json"
  | "application/vnd.obsidian.base+yaml";

export const MEDIA_TYPES = [
  "text/markdown",
  "application/vnd.obsidian.canvas+json",
  "application/vnd.obsidian.base+yaml"
] as const satisfies readonly MediaType[];
