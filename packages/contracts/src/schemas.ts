import { z } from "zod";
import { sha256Base64Url } from "./crypto.js";
import { CONTRACT_VERSION, LIMITS, MEDIA_TYPES } from "./constants.js";
import type { MediaType } from "./constants.js";

const OPAQUE_ID_RE = /^[A-Za-z0-9_-]{16,256}$/;
const HASH_RE = /^[A-Za-z0-9_-]{43}$/;

export const OpaqueIdSchema = z.string().regex(OPAQUE_ID_RE, "Expected an opaque identifier");
export type OpaqueId = z.infer<typeof OpaqueIdSchema>;

/** Normalize a human-entered alias consistently across agent and server. */
export function normalizeVaultId(value: string): OpaqueId {
  const candidate = value.trim();
  if (OPAQUE_ID_RE.test(candidate)) return candidate;
  if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u.test(candidate)) {
    throw new TypeError("Vault id contains unsupported characters");
  }
  return OpaqueIdSchema.parse(`vault_${sha256Base64Url(`vault-id:${candidate}`)}`);
}

const ScalarSchema = z.union([z.string(), z.number().finite(), z.boolean(), z.null()]);
export const MetadataValueSchema = z.union([
  ScalarSchema,
  z.array(ScalarSchema).max(LIMITS.maxMetadataArrayItems)
]);
export const MetadataSchema = z
  .record(z.string().min(1).max(128), MetadataValueSchema)
  .refine((value) => Object.keys(value).length <= LIMITS.maxMetadataKeys, {
    message: "Too many metadata keys"
  });
export type Metadata = z.infer<typeof MetadataSchema>;

const IsoDateSchema = z.string().refine((value) => {
  if (!/^\d{4}-\d{2}-\d{2}T/.test(value)) return false;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed);
}, "Expected an ISO-8601 timestamp");

const BoundedTextSchema = z.string().superRefine((value, context) => {
  if (Buffer.byteLength(value, "utf8") > LIMITS.maxDocumentTextBytes) {
    context.addIssue({
      code: "custom",
      message: `Document text exceeds ${LIMITS.maxDocumentTextBytes} bytes`
    });
  }
});

export const MediaTypeSchema = z.enum(MEDIA_TYPES);

/** Remote-safe document. It intentionally has no filesystem path fields. */
export const SnapshotDocumentSchema = z
  .object({
    id: OpaqueIdSchema,
    title: z.string().min(1).max(LIMITS.maxTitleChars),
    mediaType: MediaTypeSchema,
    text: BoundedTextSchema,
    sourceHash: z.string().regex(HASH_RE, "Expected a base64url SHA-256 hash"),
    modifiedAt: IsoDateSchema,
    metadata: MetadataSchema.optional()
  })
  .strict()
  .superRefine((document, context) => {
    if (sha256Base64Url(document.text) !== document.sourceHash) {
      context.addIssue({ code: "custom", path: ["sourceHash"], message: "sourceHash does not match text" });
    }
  });

export type SnapshotDocument = z.infer<typeof SnapshotDocumentSchema>;
/** Alias used by scanner/server code when a document is already remote-safe. */
export type VaultDocument = SnapshotDocument;

const DigestSchema = z.string().regex(HASH_RE, "Expected a base64url SHA-256 digest");

export const SnapshotSchema = z
  .object({
    version: z.literal(CONTRACT_VERSION),
    snapshotId: z.string().uuid(),
    vaultId: OpaqueIdSchema,
    generation: z.number().int().nonnegative(),
    createdAt: IsoDateSchema,
    documents: z.array(SnapshotDocumentSchema).max(LIMITS.maxSnapshotDocuments),
    digest: DigestSchema
  })
  .strict();
export type Snapshot = z.infer<typeof SnapshotSchema>;

export const ScanLimitsSchema = z
  .object({
    maxFiles: z.number().int().positive().max(LIMITS.maxSnapshotDocuments).optional(),
    maxFileBytes: z.number().int().positive().max(LIMITS.maxDocumentTextBytes).optional(),
    maxTotalBytes: z.number().int().positive().max(LIMITS.maxSnapshotBytes).optional()
  })
  .strict();

/** Local-only agent configuration. `vaultRoot` must never cross the API boundary. */
export const AgentConfigSchema = z
  .object({
    version: z.literal(CONTRACT_VERSION),
    agentId: OpaqueIdSchema,
    vaultId: OpaqueIdSchema,
    vaultRoot: z.string().min(1).max(4096),
    serverUrl: z.string().url(),
    deviceId: OpaqueIdSchema.optional(),
    readOnly: z.literal(true).default(true),
    syncIntervalSeconds: z.number().int().min(5).max(86_400).default(300),
    include: z.array(z.string().min(1).max(1024)).max(128).default(["**/*.md", "**/*.canvas", "**/*.base"]),
    exclude: z.array(z.string().min(1).max(1024)).max(256).default([]),
    limits: ScanLimitsSchema.optional()
  })
  .strict();
export type AgentConfig = z.infer<typeof AgentConfigSchema>;

/** Base64url-encoded Ed25519 SPKI DER public key (no PEM/newlines). */
const PublicKeySchema = z.string().regex(/^[A-Za-z0-9_-]+$/).min(32).max(4096);

export const PairDeviceRequestSchema = z
  .object({
    version: z.literal(CONTRACT_VERSION),
    pairCode: z.string().min(8).max(LIMITS.maxPairCodeChars),
    agentId: OpaqueIdSchema,
    publicKey: PublicKeySchema,
    vaultId: OpaqueIdSchema.optional(),
    label: z.string().min(1).max(128).optional()
  })
  .strict();
export type PairDeviceRequest = z.infer<typeof PairDeviceRequestSchema>;

export const PairDeviceResponseSchema = z
  .object({
    version: z.literal(CONTRACT_VERSION),
    deviceId: OpaqueIdSchema,
    vaultId: OpaqueIdSchema,
    serverUrl: z.string().url(),
    expiresAt: z.union([IsoDateSchema, z.null()])
  })
  .strict();
export type PairDeviceResponse = z.infer<typeof PairDeviceResponseSchema>;

export const UploadReceiptSchema = z
  .object({
    version: z.literal(CONTRACT_VERSION),
    accepted: z.boolean(),
    idempotent: z.boolean(),
    snapshotId: z.string().uuid(),
    vaultId: OpaqueIdSchema,
    generation: z.number().int().nonnegative(),
    documentCount: z.number().int().nonnegative().max(LIMITS.maxSnapshotDocuments),
    digest: DigestSchema,
    receivedAt: IsoDateSchema,
    reason: z.string().max(512).optional()
  })
  .strict();
export type UploadReceipt = z.infer<typeof UploadReceiptSchema>;

export const PublisherStatusResponseSchema = z
  .object({
    vaultId: OpaqueIdSchema,
    active: z.union([
      z.object({
        snapshotId: z.string().uuid(),
        generation: z.number().int().nonnegative(),
        activatedAt: z.number().int().nonnegative()
      }).strict(),
      z.null()
    ]),
    documentCount: z.number().int().nonnegative().max(LIMITS.maxSnapshotDocuments)
  })
  .strict();
export type PublisherStatusResponse = z.infer<typeof PublisherStatusResponseSchema>;

/** OpenAI MCP tool input/output contracts. Keep search input exactly `{query}`. */
export const SearchInputSchema = z.object({ query: z.string().min(1).max(LIMITS.maxQueryChars) }).strict();
export type SearchInput = z.infer<typeof SearchInputSchema>;

/** Empty means “no safe, user-openable citation URL is available yet”. */
export const CitationUrlSchema = z.union([
  z.literal(""),
  z.string().url().refine((value) => new URL(value).protocol === "https:", "Citation URL must use HTTPS")
]);
export const SearchResultSchema = z.object({ id: OpaqueIdSchema, title: z.string(), url: CitationUrlSchema }).strict();
export type SearchResult = z.infer<typeof SearchResultSchema>;
export const SearchOutputSchema = z.object({ results: z.array(SearchResultSchema).max(LIMITS.maxResults) }).strict();
export type SearchOutput = z.infer<typeof SearchOutputSchema>;

export const FetchInputSchema = z.object({ id: OpaqueIdSchema }).strict();
export type FetchInput = z.infer<typeof FetchInputSchema>;
export const FetchOutputSchema = z
  .object({
    id: OpaqueIdSchema,
    title: z.string(),
    text: z.string().superRefine((value, context) => {
      if (Buffer.byteLength(value, "utf8") > LIMITS.maxFetchedTextBytes) {
        context.addIssue({ code: "custom", message: "Fetched text exceeds the response limit" });
      }
    }),
    url: CitationUrlSchema,
    metadata: MetadataSchema.optional()
  })
  .strict();
export type FetchOutput = z.infer<typeof FetchOutputSchema>;

// Keep imports of this module side-effect free. This reference also catches an
// accidental future change where MediaType ceases to be the protocol union.
export type { MediaType };
