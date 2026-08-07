import { canonicalJson, sha256Base64Url } from "./crypto.js";
import { SnapshotDocumentSchema, type Snapshot, type SnapshotDocument } from "./schemas.js";

type SnapshotDigestInput = Omit<Snapshot, "digest">;

function canonicalMetadata(metadata: SnapshotDocument["metadata"]): SnapshotDocument["metadata"] {
  if (!metadata) return undefined;
  return Object.fromEntries(
    Object.entries(metadata)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([key, value]) => [key, Array.isArray(value) ? [...value] : value])
  );
}

/**
 * Compute a digest from every immutable snapshot field and content hashes,
 * sorted by opaque document id. Full text is covered by each document's
 * sourceHash and is not duplicated in this canonical envelope.
 */
export function computeSnapshotDigest(input: SnapshotDigestInput): string {
  const envelope = {
    version: input.version,
    snapshotId: input.snapshotId,
    vaultId: input.vaultId,
    generation: input.generation,
    createdAt: input.createdAt,
    documents: [...input.documents]
      .map((document) => {
        const parsed = SnapshotDocumentSchema.parse(document);
        return {
          id: parsed.id,
          title: parsed.title,
          mediaType: parsed.mediaType,
          sourceHash: parsed.sourceHash,
          modifiedAt: parsed.modifiedAt,
          metadata: canonicalMetadata(parsed.metadata)
        };
      })
      .sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0))
  };
  return sha256Base64Url(canonicalJson(envelope));
}

/** Backward-compatible short alias for callers that use `snapshotDigest`. */
export const snapshotDigest = computeSnapshotDigest;

export function verifySnapshotDigest(snapshot: Snapshot): boolean {
  try {
    return computeSnapshotDigest(snapshot) === snapshot.digest;
  } catch {
    return false;
  }
}

export function assertSourceHash(document: SnapshotDocument): void {
  const parsed = SnapshotDocumentSchema.safeParse(document);
  if (!parsed.success) {
    const mismatch = parsed.error.issues.find((issue) => issue.path[0] === "sourceHash");
    if (mismatch) throw new Error("sourceHash does not match text");
    throw parsed.error;
  }
}
