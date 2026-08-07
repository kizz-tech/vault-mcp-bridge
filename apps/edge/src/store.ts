import type { EdgeStore } from "./types.js";

export const createMemoryStore = (): EdgeStore => ({
  installations: new Map(),
  clients: new Map(),
  authorizationCodes: new Map(),
  refreshTokens: new Map(),
  ownerSessions: new Map(),
  revokedAccessJtis: new Map(),
  credentialLeases: new Map(),
  installationIdempotency: new Map(),
  isDurable: false,
});

/** Remove expired, one-use records without touching active installations. */
export const pruneStore = (store: EdgeStore, now: number): void => {
  for (const [hash, record] of store.authorizationCodes) {
    if (record.expiresAt <= now || record.consumedAt !== undefined) store.authorizationCodes.delete(hash);
  }
  for (const [hash, record] of store.refreshTokens) {
    if (record.expiresAt <= now || record.revokedAt !== undefined) store.refreshTokens.delete(hash);
  }
  for (const [hash, session] of store.ownerSessions) {
    if (session.expiresAt <= now) store.ownerSessions.delete(hash);
  }
  for (const [leaseId, lease] of store.credentialLeases) {
    if (lease.expiresAt <= now) store.credentialLeases.delete(leaseId);
  }
  for (const [jti, expiresAt] of store.revokedAccessJtis) {
    if (expiresAt <= now) store.revokedAccessJtis.delete(jti);
  }
  for (const [keyHash, entry] of store.installationIdempotency) {
    if (!store.installations.has(entry.installationId)) store.installationIdempotency.delete(keyHash);
  }
};
