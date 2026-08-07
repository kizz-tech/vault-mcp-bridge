import {
  createCipheriv,
  createPublicKey,
  diffieHellman,
  generateKeyPairSync,
  hkdfSync,
  randomBytes,
  type KeyObject,
} from "node:crypto";
import { hashOpaque, iso, randomOpaque } from "./crypto.js";
import { DEFAULT_EDGE_LIMITS, type EdgeLimits } from "./limits.js";
import type { CredentialKind, CredentialLease, EdgeClock, EdgeStore } from "./types.js";

const CLIENT_KEY_MIN_BYTES = 32;
const CLIENT_KEY_MAX_BYTES = 256;
const LEASE_TTL_SECONDS = 60;

export class CredentialLeaseError extends Error {
  constructor(readonly code: "invalid_key" | "not_found" | "expired" | "owner_mismatch" | "secret_unavailable" | "capacity", message: string) {
    super(message);
    this.name = "CredentialLeaseError";
  }
}

export type CredentialLeaseResponse = {
  leaseId: string;
  serverPublicKey: string;
  expiresAt: string;
  algorithm: "X25519-HKDF-SHA256-AES-256-GCM";
};

export type MaterializedCredential = {
  leaseId: string;
  kind: CredentialKind;
  ciphertext: string;
  nonce: string;
  tag: string;
  serverPublicKey: string;
  algorithm: "X25519-HKDF-SHA256-AES-256-GCM";
};

const decodeClientPublicKey = (encoded: string): KeyObject => {
  if (!/^[A-Za-z0-9_-]+$/u.test(encoded)) throw new CredentialLeaseError("invalid_key", "client public key is invalid");
  const der = Buffer.from(encoded, "base64url");
  if (der.length < CLIENT_KEY_MIN_BYTES || der.length > CLIENT_KEY_MAX_BYTES) throw new CredentialLeaseError("invalid_key", "client public key is invalid");
  try {
    const key = createPublicKey({ key: der, format: "der", type: "spki" });
    if (key.asymmetricKeyType !== "x25519") throw new Error("wrong key type");
    return key;
  } catch {
    throw new CredentialLeaseError("invalid_key", "client public key is invalid");
  }
};

const encodePublicKey = (key: KeyObject): string => Buffer.from(key.export({ format: "der", type: "spki" })).toString("base64url");

const deriveKey = (privateKey: KeyObject, clientPublicKey: KeyObject, leaseId: string, installationId: string): Buffer => {
  const shared = diffieHellman({ privateKey, publicKey: clientPublicKey });
  const salt = Buffer.from(hashOpaque(`${installationId}:${leaseId}`), "base64url");
  return Buffer.from(hkdfSync("sha256", shared, salt, Buffer.from("vault-bridge/credential-lease", "utf8"), 32));
};

const aad = (lease: CredentialLease): Buffer => Buffer.from(`${lease.installationId}:${lease.leaseId}:${lease.kind}`, "utf8");

export const createCredentialLease = (
  store: EdgeStore,
  ownerId: string,
  installationId: string,
  kind: CredentialKind,
  clientPublicKey: string,
  now: EdgeClock = Date.now,
  ttlSeconds = LEASE_TTL_SECONDS,
  limits: EdgeLimits = DEFAULT_EDGE_LIMITS,
): CredentialLeaseResponse => {
  const createdAt = now();
  for (const [leaseId, lease] of store.credentialLeases) if (lease.expiresAt <= createdAt) store.credentialLeases.delete(leaseId);
  if (store.credentialLeases.size >= limits.maxCredentialLeases) throw new CredentialLeaseError("capacity", "edge capacity is temporarily unavailable");
  const clientKey = decodeClientPublicKey(clientPublicKey);
  const { privateKey, publicKey } = generateKeyPairSync("x25519");
  const leaseId = `lease_${randomOpaque(30)}`;
  const lease: CredentialLease = {
    leaseId,
    installationId,
    ownerId,
    kind,
    clientPublicKey,
    serverPrivateKey: privateKey,
    serverPublicKey: encodePublicKey(publicKey),
    createdAt,
    expiresAt: createdAt + ttlSeconds * 1000,
  };
  // Keep only the server private key in the lease store. The client key is
  // retained as an audit-boundary value, never logged or returned as a secret.
  void clientKey;
  store.credentialLeases.set(leaseId, lease);
  return {
    leaseId,
    serverPublicKey: lease.serverPublicKey,
    expiresAt: iso(lease.expiresAt),
    algorithm: "X25519-HKDF-SHA256-AES-256-GCM",
  };
};

export const materializeCredential = async (
  store: EdgeStore,
  ownerId: string,
  leaseId: string,
  secret: string | null,
  now: EdgeClock = Date.now,
): Promise<MaterializedCredential> => {
  const lease = store.credentialLeases.get(leaseId);
  if (!lease) throw new CredentialLeaseError("not_found", "credential lease not found");
  if (lease.ownerId !== ownerId) throw new CredentialLeaseError("owner_mismatch", "credential lease is not owned by this account");
  if (lease.expiresAt <= now()) {
    store.credentialLeases.delete(leaseId);
    throw new CredentialLeaseError("expired", "credential lease expired");
  }
  // Delete before touching the secret store: a concurrent redemption can
  // never obtain a second copy, even if vault I/O is slow or fails.
  store.credentialLeases.delete(leaseId);
  if (!secret) throw new CredentialLeaseError("secret_unavailable", "credential is unavailable");
  const clientPublicKey = decodeClientPublicKey(lease.clientPublicKey);
  const key = deriveKey(lease.serverPrivateKey, clientPublicKey, lease.leaseId, lease.installationId);
  const nonce = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, nonce);
  cipher.setAAD(aad(lease));
  const ciphertext = Buffer.concat([cipher.update(secret, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    leaseId,
    kind: lease.kind,
    ciphertext: ciphertext.toString("base64url"),
    nonce: nonce.toString("base64url"),
    tag: tag.toString("base64url"),
    serverPublicKey: lease.serverPublicKey,
    algorithm: "X25519-HKDF-SHA256-AES-256-GCM",
  };
};

export const leaseTtlSeconds = LEASE_TTL_SECONDS;
