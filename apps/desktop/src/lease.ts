import { createDecipheriv, createHash, createPublicKey, diffieHellman, generateKeyPairSync, hkdfSync, type KeyObject } from "node:crypto";
import { chmod, mkdir, open, unlink } from "node:fs/promises";
import { join } from "node:path";

import type { CredentialKind, CredentialLeaseResponse, EdgeCredentialPort, MaterializedCredential } from "./edge-client.js";

export interface LeaseUploader {
  ensureDirectory(remoteDirectory: string): Promise<void>;
  upload(localPath: string, remotePath: string): Promise<void>;
}

export interface MaterializeInput {
  readonly installationId: string;
  readonly remoteDirectory: string;
  readonly secretName: string;
  readonly kind: CredentialKind;
}

export interface MaterializedSecretReceipt {
  readonly kind: CredentialKind;
  readonly remotePath: string;
  readonly leaseId: string;
}

export interface EphemeralCredential {
  readonly leaseId: string;
  readonly value: string;
}

const ALGORITHM = "X25519-HKDF-SHA256-AES-256-GCM" as const;

function safeOpaque(value: string, field: string): string {
  if (!/^[A-Za-z0-9_-]{1,256}$/u.test(value)) throw new Error(`${field}_invalid`);
  return value;
}

function remotePath(value: string): string {
  if (!value.startsWith("/") || value.length > 1024 || /[\0\r\n]/u.test(value) || value.split("/").some((part) => part === "..")) throw new Error("remote_path_invalid");
  return value.replace(/\/+/gu, "/").replace(/\/$/u, "");
}

function encoded(value: string): Buffer {
  if (!/^[A-Za-z0-9_-]+$/u.test(value)) throw new Error("credential_envelope_invalid");
  return Buffer.from(value, "base64url");
}

function deriveKey(privateKey: KeyObject, serverPublicKey: string, installationId: string, leaseId: string): Buffer {
  const publicDer = encoded(serverPublicKey);
  const serverKey = createPublicKey({ key: publicDer, format: "der", type: "spki" });
  const shared = diffieHellman({ privateKey, publicKey: serverKey });
  const salt = createHash("sha256").update(`${installationId}:${leaseId}`, "utf8").digest();
  return Buffer.from(hkdfSync("sha256", shared, salt, Buffer.from("vault-bridge/credential-lease", "utf8"), 32));
}

function decryptCredential(input: {
  installationId: string;
  kind: CredentialKind;
  lease: CredentialLeaseResponse;
  materialized: MaterializedCredential;
  privateKey: KeyObject;
}): string {
  if (input.materialized.algorithm !== ALGORITHM || input.lease.algorithm !== ALGORITHM) throw new Error("credential_envelope_algorithm_invalid");
  if (input.materialized.leaseId !== input.lease.leaseId || input.materialized.serverPublicKey !== input.lease.serverPublicKey || input.materialized.kind !== input.kind) throw new Error("credential_envelope_binding_invalid");
  const key = deriveKey(input.privateKey, input.materialized.serverPublicKey, input.installationId, input.lease.leaseId);
  const nonce = encoded(input.materialized.nonce);
  const tag = encoded(input.materialized.tag);
  if (nonce.byteLength !== 12 || tag.byteLength !== 16) throw new Error("credential_envelope_invalid");
  const decipher = createDecipheriv("aes-256-gcm", key, nonce);
  decipher.setAAD(Buffer.from(`${input.installationId}:${input.lease.leaseId}:${input.kind}`, "utf8"));
  decipher.setAuthTag(tag);
  try {
    const plaintext = Buffer.concat([decipher.update(encoded(input.materialized.ciphertext)), decipher.final()]);
    if (plaintext.byteLength === 0 || plaintext.byteLength > 256 * 1024) throw new Error("credential_empty");
    return plaintext.toString("utf8");
  } catch {
    throw new Error("credential_decryption_failed");
  }
}

/**
 * Redeems one encrypted edge lease, writes its plaintext only to a private
 * 0600 staging file, uploads it through the bounded SFTP adapter, then erases
 * the local file in a finally block.  No plaintext is returned or persisted.
 */
export class CredentialLeaseMaterializer {
  public constructor(
    private readonly edge: EdgeCredentialPort,
    private readonly uploader: LeaseUploader,
    private readonly stagingRoot: string,
    private readonly now: () => number = Date.now
  ) {}

  /** Redeem to a caller-owned ephemeral value (used only for local keychain storage). */
  async redeemInMemory(installationId: string, kind: CredentialKind): Promise<EphemeralCredential> {
    const id = safeOpaque(installationId, "installation_id");
    const pair = generateKeyPairSync("x25519");
    const publicKey = createPublicKey(pair.publicKey).export({ format: "der", type: "spki" }).toString("base64url");
    const lease = await this.edge.createCredentialLease(id, kind, publicKey);
    const materialized = await this.edge.redeemCredentialLease(lease.leaseId);
    return { leaseId: lease.leaseId, value: decryptCredential({ installationId: id, kind, lease, materialized, privateKey: pair.privateKey }) };
  }

  async materializeAndUpload(input: MaterializeInput): Promise<MaterializedSecretReceipt> {
    const installationId = safeOpaque(input.installationId, "installation_id");
    const secretName = safeOpaque(input.secretName, "secret_name");
    const directory = remotePath(input.remoteDirectory);
    const pair = generateKeyPairSync("x25519");
    const publicKey = createPublicKey(pair.publicKey).export({ format: "der", type: "spki" }).toString("base64url");
    const lease = await this.edge.createCredentialLease(installationId, input.kind, publicKey);
    const materialized = await this.edge.redeemCredentialLease(lease.leaseId);
    const value = decryptCredential({ installationId, kind: input.kind, lease, materialized, privateKey: pair.privateKey });
    await mkdir(this.stagingRoot, { recursive: true, mode: 0o700 });
    const nonce = createHash("sha256").update(`${installationId}:${lease.leaseId}:${this.now()}`, "utf8").digest("hex").slice(0, 24);
    const localPath = join(this.stagingRoot, `secret-${nonce}`);
    const destination = `${directory}/${secretName}`;
    let handle: Awaited<ReturnType<typeof open>> | undefined;
    try {
      handle = await open(localPath, "wx", 0o600);
      await handle.writeFile(value, { encoding: "utf8" });
      await handle.sync();
      await chmod(localPath, 0o600);
      await this.uploader.ensureDirectory(directory);
      await this.uploader.upload(localPath, destination);
      return { kind: input.kind, remotePath: destination, leaseId: lease.leaseId };
    } finally {
      if (handle) await handle.close().catch(() => undefined);
      await unlink(localPath).catch(() => undefined);
    }
  }
}

export { decryptCredential };
