import { createCipheriv, createHash, diffieHellman, generateKeyPairSync, hkdfSync } from "node:crypto";
import { describe, expect, it } from "vitest";

import { decryptCredential } from "../src/lease.js";

describe("credential lease decryption", () => {
  it("binds the envelope to installation, lease and kind", () => {
    const installationId = "inst_test_123456";
    const leaseId = "lease_test_123456";
    const kind = "tunnel" as const;
    const client = generateKeyPairSync("x25519");
    const server = generateKeyPairSync("x25519");
    const clientPublicKey = Buffer.from(client.publicKey.export({ format: "der", type: "spki" })).toString("base64url");
    const serverPublicKey = Buffer.from(server.publicKey.export({ format: "der", type: "spki" })).toString("base64url");
    const shared = diffieHellman({ privateKey: server.privateKey, publicKey: client.publicKey });
    const salt = createHash("sha256").update(`${installationId}:${leaseId}`).digest();
    const key = Buffer.from(hkdfSync("sha256", shared, salt, Buffer.from("vault-bridge/credential-lease"), 32));
    const nonce = Buffer.alloc(12, 7);
    const cipher = createCipheriv("aes-256-gcm", key, nonce);
    cipher.setAAD(Buffer.from(`${installationId}:${leaseId}:${kind}`));
    const ciphertext = Buffer.concat([cipher.update("tunnel-secret"), cipher.final()]);
    const materialized = {
      leaseId,
      kind,
      ciphertext: ciphertext.toString("base64url"),
      nonce: nonce.toString("base64url"),
      tag: cipher.getAuthTag().toString("base64url"),
      serverPublicKey,
      algorithm: "X25519-HKDF-SHA256-AES-256-GCM" as const
    };
    const lease = { leaseId, serverPublicKey, expiresAt: new Date(Date.now() + 60_000).toISOString(), algorithm: materialized.algorithm };
    expect(decryptCredential({ installationId, kind, lease, materialized, privateKey: client.privateKey })).toBe("tunnel-secret");
    expect(() => decryptCredential({ installationId: "other_installation", kind, lease, materialized, privateKey: client.privateKey })).toThrow();
    expect(clientPublicKey).toMatch(/^[A-Za-z0-9_-]+$/u);
  });
});
