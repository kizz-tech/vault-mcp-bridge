import { createPrivateKey } from "node:crypto";

import { describe, expect, it } from "vitest";

import {
  MacPublisherIdentityProvider,
  publisherIdentityReference
} from "../src/publisher-identity.js";
import type { SecretStore } from "../src/secret-store.js";

class MemorySecretStore implements SecretStore {
  readonly values = new Map<string, string>();

  async put(reference: string, value: string): Promise<void> {
    this.values.set(reference, value);
  }

  async get(reference: string): Promise<string | null> {
    return this.values.get(reference) ?? null;
  }

  async remove(reference: string): Promise<void> {
    this.values.delete(reference);
  }
}

const installationId = "inst_1234567890abcdef1234567890abcdef";

describe("Mac publisher identity", () => {
  it("generates an ECDSA P-256 PKCS#8 key and a PEM CSR", async () => {
    const secrets = new MemorySecretStore();
    const provider = new MacPublisherIdentityProvider({ secrets });

    const identity = await provider.ensure(installationId);

    expect(identity.csr).toMatch(/^-----BEGIN CERTIFICATE REQUEST-----[\s\S]+-----END CERTIFICATE REQUEST-----\s*$/u);
    expect(identity.privateKey).toMatch(/^-----BEGIN PRIVATE KEY-----[\s\S]+-----END PRIVATE KEY-----\s*$/u);
    const key = createPrivateKey({ key: identity.privateKey, format: "pem", type: "pkcs8" });
    expect(key.asymmetricKeyType).toBe("ec");
    expect(key.asymmetricKeyDetails?.namedCurve).toBe("prime256v1");

    const encodedCsr = identity.csr
      .replace("-----BEGIN CERTIFICATE REQUEST-----", "")
      .replace("-----END CERTIFICATE REQUEST-----", "")
      .replace(/\s/gu, "");
    expect(Buffer.from(encodedCsr, "base64")[0]).toBe(0x30);
    expect(secrets.values.has(publisherIdentityReference(installationId))).toBe(true);
  });

  it("reuses the exact key and CSR across retries and provider restarts", async () => {
    const secrets = new MemorySecretStore();
    const first = await new MacPublisherIdentityProvider(secrets).ensure(installationId);
    const retry = await new MacPublisherIdentityProvider(secrets).ensure(installationId);
    const concurrent = await Promise.all([
      new MacPublisherIdentityProvider(secrets).ensure(installationId),
      new MacPublisherIdentityProvider(secrets).ensure(installationId)
    ]);

    expect(retry).toEqual(first);
    expect(concurrent[0]).toEqual(first);
    expect(concurrent[1]).toEqual(first);
    expect(secrets.values.size).toBe(1);
  });

  it("keeps identity records installation-scoped and rejects invalid ids", async () => {
    const secrets = new MemorySecretStore();
    const provider = new MacPublisherIdentityProvider(secrets);
    const otherInstallation = "inst_fedcba9876543210fedcba9876543210";

    const first = await provider.ensure(installationId);
    const second = await provider.ensure(otherInstallation);
    expect(first.privateKey).not.toBe(second.privateKey);
    expect(publisherIdentityReference(installationId)).not.toBe(publisherIdentityReference(otherInstallation));
    await expect(provider.ensure("too-short")).rejects.toThrow("publisher_installation_id_invalid");
    await expect(provider.ensure("inst_with invalid characters")).rejects.toThrow("publisher_installation_id_invalid");
  });

  it("fails closed on malformed persisted PEM metadata", async () => {
    const secrets = new MemorySecretStore();
    const reference = publisherIdentityReference(installationId);
    await secrets.put(reference, JSON.stringify({
      version: 1,
      installationId,
      csr: "-----BEGIN CERTIFICATE REQUEST-----\nMA==\n-----END CERTIFICATE REQUEST-----\n",
      privateKey: "-----BEGIN PRIVATE KEY-----\nMA==\n-----END PRIVATE KEY-----\n"
    }));

    await expect(new MacPublisherIdentityProvider(secrets).ensure(installationId)).rejects.toThrow("publisher_csr_invalid");
  });
});
