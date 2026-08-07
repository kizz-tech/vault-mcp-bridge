import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import { SafeStorageSecretStore, SecretStoreUnavailableError, type SafeStorageLike } from "../src/secret-store.js";

class FakeSafeStorage implements SafeStorageLike {
  constructor(private available = true) {}
  isEncryptionAvailable(): boolean { return this.available; }
  encryptString(value: string): Buffer { return Buffer.from(`cipher:${value}`, "utf8"); }
  decryptString(value: Buffer): string {
    const decoded = value.toString("utf8");
    if (!decoded.startsWith("cipher:")) throw new Error("corrupt");
    return decoded.slice("cipher:".length);
  }
}

describe("safe storage secret references", () => {
  it("encrypts values and never writes cleartext", async () => {
    const directory = await mkdtemp(join(tmpdir(), "vault-bridge-secrets-"));
    const file = join(directory, "secrets.json");
    try {
      const store = new SafeStorageSecretStore(file, new FakeSafeStorage());
      await store.put("tunnel_ref", "top-secret");
      expect(await store.get("tunnel_ref")).toBe("top-secret");
      expect(await readFile(file, "utf8")).not.toContain("top-secret");
      await store.remove("tunnel_ref");
      expect(await store.get("tunnel_ref")).toBeNull();
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("fails closed when platform encryption is unavailable", async () => {
    const directory = await mkdtemp(join(tmpdir(), "vault-bridge-secrets-"));
    try {
      const store = new SafeStorageSecretStore(join(directory, "secrets.json"), new FakeSafeStorage(false));
      await expect(store.put("ref", "secret")).rejects.toBeInstanceOf(SecretStoreUnavailableError);
      await expect(store.get("ref")).rejects.toBeInstanceOf(SecretStoreUnavailableError);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("rejects path-like or unbounded references", async () => {
    const store = new SafeStorageSecretStore("/tmp/not-used", new FakeSafeStorage());
    await expect(store.put("../secret", "value")).rejects.toThrow("Invalid secret reference");
    await expect(store.put("ref", "")).rejects.toThrow("Invalid secret value");
  });
});
