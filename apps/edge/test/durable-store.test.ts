import { afterEach, describe, expect, it } from "vitest";
import { randomBytes } from "node:crypto";
import { chmod, mkdtemp, readFile, readdir, rm, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { DurableEdgeStore, DurableEdgeStoreError } from "../src/durable-store.js";
import { DurableCredentialVault, DurableCredentialVaultError } from "../src/durable-credential-vault.js";
import type { SecretReference } from "@vault-mcp-bridge/contracts";

const workspaces: string[] = [];

const temporaryWorkspace = async (): Promise<string> => {
  const directory = await mkdtemp(join(tmpdir(), "vmb-edge-durable-"));
  workspaces.push(directory);
  return directory;
};

afterEach(async () => {
  while (workspaces.length) await rm(workspaces.pop() as string, { recursive: true, force: true });
});

const installation = {
  installationId: "inst_fixture",
  ownerId: "owner_fixture",
  vaultId: "vault_fixture",
  mode: "self-hosted" as const,
  status: "ready" as const,
  providerResourceId: "provider_fixture",
  endpointBundle: {},
  createdAt: "2026-01-01T00:00:00.000Z",
  updatedAt: "2026-01-01T00:00:00.000Z",
};

const reference = (id: string): SecretReference => ({ provider: "remote-file", id });

describe("DurableEdgeStore", () => {
  it("round-trips durable maps and intentionally drops credential leases", async () => {
    const directory = await temporaryWorkspace();
    const filePath = join(directory, "edge-state.json");
    const store = new DurableEdgeStore(filePath);
    store.installations.set(installation.installationId, installation);
    store.clients.set("client_fixture", {
      clientId: "client_fixture",
      installationId: installation.installationId,
      redirectUris: ["http://127.0.0.1/callback"],
      grantTypes: ["authorization_code"],
      responseTypes: ["code"],
      tokenEndpointAuthMethod: "none",
      createdAt: "2026-01-01T00:00:00.000Z",
    });
    store.authorizationCodes.set("code_hash", {
      codeHash: "code_hash",
      installationId: installation.installationId,
      ownerId: installation.ownerId,
      clientId: "client_fixture",
      redirectUri: "http://127.0.0.1/callback",
      codeChallenge: "challenge",
      codeChallengeMethod: "S256",
      scope: "vault:read",
      resource: "https://mcp.example.test/mcp",
      createdAt: 1,
      expiresAt: 2,
    });
    store.refreshTokens.set("refresh_hash", {
      tokenHash: "refresh_hash",
      installationId: installation.installationId,
      ownerId: installation.ownerId,
      clientId: "client_fixture",
      scope: "vault:read",
      resource: "https://mcp.example.test/mcp",
      createdAt: 1,
      expiresAt: 2,
    });
    store.ownerSessions.set("session_hash", { sessionHash: "session_hash", ownerId: installation.ownerId, createdAt: 1, expiresAt: 2 });
    store.revokedAccessJtis.set("jti_fixture", 10);
    store.installationIdempotency.set("idempotency_hash", {
      keyHash: "idempotency_hash",
      ownerId: installation.ownerId,
      vaultId: installation.vaultId,
      installationId: installation.installationId,
      createdAt: 1,
    });
    // A lease may contain a KeyObject and must never reach the serialized envelope.
    store.credentialLeases.set("lease_fixture", { serverPrivateKey: { export: () => "private" } } as never);
    await store.flush();

    const reloaded = new DurableEdgeStore(filePath);
    expect(reloaded.isDurable).toBe(true);
    expect(reloaded.installations.get(installation.installationId)).toEqual(installation);
    expect(reloaded.clients.has("client_fixture")).toBe(true);
    expect(reloaded.clients.get("client_fixture")?.revocationEpoch).toBe(0);
    expect(reloaded.authorizationCodes.has("code_hash")).toBe(true);
    expect(reloaded.refreshTokens.has("refresh_hash")).toBe(true);
    expect(reloaded.ownerSessions.has("session_hash")).toBe(true);
    expect(reloaded.revokedAccessJtis.get("jti_fixture")).toBe(10);
    expect(reloaded.installationIdempotency.has("idempotency_hash")).toBe(true);
    expect(reloaded.credentialLeases.size).toBe(0);
    expect((await stat(filePath)).mode & 0o777).toBe(0o600);
    expect((await readFile(filePath, "utf8")).includes("serverPrivateKey")).toBe(false);
  });

  it("fails closed for corruption and unsupported newer schema versions", async () => {
    const directory = await temporaryWorkspace();
    const filePath = join(directory, "edge-state.json");
    await writeFile(filePath, "not-json", { mode: 0o600 });
    expect(() => new DurableEdgeStore(filePath)).toThrow(DurableEdgeStoreError);
    await writeFile(filePath, JSON.stringify({ schemaVersion: 999 }), { mode: 0o600 });
    expect(() => new DurableEdgeStore(filePath)).toThrowError(/newer/u);
  });

  it("serializes concurrent flushes atomically and leaves no temporary files", async () => {
    const directory = await temporaryWorkspace();
    const filePath = join(directory, "edge-state.json");
    const store = new DurableEdgeStore(filePath);
    await Promise.all(Array.from({ length: 32 }, (_, index) => {
      store.revokedAccessJtis.set(`jti_${index}`, index);
      return store.flush();
    }));
    const reloaded = new DurableEdgeStore(filePath);
    expect(reloaded.revokedAccessJtis.size).toBe(32);
    expect((await readdir(directory)).filter((name) => name.endsWith(".tmp"))).toEqual([]);
  });
});

describe("DurableCredentialVault", () => {
  it("encrypts values, survives restart, and flushes every mutation", async () => {
    const directory = await temporaryWorkspace();
    const filePath = join(directory, "credentials.json");
    const key = randomBytes(32);
    const first = new DurableCredentialVault(filePath, key);
    const tunnel = reference("tunnel_fixture");
    const mtls = reference("mtls_fixture");
    await first.put(tunnel, "super-secret-tunnel");
    await first.put(mtls, "super-secret-mtls");
    const encrypted = await readFile(filePath, "utf8");
    expect(encrypted).not.toContain("super-secret");
    expect(JSON.stringify(first)).not.toContain("super-secret");
    expect((JSON.parse(encrypted) as { entries: { nonce: string }[] }).entries.every((entry) => entry.nonce.length > 0)).toBe(true);
    expect((await stat(filePath)).mode & 0o777).toBe(0o600);

    const restarted = new DurableCredentialVault(filePath, key);
    expect(await restarted.get(tunnel)).toBe("super-secret-tunnel");
    expect(await restarted.get(mtls)).toBe("super-secret-mtls");
    await restarted.revoke(tunnel);
    expect(await new DurableCredentialVault(filePath, key).get(tunnel)).toBeNull();
  });

  it("rejects key mismatch, tampering, and insecure key files", async () => {
    const directory = await temporaryWorkspace();
    const filePath = join(directory, "credentials.json");
    const key = randomBytes(32);
    await new DurableCredentialVault(filePath, key).put(reference("secret_fixture"), "plaintext-must-not-leak");
    expect(() => new DurableCredentialVault(filePath, randomBytes(32))).toThrow(DurableCredentialVaultError);
    const parsed = JSON.parse(await readFile(filePath, "utf8")) as { entries: { ciphertext: string }[] };
    parsed.entries[0]!.ciphertext = `${parsed.entries[0]!.ciphertext.slice(0, -1)}${parsed.entries[0]!.ciphertext.endsWith("A") ? "B" : "A"}`;
    await writeFile(filePath, JSON.stringify(parsed), { mode: 0o600 });
    try {
      new DurableCredentialVault(filePath, key);
      throw new Error("tampered credential vault was accepted");
    } catch (error) {
      expect(error).toBeInstanceOf(DurableCredentialVaultError);
      expect(error).toHaveProperty("code", "corrupt");
    }

    const keyFile = join(directory, "master.key");
    await writeFile(keyFile, key, { mode: 0o644 });
    expect(() => new DurableCredentialVault(join(directory, "from-key-file.json"), { masterKeyFile: keyFile })).toThrow(/0400|0600/u);
    await chmod(keyFile, 0o600);
    await expect(new DurableCredentialVault(join(directory, "from-key-file.json"), { masterKeyFile: keyFile }).put(reference("key_file_fixture"), "key-file-secret")).resolves.toBeUndefined();
  });

  it("serializes concurrent mutations without losing values", async () => {
    const directory = await temporaryWorkspace();
    const filePath = join(directory, "credentials.json");
    const key = randomBytes(32);
    const vault = new DurableCredentialVault(filePath, key);
    const refs = Array.from({ length: 20 }, (_, index) => reference(`credential_${index}`));
    await Promise.all(refs.map((ref, index) => vault.put(ref, `value_${index}`)));
    const restarted = new DurableCredentialVault(filePath, key);
    for (const [index, ref] of refs.entries()) expect(await restarted.get(ref)).toBe(`value_${index}`);
  });
});
