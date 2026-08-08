import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { sha256Base64Url } from "@vault-mcp-bridge/contracts";
import { describe, expect, it, vi } from "vitest";

import { availableBytesFromDf, PrivateDesktopBackend, type PrivateDeploymentPort } from "../src/private-backend.js";
import type { SecretStore } from "../src/secret-store.js";

class MemorySecrets implements SecretStore {
  private readonly values = new Map<string, string>();
  async put(reference: string, value: string): Promise<void> { this.values.set(reference, value); }
  async get(reference: string): Promise<string | null> { return this.values.get(reference) ?? null; }
  async remove(reference: string): Promise<void> { this.values.delete(reference); }
}

describe("private secure-tunnel desktop backend", () => {
  it("parses the POSIX free-space preflight without trusting localized labels", () => {
    expect(availableBytesFromDf([
      "Filesystem 1024-blocks Used Available Capacity Mounted on",
      "/dev/vda1  52428800 12000000 40428800 23% /"
    ].join("\n"))).toBe(40_428_800 * 1024);
    expect(() => availableBytesFromDf("unexpected output")).toThrow(/capacity_check/u);
  });

  it("turns vault, SSH and OpenAI inputs into one read-only setup", async () => {
    const appDataPath = await mkdtemp(join(tmpdir(), "vmb-private-desktop-"));
    const vaultRoot = await mkdtemp(join(tmpdir(), "vmb-private-vault-"));
    const content = "# Synthetic\n";
    const deployment: PrivateDeploymentPort = {
      setup: vi.fn(async (input) => ({
        projectName: input.projectName,
        remoteDirectory: `/home/operator/.local/share/vault-bridge/installations/${input.installationId}`,
        sshHostKeyAlgorithm: "ssh-ed25519" as const
      })),
      disconnect: vi.fn(async () => undefined),
      remove: vi.fn(async () => undefined)
    };
    const backend = new PrivateDesktopBackend({
      appDataPath,
      config: { image: `ghcr.io/example/vault-bridge@sha256:${"a".repeat(64)}`, syncIntervalMinutes: 5 },
      composeTemplatePath: "/synthetic/compose.yaml",
      secretStore: new MemorySecrets(),
      scanner: {
        scan: async () => ({
          files: [{
            id: "document_synthetic_0001",
            title: "Synthetic",
            relativePath: "note.md",
            bytes: content.length,
            content,
            contentType: "markdown" as const,
            sha256: sha256Base64Url(content),
            modifiedAt: "2026-01-01T00:00:00.000Z"
          }],
          excluded: [], hidden: 0, symlinks: 0, errors: [], bytes: content.length
        })
      },
      deployment,
      tunnelVerifier: async () => undefined,
      syncer: async () => ({
        status: "uploaded",
        generation: 1,
        documentCount: 1,
        changes: { added: 1, modified: 0, removed: 0, unchanged: 0, total: 1, bytes: content.length },
        digest: "digest_synthetic_0001"
      }),
      now: () => new Date("2026-08-08T00:00:00.000Z")
    });

    await backend.initialize();
    await backend.selectVault(vaultRoot);
    await backend.configureServer({ host: "server.example.invalid", user: "operator", port: 22 });
    await backend.configureTunnel({ tunnelId: `tunnel_${"a".repeat(32)}`, apiKey: "TEST_RUNTIME_API_KEY_000000000" });
    const ready = await backend.setup();

    expect(ready).toMatchObject({
      mode: "ready",
      phase: "ready",
      tunnel: { configured: true },
      serverCopy: "active",
      mcp: { host: "Connected" }
    });
    expect(ready.sync).toMatchObject({ intervalMinutes: 5, lastResult: "published" });
    expect(await backend.getJournal()).toEqual(expect.arrayContaining([
      expect.objectContaining({ message: "Changes published", result: "published", changes: { added: 1, modified: 0, removed: 0, unchanged: 0, total: 1, bytes: content.length } })
    ]));
    expect(deployment.setup).toHaveBeenCalledOnce();
    expect(await readFile(join(appDataPath, "private-setup.json"), "utf8")).not.toContain("TEST_RUNTIME_API_KEY");

    const retained = await backend.disconnect();
    expect(retained.serverCopy).toBe("retained");
    expect(deployment.disconnect).toHaveBeenCalledOnce();

    const reconnected = await backend.setup();
    expect(reconnected.serverCopy).toBe("active");

    const removed = await backend.removeServerCopy();
    expect(removed.serverCopy).toBe("none");
    expect(deployment.remove).toHaveBeenCalledOnce();
    backend.close();
  });

  it("does not persist an unverified runtime key", async () => {
    const appDataPath = await mkdtemp(join(tmpdir(), "vmb-private-key-"));
    const secrets = new MemorySecrets();
    const backend = new PrivateDesktopBackend({
      appDataPath,
      config: { image: `ghcr.io/example/vault-bridge@sha256:${"b".repeat(64)}`, syncIntervalMinutes: 5 },
      composeTemplatePath: "/synthetic/compose.yaml",
      secretStore: secrets,
      deployment: { setup: vi.fn(), disconnect: vi.fn(), remove: vi.fn() },
      tunnelVerifier: async () => { throw new Error("rejected"); }
    });
    await expect(backend.configureTunnel({
      tunnelId: `tunnel_${"b".repeat(32)}`,
      apiKey: "TEST_RUNTIME_API_KEY_000000000"
    })).rejects.toThrow(/rejected/u);
    expect(await secrets.get("secure-tunnel.runtime-api-key")).toBeNull();
  });
});
