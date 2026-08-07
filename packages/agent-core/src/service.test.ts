import { describe, expect, it } from "vitest";
import { normalizeVaultId } from "@vault-mcp-bridge/contracts";
import { MemoryAgentStateStore } from "./persistence.js";
import { createAgentService, type CredentialStore, type PublisherStatus, type RemoteClient, type ScanOptions, type ScanResult, type SnapshotPayload, type VaultScanner } from "./index.js";

const vaultId = normalizeVaultId("synthetic-vault");

class FakeCredentials implements CredentialStore {
  readonly kind: string = "file-development";
  private privateKey?: string;
  private identityValue?: { publicKey: string; keyAlgorithm: "ed25519"; createdAt: string };

  async getPrivateKey(): Promise<string | undefined> { return this.privateKey; }
  async savePrivateKey(privateKey: string): Promise<void> { this.privateKey = privateKey; }
  async deletePrivateKey(): Promise<void> { delete this.privateKey; }
  async identity() { return this.identityValue; }
  async saveIdentity(privateKey: string, publicKey: string, createdAt: string): Promise<void> {
    this.privateKey = privateKey;
    this.identityValue = { publicKey, keyAlgorithm: "ed25519", createdAt };
  }
  async getOrCreateIdKey(): Promise<string> { return "synthetic-id-key"; }
}

class FakeKeychainCredentials extends FakeCredentials {
  override readonly kind = "keychain";
}

class FakeScanner implements VaultScanner {
  incomplete = false;
  async scan(_root: string, _options: ScanOptions): Promise<ScanResult> {
    return {
      files: [{ relativePath: "notes/hello.md", bytes: 8, content: "# Hello\n", contentType: "markdown", modifiedAt: "2026-08-07T00:00:00.000Z" }],
      excluded: [{ path: ".obsidian/workspace.json", reason: "hidden" }],
      hidden: 1,
      symlinks: 0,
      errors: this.incomplete ? [{ path: "notes/hello.md", reason: "unstable", message: "synthetic unstable file" }] : [],
      bytes: 8
    };
  }
}

class FakeRemote implements RemoteClient {
  generation = 0;
  uploads: SnapshotPayload[] = [];
  async pair() { return { deviceId: "device_synthetic_0001", vaultId }; }
  async status(): Promise<PublisherStatus> { return { ok: true, checkedAt: "2026-08-07T00:00:00.000Z", vaultId, generation: this.generation }; }
  async upload(input: { url: string; deviceId: string; vaultId: string; snapshot: SnapshotPayload; privateKey: string }): Promise<unknown> {
    this.generation = input.snapshot.generation;
    this.uploads.push(input.snapshot);
    const snapshot = input.snapshot.snapshot as { digest: string; snapshotId: string; documents: unknown[] };
    return { version: 1, accepted: true, idempotent: false, snapshotId: snapshot.snapshotId, vaultId, generation: input.snapshot.generation, digest: snapshot.digest, documentCount: snapshot.documents.length, receivedAt: "2026-08-07T00:00:00.000Z" };
  }
}

function setup(mode: "development" | "production" = "development") {
  const credentials = new FakeCredentials();
  const scanner = new FakeScanner();
  const remote = new FakeRemote();
  const store = new MemoryAgentStateStore();
  const service = createAgentService({ mode, scanner, remoteClient: remote, credentials, stateStore: store, now: () => new Date("2026-08-07T00:00:00.000Z") });
  return { credentials, scanner, remote, store, service };
}

describe("framework-independent local agent service", () => {
  it("returns a path-free preview receipt and requires explicit acceptance", async () => {
    const fixture = setup();
    const service = await fixture.service;
    await service.configure({ vaultRoot: "/Users/synthetic/Notes", vaultId, remoteServerUrl: "https://publisher.example" });
    const preview = await service.preview();
    expect(preview.receipt).toMatchObject({ vaultId, documentCount: 1, totalBytes: 8, unreadableCount: 0, projectionVersion: 1 });
    expect(JSON.stringify(preview.receipt)).not.toContain("/Users/synthetic");
    await expect(service.syncNow()).rejects.toThrow("preview_required");
    await service.acceptPreview(preview.receipt);
    await service.generateIdentity();
    await service.pair("PAIR-SYNTHETIC");
    const result = await service.syncNow();
    expect(result.snapshotId).toBe(fixture.remote.uploads[0]?.snapshotId);
    expect(service.getStatus()).toMatchObject({ phase: "ready", pairingConfigured: true, readOnly: true });
    expect(service.getJournal().map((event) => event.code)).toEqual(["device-bound", "vault-synchronized"]);
  });

  it("fails closed on incomplete scans and keeps the previous receipt untouched", async () => {
    const fixture = setup();
    const service = await fixture.service;
    await service.configure({ vaultRoot: "/tmp/synthetic-vault", vaultId, remoteServerUrl: "https://publisher.example" });
    const preview = await service.preview({ accept: true });
    await service.generateIdentity();
    await service.pair("PAIR-SYNTHETIC");
    fixture.scanner.incomplete = true;
    await expect(service.syncNow()).rejects.toThrow("scan_incomplete");
    expect(fixture.remote.uploads).toHaveLength(0);
    expect(service.getStatus()).toMatchObject({ phase: "needs-attention", lastError: "scan_incomplete" });
    expect(service.getStatus().preview?.incomplete).toBe(true);
    expect(service.getStatus().preview?.receipt).not.toEqual(preview.receipt);
  });

  it("pauses scheduled work and resumes without losing the local state", async () => {
    const fixture = setup();
    const service = await fixture.service;
    await service.configure({ vaultRoot: "/tmp/synthetic-vault", vaultId, remoteServerUrl: "https://publisher.example", syncIntervalMinutes: 1 });
    expect(service.getStatus().paused).toBe(false);
    await service.setPaused(true);
    expect(service.getStatus()).toMatchObject({ phase: "paused", paused: true });
    await expect(service.syncNow()).rejects.toThrow("sync_paused");
    await service.setPaused(false);
    expect(service.getStatus().paused).toBe(false);
    expect(service.getJournal().map((event) => event.code)).toEqual(["paused", "resumed"]);
    await service.close();
  });

  it("rejects a file credential store before production setup starts", async () => {
    const fixture = setup("production");
    await expect(fixture.service).rejects.toThrow("production_credential_store_required");
  });

  it("rejects production setup when the publisher mTLS provider is absent", async () => {
    const credentials = new FakeKeychainCredentials();
    await expect(createAgentService({ mode: "production", scanner: new FakeScanner(), remoteClient: new FakeRemote(), credentials, stateStore: new MemoryAgentStateStore() })).rejects.toThrow("publisher_mtls_credentials_required");
  });

  it("bounds the redacted journal", async () => {
    const fixture = setup();
    const service = await createAgentService({ mode: "development", scanner: fixture.scanner, remoteClient: fixture.remote, credentials: fixture.credentials, stateStore: fixture.store, maxJournalEntries: 10, now: () => new Date("2026-08-07T00:00:00.000Z") });
    await service.configure({ vaultRoot: "/tmp/synthetic-vault", vaultId, remoteServerUrl: "https://publisher.example" });
    for (let index = 0; index < 20; index += 1) await service.setPaused(index % 2 === 0);
    expect(service.getJournal()).toHaveLength(10);
    expect(JSON.stringify(service.getJournal())).not.toMatch(/Users|home|private|tmp/iu);
  });

  it("allows only loopback HTTP in development and no HTTP in production", async () => {
    const fixture = setup();
    const service = await fixture.service;
    await expect(service.configure({ remoteServerUrl: "http://remote.example" })).rejects.toThrow("remote_server_https_required");
    await expect(service.configure({ remoteServerUrl: "http://127.0.0.1:8787" })).resolves.toBeDefined();
  });

  it("persists references and resumes the lifecycle without credentials in state", async () => {
    const fixture = setup();
    const first = await fixture.service;
    await first.configure({ vaultRoot: "/tmp/synthetic-vault", vaultId, remoteServerUrl: "https://publisher.example" });
    await first.close();
    const second = await createAgentService({ scanner: fixture.scanner, remoteClient: fixture.remote, credentials: fixture.credentials, stateStore: fixture.store, now: () => new Date("2026-08-07T00:00:00.000Z") });
    expect(second.getConfig()).toMatchObject({ vaultId, remoteServerUrl: "https://publisher.example" });
    expect(JSON.stringify(second.getState())).not.toContain("privateKey");
  });
});
