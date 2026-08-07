import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { InMemoryStateStore, JsonFileStateStore, PersistenceSafetyError } from "./state-store.js";
import { serverCopyDisposition } from "./projection.js";
import type { SetupRecord } from "./types.js";

const record: SetupRecord = {
  schemaVersion: 1,
  setupId: "setup-test",
  revision: 1,
  phase: "ready",
  installationId: "installation-test",
  request: {
    installationId: "installation-test",
    vault: { vaultId: "vault-test", label: "Synthetic", root: "/synthetic/vault" },
    server: { host: "server.example.invalid", user: "deploy", port: 22, authRef: "keychain:ssh" }
  },
  sync: { paused: false },
  journal: [],
  updatedAt: "2026-08-07T00:00:00.000Z"
};

describe("state stores", () => {
  it("keeps in-memory values isolated from caller mutation", async () => {
    const store = new InMemoryStateStore();
    await store.save(record);
    const loaded = await store.load();
    loaded!.request.vault.label = "changed";
    expect((await store.load())!.request.vault.label).toBe("Synthetic");
  });

  it("writes and reads JSON atomically without allowing secret-like fields", async () => {
    const directory = await mkdtemp(join(tmpdir(), "vmb-orchestrator-"));
    const filePath = join(directory, "state.json");
    const store = new JsonFileStateStore(filePath);
    await store.save(record);
    expect((await store.load())?.phase).toBe("ready");
    expect(JSON.parse(await readFile(filePath, "utf8"))).toMatchObject({ phase: "ready" });

    await expect(store.save({ ...record, publisherToken: "secret" } as SetupRecord & { publisherToken: string })).rejects.toBeInstanceOf(PersistenceSafetyError);
    await expect(store.save({ ...record, request: { ...record.request, server: { ...record.request.server, authRef: "raw-private-key" } } })).rejects.toBeInstanceOf(PersistenceSafetyError);
    expect((await store.load())?.phase).toBe("ready");
  });

  it("persists a cleanup-only replica receipt and treats legacy disconnected records as unknown", async () => {
    const retained: SetupRecord = {
      ...record,
      phase: "idle",
      serverCopy: "retained",
      replicaCleanup: {
        schemaVersion: 1,
        installationId: record.installationId,
        server: record.request.server,
        projectName: "vmb-test",
        resourceLabel: record.installationId,
        installationDirectory: "/srv/vault-bridge/installation-test",
        composePath: "/srv/vault-bridge/installation-test/compose.yaml",
        volumes: {
          replica: "vmb-test_replica_data",
          serverRuntime: "vmb-test_server_secrets",
          tunnelRuntime: "vmb-test_tunnel_secrets"
        },
        retainedAt: "2026-08-07T00:00:00.000Z"
      },
      journal: [{ at: "2026-08-07T00:00:00.000Z", level: "info", event: "disconnected", detail: { keepReplica: true } }]
    };
    const store = new InMemoryStateStore();
    await store.save(retained);
    expect((await store.load())?.replicaCleanup?.volumes.replica).toBe("vmb-test_replica_data");
    expect(serverCopyDisposition(await store.load() as SetupRecord)).toBe("retained");

    const legacy: SetupRecord = { ...record, phase: "idle", journal: retained.journal };
    delete legacy.serverCopy;
    expect(serverCopyDisposition(legacy)).toBe("unknown");
  });
});
