import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, it } from "vitest";
import { projectNameForInstallation } from "@vault-mcp-bridge/deployment";

import { ProductDeploymentAdapter, ProductDesktopBackend, ProductOwnerEdgeAdapter, installationScopedDirectory } from "../src/product-backend.js";
import type { ProductConfig } from "../src/product-config.js";
import { SshCommandError } from "../src/ssh.js";

const config: ProductConfig = {
  edgeOrigin: "https://edge.example.invalid",
  ownerIssuer: "https://issuer.example.invalid",
  ownerAuthorizationEndpoint: "https://issuer.example.invalid/authorize",
  ownerTokenEndpoint: "https://issuer.example.invalid/token",
  ownerJwksUri: "https://issuer.example.invalid/jwks",
  ownerAudience: "edge",
  ownerClientId: "desktop",
  installationDirectory: "/srv/vault-bridge",
  images: {
    serverRepository: "ghcr.io/example/server",
    serverDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    tunnelRepository: "cloudflare/cloudflared",
    tunnelDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
  }
};

function disconnectRecord() {
  const installationId = "inst_1234567890abcdef";
  const projectName = projectNameForInstallation(installationId);
  const directory = `/srv/vault-bridge/${installationId}`;
  return {
    installationId,
    request: {
      installationId,
      vault: { vaultId: "vault_1234567890abcdef", label: "Synthetic", root: "/synthetic/vault" },
      server: { host: "host.example.test", user: "deploy", port: 22 }
    },
    edge: { installationRef: installationId },
    staged: {
      projectName,
      resourceLabel: installationId,
      cleanup: {
        schemaVersion: 1,
        installationId,
        server: { host: "host.example.test", user: "deploy", port: 22 },
        projectName,
        resourceLabel: installationId,
        installationDirectory: directory,
        composePath: `${directory}/compose.yaml`,
        volumes: {
          replica: `${projectName}_replica_data`,
          serverRuntime: `${projectName}_server_secrets`,
          tunnelRuntime: `${projectName}_tunnel_secrets`
        }
      }
    }
  };
}

function deploymentFor(run: (command: readonly string[]) => Promise<{ code: number; stdout: string; stderr: string }>): ProductDeploymentAdapter {
  return new ProductDeploymentAdapter({
    config,
    ssh: {
      async runFixed(_target: unknown, command: readonly string[]) { return run(command); },
      async ensurePinned(target: unknown) { return target; }
    } as never,
    sftp: {} as never,
    pins: {} as never,
    confirmation: { async confirm() { return true; } },
    appDataPath: "/private/app-data",
    now: () => new Date("2026-08-07T00:00:00.000Z")
  });
}

function cacheProject(adapter: ProductDeploymentAdapter, record: ReturnType<typeof disconnectRecord>, composePath = "/srv/vault-bridge/inst_1234567890abcdef/compose.yaml"): void {
  (adapter as unknown as { projects: Map<string, unknown> }).projects.set(record.installationId, {
    target: { host: "host.example.test", user: "deploy", port: 22 },
    composePath,
    project: { installationId: record.installationId, projectName: record.staged.projectName, labels: { "com.vault-mcp-bridge.installation-id": record.installationId } }
  });
}

function disconnectInput(record: ReturnType<typeof disconnectRecord>, keepReplica: boolean) {
  return { installationId: record.installationId, prior: record as never, keepReplica, projectName: record.staged.projectName, resourceLabel: record.installationId } as never;
}

function cleanupInput(record: ReturnType<typeof disconnectRecord>) {
  return {
    setupId: "setup_1234567890abcdef",
    installationId: record.installationId,
    idempotencyKey: "setup_1234567890abcdef:remove-replica",
    request: record.request,
    receipt: record.staged.cleanup
  } as never;
}

function activeLifecycleRecord() {
  const source = disconnectRecord();
  return {
    schemaVersion: 1,
    setupId: "setup_1234567890abcdef",
    revision: 8,
    phase: "needs-attention",
    resumePhase: "ready",
    installationId: source.installationId,
    request: source.request,
    serverCopy: "active",
    edge: { installationRef: source.installationId, endpointUrl: "https://mcp.example.test/mcp", provider: "managed-edge" },
    staged: source.staged,
    sync: { paused: false },
    attention: {
      code: "deployment-failed",
      message: "deployment cleanup failed",
      phase: "ready",
      retryable: true,
      at: "2026-08-07T00:00:00.000Z"
    },
    journal: [],
    updatedAt: "2026-08-07T00:00:00.000Z"
  } as const;
}

function retainedLifecycleRecord() {
  const active = activeLifecycleRecord();
  return {
    ...active,
    phase: "needs-attention" as const,
    resumePhase: "idle" as const,
    serverCopy: "retained" as const,
    replicaCleanup: { ...active.staged.cleanup, retainedAt: "2026-08-07T00:00:00.000Z" },
    edge: undefined,
    staged: undefined
  };
}

function lifecycleHarness(options: {
  directoryExists?: boolean;
  composeExists?: boolean;
  containers?: string;
  networks?: string;
  pathProbeError?: boolean;
  wrongVolumeLabel?: string;
} = {}) {
  const record = disconnectRecord();
  const calls: string[][] = [];
  const volumes = new Set(Object.values(record.staged.cleanup.volumes));
  let directoryExists = options.directoryExists ?? true;
  let composeExists = options.composeExists ?? true;
  const run = async (command: readonly string[]) => {
    calls.push([...command]);
    if (command[0] === "find") {
      if (options.pathProbeError) throw new SshCommandError("permission denied", { code: 1, stdout: "", stderr: "permission denied" });
      const parent = command[1] ?? "";
      const name = command[7] ?? "";
      const type = command[9] ?? "";
      const path = `${parent.replace(/\/$/u, "")}/${name}`;
      const exists = type === "d"
        ? path === record.staged.cleanup.installationDirectory && directoryExists
        : type === "f" && path === record.staged.cleanup.composePath && directoryExists && composeExists;
      return { code: 0, stdout: exists ? `${path}\n` : "", stderr: "" };
    }
    if (command[0] === "rm") {
      directoryExists = false;
      composeExists = false;
      return { code: 0, stdout: "", stderr: "" };
    }
    if (command[0] === "docker" && command[1] === "ps") {
      return { code: 0, stdout: options.containers ?? "", stderr: "" };
    }
    if (command[0] === "docker" && command[1] === "network") {
      return { code: 0, stdout: options.networks ?? "", stderr: "" };
    }
    if (command[0] === "docker" && command[1] === "volume" && command[2] === "inspect") {
      const volume = command[3] ?? "";
      if (!volumes.has(volume)) throw new SshCommandError("not found", { code: 1, stdout: "", stderr: "" });
      const component = volume === record.staged.cleanup.volumes.replica
        ? "replica"
        : volume === record.staged.cleanup.volumes.serverRuntime
          ? "server-secrets"
          : "tunnel-secrets";
      return {
        code: 0,
        stdout: JSON.stringify([{
          Name: volume,
          Labels: {
            "com.vault-mcp-bridge.installation-id": options.wrongVolumeLabel === volume ? "inst_unrelated_123456" : record.installationId,
            "com.vault-mcp-bridge.project": record.staged.projectName,
            "com.vault-mcp-bridge.component": component
          }
        }]),
        stderr: ""
      };
    }
    if (command[0] === "docker" && command[1] === "volume" && command[2] === "rm") {
      volumes.delete(command[3] ?? "");
      return { code: 0, stdout: "", stderr: "" };
    }
    if (command[0] === "docker" && command[1] === "volume" && command[2] === "ls") {
      const filter = command[5] ?? "";
      if (filter.startsWith("name=")) {
        const volume = filter.slice("name=".length);
        return { code: 0, stdout: volumes.has(volume) ? `${volume}\n` : "", stderr: "" };
      }
      return { code: 0, stdout: [...volumes].join("\n"), stderr: "" };
    }
    return { code: 0, stdout: "", stderr: "" };
  };
  return { record, calls, volumes, run };
}

describe("product desktop backend", () => {
  it("reports concise configuration attention instead of setup unavailable", async () => {
    const backend = new ProductDesktopBackend({ appDataPath: "/private/app-data" });
    const state = await backend.getState();
    expect(state.mode).toBe("attention");
    expect(state.attention?.code).toBe("oauth-not-linked");
    expect(state.attention?.message).toBe("Edge not configured");
  });

  it("loads legacy cleanup state without requiring a configured edge runtime", async () => {
    const appDataPath = await mkdtemp(join(tmpdir(), "vault-bridge-legacy-cleanup-"));
    try {
      const source = disconnectRecord();
      await writeFile(join(appDataPath, "setup.json"), JSON.stringify({
        schemaVersion: 1,
        setupId: "setup_1234567890abcdef",
        revision: 4,
        phase: "idle",
        installationId: source.installationId,
        request: source.request,
        sync: { paused: false },
        journal: [{ at: "2026-08-07T00:00:00.000Z", level: "info", event: "disconnected", detail: { keepReplica: true } }],
        updatedAt: "2026-08-07T00:00:00.000Z"
      }), { mode: 0o600 });
      const backend = new ProductDesktopBackend({ appDataPath });
      const state = await backend.initialize();
      expect(state.serverCopy).toBe("unknown");
      expect(state.attention?.message).toBe("Server copy status unknown");
      backend.close();
    } finally {
      await rm(appDataPath, { recursive: true, force: true });
    }
  });

  it("does not journal lifecycle success when the durable orchestrator returns attention", async () => {
    const backend = new ProductDesktopBackend({ appDataPath: "/private/app-data" });
    (backend as unknown as { orchestrator: { disconnect: () => Promise<unknown>; removeServerCopy: () => Promise<unknown> } }).orchestrator = {
      async disconnect() { return activeLifecycleRecord(); },
      async removeServerCopy() { return retainedLifecycleRecord(); }
    };
    const disconnected = await backend.disconnect();
    expect(disconnected.serverCopy).toBe("active");
    expect(disconnected.attention?.message).toBe("Setup failed");
    expect((await backend.getJournal()).map((entry) => entry.message)).not.toContain("Disconnected");
    const removed = await backend.removeServerCopy();
    expect(removed.serverCopy).toBe("retained");
    expect(removed.attention?.message).toBe("Setup failed");
    expect((await backend.getJournal()).map((entry) => entry.message)).not.toContain("Server copy removed");
  });

  it("derives an installation-scoped path and rejects broad removal roots", () => {
    expect(installationScopedDirectory("/srv/vault-bridge", "inst_test_1234567890")).toBe("/srv/vault-bridge/inst_test_1234567890");
    expect(installationScopedDirectory("/srv/vault-bridge/inst_test_1234567890", "inst_test_1234567890")).toBe("/srv/vault-bridge/inst_test_1234567890");
    for (const root of ["/", "/srv", "/home/deploy", "/tmp", "/srv/../etc"]) {
      expect(() => installationScopedDirectory(root, "inst_test_1234567890")).toThrow("installation_directory_invalid");
    }
  });

  it("refuses to display a new server while an installation still owns remote resources", async () => {
    const appDataPath = await mkdtemp(join(tmpdir(), "vault-bridge-server-change-"));
    try {
      await mkdir(appDataPath, { recursive: true });
      await writeFile(join(appDataPath, "setup.json"), JSON.stringify({
        schemaVersion: 1,
        setupId: "setup_1234567890abcdef",
        revision: 1,
        phase: "ready",
        installationId: "inst_1234567890abcdef",
        request: {
          installationId: "inst_1234567890abcdef",
          vault: { vaultId: "vault_1234567890abcdef", label: "Vault", root: "/private/vault" },
          server: { host: "old.example.test", user: "deploy", port: 22 }
        },
        edge: {
          installationRef: "inst_1234567890abcdef",
          endpointUrl: "https://mcp.example.test/mcp",
          provider: "managed-edge"
        },
        sync: { paused: false },
        journal: [],
        updatedAt: "2026-08-07T00:00:00.000Z"
      }), { mode: 0o600 });

      const backend = new ProductDesktopBackend({ appDataPath });
      await expect(backend.configureServer({ host: "new.example.test", user: "deploy", port: 22 }))
        .rejects.toThrow("disconnect_before_server_change");
      expect((await backend.getState()).server).toBeNull();
    } finally {
      await rm(appDataPath, { recursive: true, force: true });
    }
  });

  it("restores retained-copy capability after restart and blocks a replacement setup", async () => {
    const appDataPath = await mkdtemp(join(tmpdir(), "vault-bridge-retained-"));
    const source = disconnectRecord();
    try {
      await writeFile(join(appDataPath, "setup.json"), JSON.stringify({
        schemaVersion: 1,
        setupId: "setup_1234567890abcdef",
        revision: 8,
        phase: "idle",
        installationId: source.installationId,
        request: source.request,
        serverCopy: "retained",
        replicaCleanup: { ...source.staged.cleanup, retainedAt: "2026-08-07T00:00:00.000Z" },
        sync: { paused: false },
        journal: [{ at: "2026-08-07T00:00:00.000Z", level: "info", event: "disconnected", detail: { keepReplica: true } }],
        updatedAt: "2026-08-07T00:00:00.000Z"
      }), { mode: 0o600 });
      const backend = new ProductDesktopBackend({ appDataPath, config, edge: {} as never });
      const state = await backend.initialize();
      expect(state.serverCopy).toBe("retained");
      expect(state.server?.connected).toBe(false);
      expect((await backend.setup()).attention?.message).toBe("Remove server copy first");
      backend.close();
    } finally {
      await rm(appDataPath, { recursive: true, force: true });
    }
  });

  it("removes only exact installation resources and verifies their absence", async () => {
    const harness = lifecycleHarness();
    const adapter = deploymentFor(harness.run);
    const record = harness.record;
    const directory = "/srv/vault-bridge/inst_1234567890abcdef";
    cacheProject(adapter, record, `${directory}/compose.yaml`);
    await adapter.disconnect(disconnectInput(record, false));
    expect(harness.calls).toContainEqual(["find", "/srv/vault-bridge", "-maxdepth", "1", "-mindepth", "1", "-name", record.installationId, "-type", "d", "-print"]);
    expect(harness.calls).toContainEqual(["find", directory, "-maxdepth", "1", "-mindepth", "1", "-name", "compose.yaml", "-type", "f", "-print"]);
    expect(harness.calls).toContainEqual(expect.arrayContaining(["down", "--timeout", "30"]));
    expect(harness.calls).toContainEqual(["rm", "-rf", "--", directory]);
    expect(harness.volumes.size).toBe(0);
  });

  it("removes exact volumes even when the installation directory is already absent", async () => {
    const harness = lifecycleHarness({ directoryExists: false });
    const adapter = deploymentFor(harness.run);
    const record = harness.record;
    cacheProject(adapter, record);
    await expect(adapter.disconnect(disconnectInput(record, false))).resolves.toBeUndefined();
    expect(harness.calls.some((command) => command.includes("down"))).toBe(false);
    expect(harness.volumes.size).toBe(0);
  });

  it("fails closed when the exact installation compose file is absent", async () => {
    const harness = lifecycleHarness({ composeExists: false });
    const adapter = deploymentFor(harness.run);
    const record = harness.record;
    cacheProject(adapter, record);
    await expect(adapter.disconnect(disconnectInput(record, false))).rejects.toThrow("deployment_compose_missing");
    expect(harness.calls).toHaveLength(2);
    expect(harness.calls.some((command) => command.includes("down") || command[0] === "rm")).toBe(false);
  });

  it("does not treat a code-1 permission denial as path absence", async () => {
    const harness = lifecycleHarness({ pathProbeError: true });
    const adapter = deploymentFor(harness.run);
    const record = harness.record;
    cacheProject(adapter, record);
    await expect(adapter.disconnect(disconnectInput(record, false))).rejects.toThrow("permission denied");
    expect(harness.volumes.size).toBe(3);
    expect(harness.calls.some((command) => command[0] === "docker" || command[0] === "rm")).toBe(false);
  });

  it("keeps only the replica while deleting revoked secret volumes and staged files", async () => {
    const harness = lifecycleHarness();
    const adapter = deploymentFor(harness.run);
    const record = harness.record;
    cacheProject(adapter, record);
    await adapter.disconnect(disconnectInput(record, true));
    const down = harness.calls.find((command) => command.includes("down"));
    expect(down).toBeDefined();
    expect(down).not.toContain("--volumes");
    expect(harness.volumes).toEqual(new Set([record.staged.cleanup.volumes.replica]));
    expect(harness.calls).toContainEqual(["rm", "-rf", "--", record.staged.cleanup.installationDirectory]);
  });

  it("removes a retained replica after restart using only its cleanup receipt", async () => {
    const harness = lifecycleHarness({ directoryExists: false });
    const adapter = deploymentFor(harness.run);
    await adapter.removeReplica(cleanupInput(harness.record));
    expect(harness.volumes.size).toBe(0);
    expect(harness.calls.some((command) => command.includes("compose"))).toBe(false);
  });

  it("fails before volume mutation when retained cleanup scope is mismatched", async () => {
    const harness = lifecycleHarness({ directoryExists: false });
    const adapter = deploymentFor(harness.run);
    const input = cleanupInput(harness.record) as { receipt: { volumes: { replica: string } } };
    input.receipt.volumes.replica = "unrelated_volume";
    await expect(adapter.removeReplica(input as never)).rejects.toThrow("deployment_volume_mismatch");
    expect(harness.calls).toEqual([]);
  });

  it("rejects an exact-name volume with foreign ownership labels before mutation", async () => {
    const source = disconnectRecord();
    const harness = lifecycleHarness({ directoryExists: false, wrongVolumeLabel: source.staged.cleanup.volumes.serverRuntime });
    const adapter = deploymentFor(harness.run);
    await expect(adapter.removeReplica(cleanupInput(harness.record))).rejects.toThrow("deployment_volume_ownership_mismatch");
    expect(harness.calls.some((command) => command[0] === "docker" && command[2] === "rm")).toBe(false);
    expect(harness.volumes.size).toBe(3);
  });

  it("fails closed when an owned container remains after the Compose directory is gone", async () => {
    const harness = lifecycleHarness({ directoryExists: false, containers: "container-id\n" });
    const adapter = deploymentFor(harness.run);
    await expect(adapter.removeReplica(cleanupInput(harness.record))).rejects.toThrow("deployment_containers_remain");
    expect(harness.volumes.size).toBe(3);
  });

  it("uses the persisted cleanup path even when a cached project path drifted", async () => {
    const harness = lifecycleHarness({ directoryExists: false });
    const adapter = deploymentFor(harness.run);
    const record = harness.record;
    cacheProject(adapter, record, "/srv/vault-bridge/other-installation/compose.yaml");
    await expect(adapter.disconnect(disconnectInput(record, false))).resolves.toBeUndefined();
    expect(harness.calls[0]).toEqual(["find", "/srv/vault-bridge", "-maxdepth", "1", "-mindepth", "1", "-name", record.installationId, "-type", "d", "-print"]);
    expect(harness.calls.flat()).not.toContain("/srv/vault-bridge/other-installation/compose.yaml");
  });

  it("refuses active cleanup without a persisted exact receipt", async () => {
    const calls: string[][] = [];
    const adapter = deploymentFor(async (command) => {
      calls.push([...command]);
      return { code: 0, stdout: "", stderr: "" };
    });
    const record = disconnectRecord();
    delete (record.staged as { cleanup?: unknown }).cleanup;
    await expect(adapter.disconnect(disconnectInput(record, false))).rejects.toThrow("deployment_cleanup_scope_missing");
    expect(calls).toEqual([]);
  });

  it("revokes the exact edge installation before deleting retained local mTLS material", async () => {
    const calls: string[] = [];
    const owner = new ProductOwnerEdgeAdapter({
      edge: { async revokeInstallation(id: string, key?: string) { calls.push(`revoke:${id}:${key ?? ""}`); } } as never,
      secrets: { async remove(key: string) { calls.push(`remove:${key}`); } } as never,
      uploader: async () => ({ ensureDirectory: async () => undefined, upload: async () => undefined }),
      appDataPath: "/private/app-data",
      directoryFor: () => "/srv/vault-bridge/inst_1234567890abcdef"
    });
    const record = disconnectRecord();
    await owner.disconnect({
      installationId: record.installationId,
      prior: record as never,
      keepReplica: true,
      idempotencyKey: "setup_1234567890abcdef:disconnect"
    } as never);
    await owner.disconnect({
      installationId: record.installationId,
      prior: record as never,
      keepReplica: true,
      idempotencyKey: "setup_1234567890abcdef:disconnect"
    } as never);
    expect(calls).toEqual([
      "revoke:inst_1234567890abcdef:setup_1234567890abcdef:disconnect",
      "remove:publisher.mtls.credentials",
      "revoke:inst_1234567890abcdef:setup_1234567890abcdef:disconnect",
      "remove:publisher.mtls.credentials"
    ]);
  });
});
