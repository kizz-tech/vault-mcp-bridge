import { describe, expect, it } from "vitest";
import { InMemoryStateStore } from "./state-store.js";
import { SetupOrchestrator } from "./orchestrator.js";
import type {
  DisconnectInput,
  DeploymentPort,
  DeviceBinding,
  EdgeInstallation,
  EndpointVerification,
  EndpointVerificationPort,
  OwnerEdgePort,
  PublisherPort,
  ReplicaCleanupInput,
  SetupInput,
  StagedDeployment,
  VaultPreview,
  VaultPreviewPort
} from "./types.js";

const input: SetupInput = {
  installationId: "installation-test",
  vault: { vaultId: "vault-test", label: "Synthetic vault", root: "/synthetic/vault" },
  server: { host: "server.example.invalid", user: "deploy", port: 22, authRef: "keychain:ssh-test" }
};

const preview: VaultPreview = {
  vaultId: input.vault.vaultId,
  label: input.vault.label,
  noteCount: 2,
  byteCount: 42
};
const edgeInstallation: EdgeInstallation = {
  installationRef: "edge-installation",
  endpointUrl: "https://mcp.example.invalid/mcp",
  provider: "fake"
};
const staged: StagedDeployment = {
  projectName: "vmb-test",
  release: "test@digest",
  resourceLabel: "installation-test",
  cleanup: {
    schemaVersion: 1,
    installationId: "installation-test",
    server: input.server,
    projectName: "vmb-test",
    resourceLabel: "installation-test",
    installationDirectory: "/srv/vault-bridge/installation-test",
    composePath: "/srv/vault-bridge/installation-test/compose.yaml",
    volumes: {
      replica: "vmb-test_replica_data",
      serverRuntime: "vmb-test_server_secrets",
      tunnelRuntime: "vmb-test_tunnel_secrets"
    }
  }
};

type Operation =
  | "preview"
  | "preflight"
  | "edge"
  | "stage"
  | "deploy"
  | "bind"
  | "snapshot"
  | "endpoint"
  | "sync"
  | "remove";

class FakeAdapters implements VaultPreviewPort, DeploymentPort, PublisherPort, EndpointVerificationPort {
  readonly calls: Operation[] = [];
  failOnce: Operation | undefined;

  private call(operation: Operation): void {
    this.calls.push(operation);
    if (this.failOnce === operation) {
      this.failOnce = undefined;
      throw new Error("synthetic interruption");
    }
  }

  async preview(): Promise<VaultPreview> {
    this.call("preview");
    return preview;
  }

  async preflight() {
    this.call("preflight");
    return { os: "linux", architecture: "arm64", dockerMode: "rootless" as const };
  }

  async install(): Promise<EdgeInstallation> {
    this.call("edge");
    return edgeInstallation;
  }

  async stage(): Promise<StagedDeployment> {
    this.call("stage");
    return staged;
  }

  async deploy() {
    this.call("deploy");
    return { projectName: staged.projectName, release: staged.release, health: "healthy" as const, startedAt: "2026-08-07T00:00:00.000Z" };
  }

  async bindDevice(): Promise<DeviceBinding> {
    this.call("bind");
    return { deviceId: "device-test", publisherCredentialRef: "keychain:publisher-test" };
  }

  async publishFirstSnapshot() {
    this.call("snapshot");
    return { snapshotId: "snapshot-test", generation: 1, documentCount: 2, digest: "digest-test", publishedAt: "2026-08-07T00:00:00.000Z" };
  }

  async syncNow() {
    this.call("sync");
    return { generation: 2, documentCount: 2, digest: "digest-test-2", publishedAt: "2026-08-07T00:01:00.000Z" };
  }

  async verify(): Promise<EndpointVerification> {
    this.call("endpoint");
    return { endpointUrl: edgeInstallation.endpointUrl, mcp: "ok", oauth: "ok", verifiedAt: "2026-08-07T00:00:00.000Z" };
  }

  async disconnect() {
    this.calls.push("endpoint");
  }

  async removeReplica(_input: ReplicaCleanupInput) {
    this.call("remove");
  }
}

type DisconnectOperation = "edge" | "publisher" | "deployment";

class DisconnectRecorder {
  readonly calls: Array<{ operation: DisconnectOperation; input: DisconnectInput }> = [];
  readonly failures = new Set<DisconnectOperation>();

  async disconnect(operation: DisconnectOperation, input: DisconnectInput): Promise<void> {
    this.calls.push({ operation, input: structuredClone(input) });
    if (this.failures.has(operation)) throw new Error(operation + " revoke failed");
  }
}

function makeDisconnectOrchestrator(recorder: DisconnectRecorder, store = new InMemoryStateStore()): SetupOrchestrator {
  const setup = new FakeAdapters();
  const edge: OwnerEdgePort = {
    install: (input) => setup.install(input),
    disconnect: (input) => recorder.disconnect("edge", input)
  };
  const deployment: DeploymentPort = {
    preflight: (input) => setup.preflight(input),
    stage: (input) => setup.stage(input),
    deploy: (input) => setup.deploy(input),
    disconnect: (input) => recorder.disconnect("deployment", input)
  };
  const publisher: PublisherPort = {
    bindDevice: (input) => setup.bindDevice(input),
    publishFirstSnapshot: (input) => setup.publishFirstSnapshot(input),
    disconnect: (input) => recorder.disconnect("publisher", input)
  };
  const endpoint: EndpointVerificationPort = { verify: (input) => setup.verify(input) };
  return new SetupOrchestrator({
    stateStore: store,
    vault: setup,
    edge,
    deployment,
    publisher,
    endpoint,
    now: () => new Date("2026-08-07T00:00:00.000Z")
  });
}

function makeOrchestrator(adapters: FakeAdapters, store = new InMemoryStateStore()): SetupOrchestrator {
  return new SetupOrchestrator({
    stateStore: store,
    vault: adapters,
    edge: adapters,
    deployment: adapters,
    publisher: adapters,
    endpoint: adapters,
    createId: (() => {
      let count = 0;
      return () => "generated-" + ++count;
    })(),
    now: () => new Date("2026-08-07T00:00:00.000Z")
  });
}

describe("SetupOrchestrator", () => {
  it("runs the complete ordered state machine and is idempotent after ready", async () => {
    const adapters = new FakeAdapters();
    const orchestrator = makeOrchestrator(adapters);
    const ready = await orchestrator.start(input);
    expect(ready.phase).toBe("ready");
    expect(adapters.calls).toEqual(["preview", "preflight", "edge", "stage", "deploy", "bind", "snapshot", "endpoint"]);

    const callCount = adapters.calls.length;
    expect((await orchestrator.resume()).phase).toBe("ready");
    expect(adapters.calls).toHaveLength(callCount);
  });

  it.each([
    ["preview", "idle"],
    ["preflight", "idle"],
    ["edge", "preflight"],
    ["stage", "preflight"],
    ["deploy", "staged"],
    ["bind", "deployed"],
    ["snapshot", "device-bound"],
    ["endpoint", "first-snapshot"]
  ] as const)("resumes safely when %s is interrupted from %s", async (operation: Operation, _expectedPhase: string) => {
    const adapters = new FakeAdapters();
    adapters.failOnce = operation;
    const orchestrator = makeOrchestrator(adapters);

    const attention = await orchestrator.start(input);
    expect(attention.phase).toBe("needs-attention");
    expect(attention.attention?.phase).toBe(operation === "preview" || operation === "preflight" ? "idle" : operation === "edge" || operation === "stage" ? "preflight" : operation === "deploy" ? "staged" : operation === "bind" ? "deployed" : operation === "snapshot" ? "device-bound" : "first-snapshot");

    const ready = await orchestrator.resume();
    expect(ready.phase).toBe("ready");
    expect(adapters.calls.filter((call) => call === operation).length).toBeGreaterThanOrEqual(2);
  });

  it("pauses and resumes sync without changing setup stage", async () => {
    const adapters = new FakeAdapters();
    const orchestrator = makeOrchestrator(adapters);
    await orchestrator.start(input);
    await orchestrator.pauseSync();
    expect((await orchestrator.getState())?.sync.paused).toBe(true);
    await expect(orchestrator.syncNow()).rejects.toMatchObject({ code: "sync-paused" });
    await orchestrator.resumeSync();
    const synced = await orchestrator.syncNow();
    expect(synced.phase).toBe("ready");
    expect(synced.sync.last?.generation).toBe(2);
  });

  it("disconnects exact installation resources and keeps the local configuration", async () => {
    const adapters = new FakeAdapters();
    const orchestrator = makeOrchestrator(adapters);
    await orchestrator.start(input);
    const disconnected = await orchestrator.disconnect(true);
    expect(disconnected?.phase).toBe("idle");
    expect(disconnected?.request.vault.root).toBe(input.vault.root);
    expect(disconnected?.deployment).toBeUndefined();
    expect(disconnected?.edge).toBeUndefined();
    expect(disconnected?.device).toBeUndefined();
    expect(disconnected?.serverCopy).toBe("retained");
    expect(disconnected?.replicaCleanup).toMatchObject({ installationId: input.installationId });
  });

  it("attempts deployment cleanup when edge and publisher revocation fail, then retries idempotently", async () => {
    const recorder = new DisconnectRecorder();
    const orchestrator = makeDisconnectOrchestrator(recorder);
    await orchestrator.start(input);
    recorder.failures.add("edge");
    recorder.failures.add("publisher");

    const attention = await orchestrator.disconnect(false);
    expect(recorder.calls.map((call) => call.operation)).toEqual(["edge", "publisher", "deployment"]);
    expect(recorder.calls.every((call) => call.input.keepReplica === false)).toBe(true);
    expect(attention?.phase).toBe("needs-attention");
    expect(attention?.attention).toMatchObject({ phase: "ready", retryable: true });
    expect(attention?.deployment).toBeDefined();
    expect(attention?.edge).toBeDefined();

    recorder.failures.clear();
    const disconnected = await orchestrator.disconnect(false);
    expect(recorder.calls.map((call) => call.operation)).toEqual([
      "edge",
      "publisher",
      "deployment",
      "edge",
      "publisher",
      "deployment"
    ]);
    expect(disconnected?.phase).toBe("idle");
    expect(disconnected?.edge).toBeUndefined();
    expect(disconnected?.deployment).toBeUndefined();
    expect(disconnected?.attention).toBeUndefined();

    // A successful retry leaves no scope to operate on, so a third request is
    // a no-op rather than an unscoped remote disconnect.
    expect((await orchestrator.disconnect(false))?.revision).toBe(disconnected?.revision);
    expect(recorder.calls).toHaveLength(6);
  });

  it("blocks fresh setup while a retained replica exists, then allows it after explicit removal", async () => {
    const adapters = new FakeAdapters();
    const orchestrator = makeOrchestrator(adapters);
    await orchestrator.start(input);
    const disconnected = await orchestrator.disconnect(true);
    const callsAfterDisconnect = adapters.calls.length;

    const unchanged = await orchestrator.start();
    expect(unchanged.phase).toBe("idle");
    expect(unchanged.setupId).toBe(disconnected?.setupId);
    expect(adapters.calls).toHaveLength(callsAfterDisconnect);

    const replacement: SetupInput = {
      installationId: "installation-replacement",
      vault: { vaultId: "vault-replacement", label: "Replacement vault", root: "/synthetic/replacement" },
      server: { host: "replacement.example.invalid", user: "operator", port: 2222, authRef: "keychain:ssh-replacement" }
    };
    await expect(orchestrator.start(replacement)).rejects.toMatchObject({ code: "server-copy-retained" });
    const removed = await orchestrator.removeServerCopy();
    expect(removed?.serverCopy).toBe("none");
    expect(removed?.replicaCleanup).toBeUndefined();
    expect(adapters.calls.at(-1)).toBe("remove");
    const removalCallCount = adapters.calls.length;
    expect((await orchestrator.removeServerCopy())?.revision).toBe(removed?.revision);
    expect(adapters.calls).toHaveLength(removalCallCount);

    const ready = await orchestrator.start(replacement);
    expect(ready.phase).toBe("ready");
    expect(ready.setupId).not.toBe(disconnected?.setupId);
    expect(ready.installationId).toBe(replacement.installationId);
    expect(ready.request).toEqual({ installationId: replacement.installationId, vault: replacement.vault, server: replacement.server });
  });

  it("retains cleanup authority across restart and a failed removal retry", async () => {
    const store = new InMemoryStateStore();
    const initialAdapters = new FakeAdapters();
    const initial = makeOrchestrator(initialAdapters, store);
    await initial.start(input);
    await initial.disconnect(true);

    const restartedAdapters = new FakeAdapters();
    restartedAdapters.failOnce = "remove";
    const restarted = makeOrchestrator(restartedAdapters, store);
    const attention = await restarted.removeServerCopy();
    expect(attention?.phase).toBe("needs-attention");
    expect(attention?.replicaCleanup).toBeDefined();
    expect(attention?.serverCopy).toBe("retained");

    const removed = await restarted.removeServerCopy();
    expect(removed?.phase).toBe("idle");
    expect(removed?.replicaCleanup).toBeUndefined();
    expect(restartedAdapters.calls.filter((call) => call === "remove")).toHaveLength(2);
  });

  it("projects a renderer-safe public state", async () => {
    const adapters = new FakeAdapters();
    const orchestrator = makeOrchestrator(adapters);
    await orchestrator.start(input);
    const publicState = await orchestrator.getPublicState();
    expect(publicState?.stage).toBe("ready");
    expect(publicState?.status).toBe("ready");
    expect(publicState?.serverCopy).toBe("active");
    expect(JSON.stringify(publicState)).not.toMatch(/(?:authRef|privateKey|token|secretValue)/iu);
  });
});
