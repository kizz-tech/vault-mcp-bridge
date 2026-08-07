import { randomUUID } from "node:crypto";
import { open, mkdir, readFile, rename, rm, chmod } from "node:fs/promises";
import { dirname, basename, join } from "node:path";
import { PersistenceSafetyError, StateStoreError } from "./errors.js";
import {
  SETUP_PHASES,
  SERVER_COPY_DISPOSITIONS,
  type JournalEntry,
  type ReplicaCleanupReceipt,
  type SetupPhase,
  type SetupRecord,
  type SetupStateStore
} from "./types.js";

export { PersistenceSafetyError, StateStoreError } from "./errors.js";

const SECRET_KEY_RE = /(?:secret|token|password|passphrase|privatekey|bearer|authorization|pair(?:ing)?code)/iu;
const SECRET_REFERENCE_KEY_RE = /(?:auth|credential|secret|token)Ref$/u;
const SECRET_REFERENCE_RE = /^(?:keychain|safe-storage|ssh-agent|remote-file):[A-Za-z0-9_.:-]{1,256}$/u;
const MAX_VALIDATION_DEPTH = 32;

/**
 * Fail closed before a state file is touched.  References such as
 * `publisherCredentialRef` are deliberately permitted; the value they point
 * to lives in the platform keychain and is not a credential itself.
 */
export function assertNoSecrets(value: unknown, path = "state", depth = 0): void {
  if (depth > MAX_VALIDATION_DEPTH) throw new PersistenceSafetyError(path);
  if (Array.isArray(value)) {
    for (const [index, item] of value.entries()) assertNoSecrets(item, `${path}[${index}]`, depth + 1);
    return;
  }
  if (value === null || typeof value !== "object") return;
  for (const [key, item] of Object.entries(value)) {
    const isPublicEndpointField = /(?:authorization|token)endpoint$|^oauthProtectedResourceMetadataUrl$/iu.test(key);
    if (SECRET_REFERENCE_KEY_RE.test(key) && typeof item === "string" && !SECRET_REFERENCE_RE.test(item)) {
      throw new PersistenceSafetyError(path + "." + key);
    }
    if (SECRET_KEY_RE.test(key) && !isPublicEndpointField && !/ref$/iu.test(key) && item !== undefined && item !== null && item !== "") {
      throw new PersistenceSafetyError(`${path}.${key}`);
    }
    assertNoSecrets(item, `${path}.${key}`, depth + 1);
  }
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isPhase(value: unknown): value is SetupPhase {
  return typeof value === "string" && (SETUP_PHASES as readonly string[]).includes(value);
}

function isJournalEntry(value: unknown): value is JournalEntry {
  if (!isObject(value)) return false;
  return (
    typeof value.at === "string" &&
    (value.level === "info" || value.level === "warn" || value.level === "error") &&
    typeof value.event === "string" &&
    (value.detail === undefined || isObject(value.detail))
  );
}

function isServerSelection(value: unknown): value is ReplicaCleanupReceipt["server"] {
  if (!isObject(value)) return false;
  if (typeof value.host !== "string" || value.host.length === 0 || value.host.length > 253) return false;
  if (typeof value.user !== "string" || value.user.length === 0 || value.user.length > 64) return false;
  if (value.port !== undefined && (!Number.isInteger(value.port) || (value.port as number) < 1 || (value.port as number) > 65_535)) return false;
  if (value.authRef !== undefined && typeof value.authRef !== "string") return false;
  return value.hostKeyFingerprint === undefined || typeof value.hostKeyFingerprint === "string";
}

function assertReplicaCleanupReceipt(value: unknown, installationId: string): asserts value is ReplicaCleanupReceipt {
  if (!isObject(value) || value.schemaVersion !== 1) throw new StateStoreError("Persisted state has an unsupported replica cleanup receipt");
  if (value.installationId !== installationId || typeof value.installationId !== "string" || value.installationId.length === 0) {
    throw new StateStoreError("Persisted state has an invalid replica cleanup installation id");
  }
  if (!isServerSelection(value.server)) throw new StateStoreError("Persisted state has an invalid replica cleanup server");
  if (typeof value.projectName !== "string" || !/^[a-z0-9][a-z0-9_-]{0,62}$/u.test(value.projectName)) {
    throw new StateStoreError("Persisted state has an invalid replica cleanup project");
  }
  if (typeof value.resourceLabel !== "string" || value.resourceLabel.length === 0 || value.resourceLabel.length > 256) {
    throw new StateStoreError("Persisted state has an invalid replica cleanup label");
  }
  if (typeof value.installationDirectory !== "string" || !isExactInstallationPath(value.installationDirectory)) {
    throw new StateStoreError("Persisted state has an invalid replica cleanup directory");
  }
  if (typeof value.composePath !== "string" || value.composePath !== `${value.installationDirectory}/compose.yaml`) {
    throw new StateStoreError("Persisted state has an invalid replica cleanup compose path");
  }
  if (!isObject(value.volumes)) throw new StateStoreError("Persisted state has no replica cleanup volumes");
  const expected = {
    replica: `${value.projectName}_replica_data`,
    serverRuntime: `${value.projectName}_server_secrets`,
    tunnelRuntime: `${value.projectName}_tunnel_secrets`
  } as const;
  for (const key of ["replica", "serverRuntime", "tunnelRuntime"] as const) {
    if (value.volumes[key] !== expected[key]) throw new StateStoreError("Persisted state has an invalid replica cleanup volume");
  }
  if (value.retainedAt !== undefined && (typeof value.retainedAt !== "string" || !Number.isFinite(Date.parse(value.retainedAt)))) {
    throw new StateStoreError("Persisted state has an invalid replica cleanup timestamp");
  }
}

function isExactInstallationPath(value: string): boolean {
  return value.length > 1 && value.length <= 2048 && value.startsWith("/") && !value.includes("..") && !/[\0\r\n$`;&|<>]/u.test(value) && value.split("/").filter(Boolean).every((part) => /^[A-Za-z0-9._-]+$/u.test(part));
}

/** Validate only the durable envelope; adapter-specific payloads are typed at compile time. */
export function assertSetupRecord(value: unknown): asserts value is SetupRecord {
  if (!isObject(value)) throw new StateStoreError("Persisted state must be an object");
  if (value.schemaVersion !== 1) throw new StateStoreError("Unsupported persisted state schema");
  if (typeof value.setupId !== "string" || value.setupId.length === 0) throw new StateStoreError("Persisted state has no setup id");
  if (!Number.isInteger(value.revision) || (value.revision as number) < 0) throw new StateStoreError("Persisted state has an invalid revision");
  if (!isPhase(value.phase)) throw new StateStoreError("Persisted state has an invalid phase");
  if (value.resumePhase !== undefined && !isPhase(value.resumePhase)) throw new StateStoreError("Persisted state has an invalid resume phase");
  if (typeof value.installationId !== "string" || value.installationId.length === 0) throw new StateStoreError("Persisted state has no installation id");
  if (!isObject(value.request)) throw new StateStoreError("Persisted state has no setup request");
  if (typeof value.request.installationId !== "string" || value.request.installationId.length === 0) {
    throw new StateStoreError("Persisted state has an invalid request installation id");
  }
  if (!isObject(value.request.vault) || typeof value.request.vault.vaultId !== "string" || typeof value.request.vault.label !== "string" || typeof value.request.vault.root !== "string") {
    throw new StateStoreError("Persisted state has an invalid vault selection");
  }
  if (!isObject(value.request.server) || typeof value.request.server.host !== "string" || typeof value.request.server.user !== "string") {
    throw new StateStoreError("Persisted state has an invalid server selection");
  }
  if (
    value.request.server.port !== undefined &&
    (!Number.isInteger(value.request.server.port) || (value.request.server.port as number) < 1 || (value.request.server.port as number) > 65_535)
  ) {
    throw new StateStoreError("Persisted state has an invalid SSH port");
  }
  if (!isObject(value.sync) || typeof value.sync.paused !== "boolean") throw new StateStoreError("Persisted state has invalid sync state");
  if (value.serverCopy !== undefined && !(SERVER_COPY_DISPOSITIONS as readonly unknown[]).includes(value.serverCopy)) {
    throw new StateStoreError("Persisted state has an invalid server copy disposition");
  }
  if (value.replicaCleanup !== undefined) assertReplicaCleanupReceipt(value.replicaCleanup, value.installationId as string);
  if (!Array.isArray(value.journal) || !value.journal.every(isJournalEntry)) throw new StateStoreError("Persisted state has invalid journal entries");
  if (typeof value.updatedAt !== "string") throw new StateStoreError("Persisted state has no update timestamp");
  assertNoSecrets(value);
}

function clone<T>(value: T): T {
  return structuredClone(value);
}

export class InMemoryStateStore implements SetupStateStore {
  private record: SetupRecord | null = null;

  async load(): Promise<SetupRecord | null> {
    return this.record === null ? null : clone(this.record);
  }

  async save(record: SetupRecord): Promise<void> {
    assertSetupRecord(record);
    this.record = clone(record);
  }

  async clear(): Promise<void> {
    this.record = null;
  }
}

/** Atomic state file writer used by the desktop process. */
export class JsonFileStateStore implements SetupStateStore {
  private writeChain: Promise<void> = Promise.resolve();

  constructor(readonly filePath: string) {}

  async load(): Promise<SetupRecord | null> {
    let text: string;
    try {
      text = await readFile(this.filePath, "utf8");
    } catch (error) {
      if (isNodeError(error, "ENOENT")) return null;
      throw new StateStoreError(`Unable to read state file ${basename(this.filePath)}`, { cause: error });
    }

    let value: unknown;
    try {
      value = JSON.parse(text) as unknown;
    } catch (error) {
      throw new StateStoreError("Persisted state is not valid JSON", { cause: error });
    }
    assertSetupRecord(value);
    return clone(value);
  }

  async save(record: SetupRecord): Promise<void> {
    assertSetupRecord(record);
    const serialized = `${JSON.stringify(record, null, 2)}\n`;
    const write = async (): Promise<void> => {
      const directory = dirname(this.filePath);
      await mkdir(directory, { recursive: true, mode: 0o700 });
      const temporaryPath = join(directory, `.${basename(this.filePath)}.${process.pid}.${randomUUID()}.tmp`);
      try {
        const handle = await open(temporaryPath, "wx", 0o600);
        try {
          await handle.writeFile(serialized, "utf8");
          await handle.sync();
        } finally {
          await handle.close();
        }
        await rename(temporaryPath, this.filePath);
        await chmod(this.filePath, 0o600);
      } catch (error) {
        await rm(temporaryPath, { force: true }).catch(() => undefined);
        throw new StateStoreError("Unable to atomically write state file", { cause: error });
      }
    };

    // Keep the queue usable after a failed write; a later retry must still run.
    const operation = this.writeChain.then(write, write);
    this.writeChain = operation.then(
      () => undefined,
      () => undefined
    );
    await operation;
  }

  async clear(): Promise<void> {
    const remove = async (): Promise<void> => {
      try {
        await rm(this.filePath, { force: true });
      } catch (error) {
        throw new StateStoreError("Unable to remove state file", { cause: error });
      }
    };
    const operation = this.writeChain.then(remove, remove);
    this.writeChain = operation.then(
      () => undefined,
      () => undefined
    );
    await operation;
  }
}

function isNodeError(error: unknown, code: string): boolean {
  return isObject(error) && error.code === code;
}
