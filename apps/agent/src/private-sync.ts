import { randomBytes } from "node:crypto";
import { chmod, mkdir, open, readFile, rename, unlink } from "node:fs/promises";
import { isAbsolute, dirname, join, resolve } from "node:path";
import { spawn } from "node:child_process";
import type { Writable } from "node:stream";
import {
  DefaultVaultScanner,
  buildSnapshot,
  receiptMatches,
  safeErrorMessage,
  type ScanResult,
  type VaultScanner,
} from "@vault-mcp-bridge/agent-core";
import {
  OpaqueIdSchema,
  SnapshotSchema,
  canonicalJson,
  sha256Base64Url,
  type Snapshot,
} from "@vault-mcp-bridge/contracts";

const SSH_HOST_RE = /^[A-Za-z0-9._-]{1,255}$/u;
const SSH_USER_RE = /^[A-Za-z0-9._-]{1,253}$/u;
const PROJECT_RE = /^[a-z0-9][a-z0-9_-]{1,62}$/u;
const REMOTE_DIRECTORY_RE = /^\/(?:[A-Za-z0-9._-]+\/){1,20}[A-Za-z0-9._-]{2,128}$/u;
const BROAD_REMOTE_DIRECTORIES = new Set(["/", "/etc", "/home", "/opt", "/private", "/root", "/srv", "/tmp", "/usr", "/var"]);
const DEFAULT_INCLUDE = ["**/*.md", "**/*.canvas", "**/*.base"];
const DEFAULT_EXCLUDE = [".obsidian/**", "**/.obsidian/**", "**/.git/**", "**/.*", "**/node_modules/**"];

export type PrivateSyncConfig = {
  version: 1;
  vaultRoot: string;
  vaultId: string;
  deviceId: string;
  sshHost: string;
  sshUser?: string;
  sshPort?: number;
  sshKnownHostsFile?: string;
  sshHostKeyAlias?: string;
  sshHostKeyAlgorithm?: "ssh-ed25519" | "ecdsa-sha2-nistp256" | "ssh-rsa";
  remoteDirectory: string;
  projectName: string;
  include: string[];
  exclude: string[];
};

type PrivateSyncState = {
  version: 1;
  idKey: string;
  lastGeneration: number;
  lastProjectionDigest?: string;
  lastProjection?: ProjectionEntry[];
  lastReceipt?: unknown;
};

type PendingSnapshot = {
  version: 1;
  projectionDigest: string;
  projection?: ProjectionEntry[];
  changes?: PrivateSyncChanges;
  snapshot: Snapshot;
};

type ProjectionEntry = {
  id: string;
  sourceHash: string;
  bytes: number;
};

export type PrivateSyncChanges = {
  added: number;
  modified: number;
  removed: number;
  unchanged: number;
  total: number;
  bytes: number;
};

export type PrivateSyncReceipt = {
  status: "uploaded" | "unchanged";
  generation: number;
  documentCount: number;
  changes: PrivateSyncChanges;
  digest?: string;
};

export type SnapshotUploader = (input: {
  config: PrivateSyncConfig;
  snapshotJson: string;
}) => Promise<unknown>;

const atomicWriteJson = async (path: string, value: unknown): Promise<void> => {
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  const temporary = `${path}.${process.pid}.${Date.now()}.tmp`;
  const handle = await open(temporary, "wx", 0o600);
  try {
    await handle.writeFile(`${JSON.stringify(value)}\n`, "utf8");
    await handle.sync();
  } finally {
    await handle.close();
  }
  await chmod(temporary, 0o600).catch(() => undefined);
  await rename(temporary, path);
  await chmod(path, 0o600).catch(() => undefined);
};

const readJson = async <T>(path: string): Promise<T | undefined> => {
  try {
    return JSON.parse(await readFile(path, "utf8")) as T;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
    throw error;
  }
};

const stringList = (value: unknown, fallback: readonly string[]): string[] => {
  if (value === undefined) return [...fallback];
  if (!Array.isArray(value) || value.length > 256 || value.some((entry) => typeof entry !== "string" || entry.length < 1 || entry.length > 1024)) {
    throw new Error("private sync include/exclude patterns are invalid");
  }
  return [...value];
};

export const validatePrivateSyncConfig = (value: unknown): PrivateSyncConfig => {
  if (!value || typeof value !== "object") throw new Error("private sync config is invalid");
  const candidate = value as Record<string, unknown>;
  if (candidate.version !== 1) throw new Error("private sync config version is unsupported");
  const vaultRoot = typeof candidate.vaultRoot === "string" ? candidate.vaultRoot : "";
  if (!isAbsolute(vaultRoot) || resolve(vaultRoot) !== vaultRoot) throw new Error("vaultRoot must be an absolute normalized path");
  const vaultId = OpaqueIdSchema.parse(candidate.vaultId);
  const deviceId = OpaqueIdSchema.parse(candidate.deviceId);
  const sshHost = typeof candidate.sshHost === "string" && SSH_HOST_RE.test(candidate.sshHost) ? candidate.sshHost : "";
  const sshUser = candidate.sshUser === undefined
    ? undefined
    : typeof candidate.sshUser === "string" && SSH_USER_RE.test(candidate.sshUser)
      ? candidate.sshUser
      : "";
  const sshPort = candidate.sshPort === undefined ? undefined : Number(candidate.sshPort);
  const sshKnownHostsFile = candidate.sshKnownHostsFile === undefined
    ? undefined
    : typeof candidate.sshKnownHostsFile === "string" && isAbsolute(candidate.sshKnownHostsFile) && resolve(candidate.sshKnownHostsFile) === candidate.sshKnownHostsFile
      ? candidate.sshKnownHostsFile
      : "";
  const sshHostKeyAlias = candidate.sshHostKeyAlias === undefined
    ? undefined
    : typeof candidate.sshHostKeyAlias === "string" && SSH_HOST_RE.test(candidate.sshHostKeyAlias)
      ? candidate.sshHostKeyAlias
      : "";
  const sshHostKeyAlgorithm = candidate.sshHostKeyAlgorithm === undefined
    ? undefined
    : ["ssh-ed25519", "ecdsa-sha2-nistp256", "ssh-rsa"].includes(String(candidate.sshHostKeyAlgorithm))
      ? candidate.sshHostKeyAlgorithm as PrivateSyncConfig["sshHostKeyAlgorithm"]
      : "";
  const remoteDirectory = typeof candidate.remoteDirectory === "string" &&
    REMOTE_DIRECTORY_RE.test(candidate.remoteDirectory) &&
    !candidate.remoteDirectory.includes("..") &&
    !BROAD_REMOTE_DIRECTORIES.has(candidate.remoteDirectory)
    ? candidate.remoteDirectory
    : "";
  const projectName = typeof candidate.projectName === "string" && PROJECT_RE.test(candidate.projectName) ? candidate.projectName : "";
  if (
    !sshHost ||
    sshUser === "" ||
    (sshPort !== undefined && (!Number.isInteger(sshPort) || sshPort < 1 || sshPort > 65_535)) ||
    sshKnownHostsFile === "" ||
    sshHostKeyAlias === "" ||
    sshHostKeyAlgorithm === "" ||
    (sshKnownHostsFile !== undefined && sshHostKeyAlgorithm === undefined) ||
    (sshHostKeyAlias !== undefined && sshKnownHostsFile === undefined) ||
    ((sshUser !== undefined || sshPort !== undefined) && sshKnownHostsFile === undefined) ||
    !remoteDirectory ||
    !projectName
  ) throw new Error("private sync SSH target is invalid");
  return {
    version: 1,
    vaultRoot,
    vaultId,
    deviceId,
    sshHost,
    ...(sshUser ? { sshUser } : {}),
    ...(sshPort !== undefined ? { sshPort } : {}),
    ...(sshKnownHostsFile ? { sshKnownHostsFile } : {}),
    ...(sshHostKeyAlias ? { sshHostKeyAlias } : {}),
    ...(sshHostKeyAlgorithm ? { sshHostKeyAlgorithm } : {}),
    remoteDirectory,
    projectName,
    include: stringList(candidate.include, DEFAULT_INCLUDE),
    exclude: stringList(candidate.exclude, DEFAULT_EXCLUDE),
  };
};

const projectionDigest = (scan: ScanResult): string => sha256Base64Url(canonicalJson(
  [...scan.files]
    .map((file) => ({
      id: file.id ?? "",
      title: file.title ?? "",
      mediaType: file.contentType,
      sourceHash: file.sha256 ?? sha256Base64Url(file.content),
      modifiedAt: file.modifiedAt ?? "",
      metadata: file.metadata ?? null,
    }))
    .sort((left, right) => left.id.localeCompare(right.id)),
));

const projection = (scan: ScanResult): ProjectionEntry[] => [...scan.files]
  .map((file) => ({
    id: file.id ?? "",
    sourceHash: file.sha256 ?? sha256Base64Url(file.content),
    bytes: file.bytes,
  }))
  .sort((left, right) => left.id.localeCompare(right.id));

const changesBetween = (before: readonly ProjectionEntry[], after: readonly ProjectionEntry[]): PrivateSyncChanges => {
  const previous = new Map(before.map((entry) => [entry.id, entry]));
  let added = 0;
  let modified = 0;
  let unchanged = 0;
  for (const entry of after) {
    const prior = previous.get(entry.id);
    if (!prior) added += 1;
    else if (prior.sourceHash !== entry.sourceHash) modified += 1;
    else unchanged += 1;
    previous.delete(entry.id);
  }
  return {
    added,
    modified,
    removed: previous.size,
    unchanged,
    total: after.length,
    bytes: after.reduce((total, entry) => total + entry.bytes, 0),
  };
};

const commandArgument = (value: string): string => `'${value.replaceAll("'", "'\\''")}'`;

export const userKnownHostsFileOption = (path: string): string => {
  if (!isAbsolute(path) || /[\0\r\n]/u.test(path)) throw new Error("private sync known_hosts path is invalid");
  const quoted = path.replaceAll("\\", "\\\\").replaceAll('"', '\\"');
  return `UserKnownHostsFile="${quoted}"`;
};

export const hostKeyAliasOption = (host: string, port: number): string => {
  if (!SSH_HOST_RE.test(host) || !Number.isInteger(port) || port < 1 || port > 65_535) {
    throw new Error("private sync host-key alias is invalid");
  }
  return `HostKeyAlias=${port === 22 ? host : `[${host}]:${port}`}`;
};

export const buildPrivateImportCommand = (config: PrivateSyncConfig): string => {
  const validated = validatePrivateSyncConfig(config);
  return [
    "cd", commandArgument(validated.remoteDirectory), "&&", "exec",
    "docker", "compose", "--env-file", ".env", "-f", "compose.yaml",
    "exec", "-T", "runtime", "node", "dist/cli.js", "private-import",
    "--vault-id", commandArgument(validated.vaultId),
    "--device-id", commandArgument(validated.deviceId),
  ].join(" ");
};

const collectBounded = (stream: NodeJS.ReadableStream, maximumBytes: number): Promise<string> => new Promise((resolveValue, reject) => {
  const chunks: Buffer[] = [];
  let bytes = 0;
  stream.on("data", (chunk: Buffer | string) => {
    const value = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    bytes += value.length;
    if (bytes > maximumBytes) {
      reject(new Error("private sync command output exceeded its limit"));
      return;
    }
    chunks.push(value);
  });
  stream.on("end", () => resolveValue(Buffer.concat(chunks).toString("utf8")));
  stream.on("error", reject);
});

export const writeSnapshotInput = (input: Writable, snapshotJson: string): Promise<Error | undefined> => new Promise((resolveValue) => {
  let settled = false;
  const finish = (error?: unknown): void => {
    if (settled) return;
    settled = true;
    resolveValue(error === undefined ? undefined : error instanceof Error ? error : new Error(String(error)));
  };
  input.once("error", finish);
  input.once("finish", () => finish());
  try {
    input.end(snapshotJson, "utf8");
  } catch (error) {
    finish(error);
  }
});

export const uploadSnapshotOverSsh: SnapshotUploader = async ({ config, snapshotJson }) => {
  const validated = validatePrivateSyncConfig(config);
  const destination = validated.sshUser ? `${validated.sshUser}@${validated.sshHost}` : validated.sshHost;
  const sshArguments = [
    "-o", "BatchMode=yes",
    "-o", "ConnectTimeout=15",
    "-o", "ForwardAgent=no",
    "-o", "ForwardX11=no",
    "-o", "ClearAllForwardings=yes",
    "-o", "RequestTTY=no",
    ...(validated.sshKnownHostsFile
      ? ["-o", "StrictHostKeyChecking=yes", "-o", userKnownHostsFileOption(validated.sshKnownHostsFile)]
      : []),
    ...(validated.sshHostKeyAlias
      ? ["-o", hostKeyAliasOption(validated.sshHostKeyAlias, validated.sshPort ?? 22)]
      : []),
    ...(validated.sshHostKeyAlgorithm
      ? ["-o", `HostKeyAlgorithms=${privateHostKeyAlgorithms(validated.sshHostKeyAlgorithm)}`]
      : []),
    ...(validated.sshPort !== undefined ? ["-p", String(validated.sshPort)] : []),
    "--", destination,
    buildPrivateImportCommand(validated),
  ];
  const child = spawn("/usr/bin/ssh", sshArguments, { stdio: ["pipe", "pipe", "pipe"], windowsHide: true });
  const stdout = collectBounded(child.stdout, 64 * 1024);
  const stderr = collectBounded(child.stderr, 128 * 1024);
  const input = writeSnapshotInput(child.stdin, snapshotJson);
  const output = Promise.all([stdout, stderr, input]).then(
    ([out, err, inputError]) => ({ ok: true as const, out, err, inputError }),
    (error: unknown) => ({ ok: false as const, error })
  );
  const timeout = setTimeout(() => child.kill("SIGTERM"), 120_000);
  const exitCode = await new Promise<number | null>((resolveValue, reject) => {
    child.once("error", reject);
    child.once("close", resolveValue);
  }).finally(() => clearTimeout(timeout));
  const collected = await output;
  if (!collected.ok) throw collected.error;
  if (exitCode !== 0 || collected.inputError) {
    throw new Error(`private sync SSH import failed: ${safeErrorMessage(collected.err || collected.inputError || `exit ${String(exitCode)}`)}`);
  }
  const lines = collected.out.trim().split(/\r?\n/u).filter(Boolean);
  if (lines.length !== 1) throw new Error("private sync receipt is invalid");
  try {
    return JSON.parse(lines[0]!) as unknown;
  } catch {
    throw new Error("private sync receipt is invalid");
  }
};

const privateHostKeyAlgorithms = (value: NonNullable<PrivateSyncConfig["sshHostKeyAlgorithm"]>): string => {
  switch (value) {
    case "ssh-rsa": return "rsa-sha2-512,rsa-sha2-256";
    case "ssh-ed25519": return "ssh-ed25519";
    case "ecdsa-sha2-nistp256": return "ecdsa-sha2-nistp256";
  }
};

export const runPrivateSync = async (options: {
  configPath: string;
  scanner?: VaultScanner;
  uploader?: SnapshotUploader;
  now?: () => Date;
}): Promise<PrivateSyncReceipt> => {
  const configPath = resolve(options.configPath);
  const dataDirectory = dirname(configPath);
  await mkdir(dataDirectory, { recursive: true, mode: 0o700 });
  await chmod(dataDirectory, 0o700).catch(() => undefined);
  const config = validatePrivateSyncConfig(await readJson<unknown>(configPath));
  const statePath = join(dataDirectory, "sync-state.json");
  const pendingPath = join(dataDirectory, "pending-snapshot.json");
  let state = await readJson<PrivateSyncState>(statePath);
  if (!state) {
    state = { version: 1, idKey: randomBytes(32).toString("base64url"), lastGeneration: 0 };
    await atomicWriteJson(statePath, state);
  }
  if (state.version !== 1 || !/^[A-Za-z0-9_-]{43}$/u.test(state.idKey) || !Number.isSafeInteger(state.lastGeneration) || state.lastGeneration < 0) {
    throw new Error("private sync state is invalid");
  }

  let pending = await readJson<PendingSnapshot>(pendingPath);
  if (pending) {
    const parsed = SnapshotSchema.safeParse(pending.snapshot);
    if (pending.version !== 1 || !parsed.success || parsed.data.vaultId !== config.vaultId) throw new Error("pending private snapshot is invalid");
    pending = { ...pending, snapshot: parsed.data };
  } else {
    const scanner = options.scanner ?? new DefaultVaultScanner(Buffer.from(state.idKey, "base64url"));
    const scan = await scanner.scan(config.vaultRoot, {
      include: config.include,
      exclude: config.exclude,
      vaultId: config.vaultId,
    });
    if (scan.errors.length > 0) throw new Error(`vault scan is incomplete (${scan.errors.length} item(s))`);
    const digest = projectionDigest(scan);
    const currentProjection = projection(scan);
    if (state.lastProjectionDigest === digest) {
      if (!state.lastProjection) {
        state = { ...state, lastProjection: currentProjection };
        await atomicWriteJson(statePath, state);
      }
      return {
        status: "unchanged",
        generation: state.lastGeneration,
        documentCount: scan.files.length,
        changes: changesBetween(currentProjection, currentProjection),
      };
    }
    const payload = buildSnapshot(scan, config.vaultId, state.lastGeneration + 1, (options.now ?? (() => new Date()))().toISOString());
    pending = {
      version: 1,
      projectionDigest: digest,
      projection: currentProjection,
      changes: changesBetween(state.lastProjection ?? [], currentProjection),
      snapshot: SnapshotSchema.parse(payload.snapshot),
    };
    await atomicWriteJson(pendingPath, pending);
  }

  const payload = {
    snapshot: pending.snapshot,
    body: JSON.stringify(pending.snapshot),
    snapshotId: pending.snapshot.snapshotId,
    generation: pending.snapshot.generation,
  };
  const receipt = await (options.uploader ?? uploadSnapshotOverSsh)({ config, snapshotJson: payload.body });
  if (!receiptMatches(receipt, payload, config.vaultId)) throw new Error("private sync receipt does not match the snapshot");
  state = {
    ...state,
    lastGeneration: pending.snapshot.generation,
    lastProjectionDigest: pending.projectionDigest,
    ...(pending.projection ? { lastProjection: pending.projection } : {}),
    lastReceipt: receipt,
  };
  await atomicWriteJson(statePath, state);
  await unlink(pendingPath).catch((error: unknown) => {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  });
  return {
    status: "uploaded",
    generation: pending.snapshot.generation,
    documentCount: pending.snapshot.documents.length,
    changes: pending.changes ?? {
      added: pending.snapshot.documents.length,
      modified: 0,
      removed: 0,
      unchanged: 0,
      total: pending.snapshot.documents.length,
      bytes: pending.snapshot.documents.reduce((total, document) => total + Buffer.byteLength(document.text, "utf8"), 0),
    },
    digest: pending.snapshot.digest,
  };
};
