import { createHash, randomUUID } from "node:crypto";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { chmod, mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname } from "node:path";

import type { ServerInput } from "./types.js";

export interface CommandResult {
  code: number;
  stdout: string;
  stderr: string;
}

export interface CommandRunner {
  run(command: string, args: readonly string[], options?: { timeoutMs?: number }): Promise<CommandResult>;
}

export interface SftpRunner {
  run(args: readonly string[], batch: string, options?: { timeoutMs?: number }): Promise<CommandResult>;
}

export interface SecretUploader {
  ensureDirectory(remoteDirectory: string): Promise<void>;
  upload(localPath: string, remotePath: string): Promise<void>;
}

export interface SshTarget {
  host: string;
  user: string;
  port: number;
  hostKeyFingerprint?: string;
}

export interface HostKeyStatus {
  fingerprint: string | null;
  changed: boolean;
}

export interface HostKeyPinStore {
  get(target: SshTarget): Promise<string | null>;
  put(target: SshTarget, fingerprint: string): Promise<void>;
  remove(target: SshTarget): Promise<void>;
}

export interface HostKeyRecord {
  fingerprint: string;
  line: string;
}

export interface KnownHostsWriter {
  write(target: SshTarget, keyscanLine: string): Promise<void>;
}

/** Non-secret test/dev implementation. Production uses FileHostKeyPinStore. */
export class MemoryHostKeyPinStore implements HostKeyPinStore {
  private readonly pins = new Map<string, string>();
  async get(target: SshTarget): Promise<string | null> { return this.pins.get(hostPinKey(target)) ?? null; }
  async put(target: SshTarget, fingerprint: string): Promise<void> { this.pins.set(hostPinKey(target), normalizeFingerprint(fingerprint)); }
  async remove(target: SshTarget): Promise<void> { this.pins.delete(hostPinKey(target)); }
}

/** Small atomic JSON pin file; host keys are not credentials but stay private to the app. */
export class FileHostKeyPinStore implements HostKeyPinStore {
  private pins: Record<string, string> | null = null;
  private operation: Promise<void> = Promise.resolve();

  constructor(private readonly filePath: string) {}

  async get(target: SshTarget): Promise<string | null> {
    return this.withLock(async () => (await this.load())[hostPinKey(target)] ?? null);
  }

  async put(target: SshTarget, fingerprint: string): Promise<void> {
    const normalized = normalizeFingerprint(fingerprint);
    await this.withLock(async () => {
      const pins = await this.load();
      pins[hostPinKey(target)] = normalized;
      await this.persist(pins);
    });
  }

  async remove(target: SshTarget): Promise<void> {
    await this.withLock(async () => {
      const pins = await this.load();
      delete pins[hostPinKey(target)];
      await this.persist(pins);
    });
  }

  private async load(): Promise<Record<string, string>> {
    if (this.pins) return { ...this.pins };
    try {
      const parsed: unknown = JSON.parse(await readFile(this.filePath, "utf8"));
      if (!parsed || typeof parsed !== "object") throw new Error("invalid host pin file");
      const pins: Record<string, string> = {};
      for (const [key, value] of Object.entries(parsed)) {
        if (typeof value === "string") pins[key] = normalizeFingerprint(value);
      }
      this.pins = pins;
      return { ...pins };
    } catch (error) {
      if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") {
        this.pins = {};
        return {};
      }
      throw new Error("Host key pins are unreadable");
    }
  }

  private async persist(pins: Record<string, string>): Promise<void> {
    await mkdir(dirname(this.filePath), { recursive: true, mode: 0o700 });
    const temporary = `${this.filePath}.${process.pid}.tmp`;
    await writeFile(temporary, `${JSON.stringify(pins)}\n`, { encoding: "utf8", mode: 0o600 });
    await rename(temporary, this.filePath);
    this.pins = { ...pins };
  }

  private async withLock<T>(operation: () => Promise<T>): Promise<T> {
    const previous = this.operation;
    let release!: () => void;
    this.operation = new Promise<void>((resolve) => { release = resolve; });
    await previous;
    try { return await operation(); } finally { release(); }
  }
}

/**
 * App-private known_hosts writer. It never touches ~/.ssh/known_hosts and
 * keeps the file mode at 0600 so OpenSSH's strict host-key checks can consume
 * the TOFU result without mutating a user's global SSH configuration.
 */
export class FileKnownHostsWriter implements KnownHostsWriter {
  constructor(private readonly filePath: string) {}

  async write(target: SshTarget, keyscanLine: string): Promise<void> {
    const fields = keyscanLine.trim().split(/\s+/u);
    const keyType = fields[1];
    const key = fields[2];
    if (!keyType || !key || !/^[A-Za-z0-9][A-Za-z0-9@._+-]*$/u.test(keyType) || !/^[A-Za-z0-9+/]+={0,2}$/u.test(key)) {
      throw new TypeError("Invalid host key record");
    }
    const host = target.port === 22 ? target.host : `[${target.host}]:${target.port}`;
    const record = `${host} ${keyType} ${key}`;
    let current = "";
    try {
      current = await readFile(this.filePath, "utf8");
    } catch (error) {
      if (!isNotFound(error)) throw new Error("App host-key file is unreadable");
    }
    if (!current.split("\n").some((line) => line.trim() === record)) {
      current = `${current.replace(/\s*$/u, "")}${current.trim() ? "\n" : ""}${record}\n`;
      await mkdir(dirname(this.filePath), { recursive: true, mode: 0o700 });
      const temporary = `${this.filePath}.${process.pid}.tmp`;
      await writeFile(temporary, current, { encoding: "utf8", mode: 0o600 });
      await rename(temporary, this.filePath);
    }
    // chmod after both the existing and append paths prevents a pre-existing
    // file from weakening the strict known_hosts boundary.
    await chmod(this.filePath, 0o600);
  }
}

export const SSH_SAFE_OPTIONS = Object.freeze([
  "BatchMode=yes",
  "StrictHostKeyChecking=yes",
  "ForwardAgent=no",
  "ForwardX11=no",
  "ClearAllForwardings=yes",
  "IdentitiesOnly=no",
  "RequestTTY=no",
  "ConnectTimeout=15"
]);

const SSH_COMMAND = "/usr/bin/ssh";
const SSH_KEYSCAN_COMMAND = "/usr/bin/ssh-keyscan";
const SFTP_COMMAND = "/usr/bin/sftp";
const MAX_COMMAND_OUTPUT_BYTES = 256 * 1024;

export class SshCommandError extends Error {
  constructor(
    message: string,
    readonly result: CommandResult
  ) {
    super(message);
    this.name = "SshCommandError";
  }
}

export class HostKeyChangedError extends Error {
  constructor(readonly target: SshTarget, readonly expected: string, readonly actual: string) {
    super("Server identity changed");
    this.name = "HostKeyChangedError";
  }
}

export class OpenSshAdapter {
  constructor(
    private readonly runner: CommandRunner = new SpawnCommandRunner(),
    private readonly knownHostsFile?: string,
    private readonly knownHostsWriter: KnownHostsWriter | undefined = knownHostsFile
      ? new FileKnownHostsWriter(knownHostsFile)
      : undefined
  ) {}

  static fromInput(input: ServerInput & { hostKeyFingerprint?: string }): SshTarget {
    const host = input.host.trim();
    const user = input.user.trim();
    const port = Number(input.port);
    assertSshToken(host, "host");
    assertSshToken(user, "user");
    if (!Number.isInteger(port) || port < 1 || port > 65_535) throw new TypeError("Invalid SSH port");
    return input.hostKeyFingerprint
      ? { host, user, port, hostKeyFingerprint: normalizeFingerprint(input.hostKeyFingerprint) }
      : { host, user, port };
  }

  /** Resolve ~/.ssh/config aliases without opening a session. */
  async resolve(target: SshTarget): Promise<SshTarget> {
    const result = await this.runner.run(SSH_COMMAND, this.args(target, { configOnly: true }), { timeoutMs: 10_000 });
    if (result.code !== 0) throw new SshCommandError("SSH configuration could not be resolved", result);
    const values = parseSshConfig(result.stdout);
    const host = values.hostname ?? target.host;
    const user = values.user ?? target.user;
    const port = values.port ? Number(values.port) : target.port;
    assertSshToken(host, "host");
    assertSshToken(user, "user");
    if (!Number.isInteger(port) || port < 1 || port > 65_535) throw new TypeError("SSH config returned an invalid port");
    return {
      host,
      user,
      port,
      ...(target.hostKeyFingerprint ? { hostKeyFingerprint: target.hostKeyFingerprint } : {})
    };
  }

  /** Obtain a candidate key fingerprint for explicit user confirmation. */
  async readHostFingerprint(target: SshTarget): Promise<string | null> {
    const record = await this.readHostKey(target);
    return record?.fingerprint ?? null;
  }

  async readHostKey(target: SshTarget): Promise<HostKeyRecord | null> {
    const result = await this.runner.run(
      SSH_KEYSCAN_COMMAND,
      ["-T", "5", "-p", String(target.port), "--", target.host],
      { timeoutMs: 10_000 }
    );
    if (result.code !== 0 || !result.stdout.trim()) return null;
    const key = result.stdout
      .split("\n")
      .map((line) => line.trim())
      .find((line) => line && !line.startsWith("#"));
    if (!key) return null;
    const fields = key.split(/\s+/u);
    const keyType = fields[1];
    const publicKey = fields[2];
    if (!keyType || !publicKey) throw new TypeError("Invalid host key record");
    const host = target.port === 22 ? target.host : `[${target.host}]:${target.port}`;
    return { fingerprint: fingerprintFromKeyscanLine(key), line: `${host} ${keyType} ${publicKey}` };
  }

  /** Compare a candidate against the pinned identity and fail closed on change. */
  verifyHostFingerprint(target: SshTarget, actual: string): HostKeyStatus {
    const fingerprint = normalizeFingerprint(actual);
    if (!target.hostKeyFingerprint) return { fingerprint, changed: false };
    const expected = normalizeFingerprint(target.hostKeyFingerprint);
    if (expected !== fingerprint) throw new HostKeyChangedError(target, expected, fingerprint);
    return { fingerprint, changed: false };
  }

  /**
   * Resolve the TOFU flow without hiding it in the UI: the caller's
   * `confirm` callback is the explicit native fingerprint confirmation.
   */
  async ensurePinned(
    target: SshTarget,
    pins: HostKeyPinStore,
    confirm: (fingerprint: string) => Promise<boolean>
  ): Promise<SshTarget> {
    const resolved = await this.resolve(target);
    if (!this.knownHostsFile || !this.knownHostsWriter) throw new Error("App-private known_hosts file is required");
    const record = await this.readHostKey(resolved);
    if (!record) throw new SshCommandError("Server identity unavailable", { code: 1, stdout: "", stderr: "" });
    const actual = record.fingerprint;
    const expected = await pins.get(resolved);
    if (expected) {
      this.verifyHostFingerprint({ ...resolved, hostKeyFingerprint: expected }, actual);
      await this.knownHostsWriter.write(resolved, record.line);
      return { ...resolved, hostKeyFingerprint: expected };
    }
    if (!(await confirm(actual))) throw new Error("Server identity was not confirmed");
    await pins.put(resolved, actual);
    await this.knownHostsWriter.write(resolved, record.line);
    return { ...resolved, hostKeyFingerprint: actual };
  }

  /** Run a harmless server check with bounded, non-interactive OpenSSH options. */
  async check(target: SshTarget): Promise<CommandResult> {
    this.requireAppKnownHosts();
    const resolved = await this.resolve(target);
    const result = await this.runner.run(SSH_COMMAND, this.args(resolved, { remoteCommand: ["true"] }), { timeoutMs: 20_000 });
    if (result.code !== 0) throw new SshCommandError("SSH authentication failed", result);
    return result;
  }

  /**
   * Run one of the product's fixed remote actions. Arbitrary shell text is not
   * accepted here; the orchestrator supplies a bounded argv list.
   */
  async runFixed(target: SshTarget, command: readonly string[], options: { timeoutMs?: number } = {}): Promise<CommandResult> {
    if (!command.length || command.some((part, index) => !isSafeRemoteToken(part) || (index === 0 && part.startsWith("-")))) {
      throw new TypeError("Invalid remote action");
    }
    const timeoutMs = options.timeoutMs ?? 60_000;
    if (!Number.isInteger(timeoutMs) || timeoutMs < 1_000 || timeoutMs > 15 * 60_000) throw new TypeError("Invalid remote action timeout");
    this.requireAppKnownHosts();
    const resolved = await this.resolve(target);
    const result = await this.runner.run(SSH_COMMAND, this.args(resolved, { remoteCommand: [...command] }), { timeoutMs });
    if (result.code !== 0) throw new SshCommandError("Remote setup action failed", result);
    return result;
  }

  private requireAppKnownHosts(): void {
    if (!this.knownHostsFile) throw new Error("App-private known_hosts file is required");
  }

  private args(
    target: SshTarget,
    mode: { configOnly: true } | { remoteCommand: readonly string[] }
  ): string[] {
    const args = ["-p", String(target.port)];
    for (const option of SSH_SAFE_OPTIONS) args.push("-o", option);
    if (this.knownHostsFile) args.push("-o", `UserKnownHostsFile=${this.knownHostsFile}`);
    if ("configOnly" in mode) {
      args.push("-G", `${target.user}@${target.host}`);
    } else {
      args.push(`${target.user}@${target.host}`, ...mode.remoteCommand);
    }
    return args;
  }
}

/**
 * Bounded SFTP staging.  The batch language is generated by this adapter and
 * accepts only paths; callers cannot inject shell commands or arbitrary SFTP
 * operations.  It shares the app-private known_hosts boundary with SSH.
 */
export class OpenSftpAdapter implements SecretUploader {
  constructor(
    private readonly runner: SftpRunner = new SpawnSftpRunner(),
    private readonly knownHostsFile?: string
  ) {}

  async ensureDirectory(_remoteDirectory: string): Promise<void> {
    throw new Error("SFTP target is not bound");
  }

  private async ensureDirectoryForTarget(target: SshTarget, remoteDirectory: string): Promise<void> {
    const directory = assertSftpRemotePath(remoteDirectory);
    const parts = directory.split("/").filter(Boolean);
    let current = "";
    const commands: string[] = [];
    for (const part of parts) {
      current += `/${part}`;
      commands.push(`-mkdir ${sftpQuote(current)}`);
      commands.push(`-chmod 700 ${sftpQuote(current)}`);
    }
    await this.run(target, commands.join("\n") + "\n");
  }

  async upload(_localPath: string, _remotePath: string): Promise<void> {
    throw new Error("SFTP target is not bound");
  }

  private async uploadForTarget(target: SshTarget, localPath: string, remotePath: string): Promise<void> {
    const local = assertSftpLocalPath(localPath);
    const remote = assertSftpRemotePath(remotePath);
    const temporary = `${remote}.part-${randomUUID().replace(/-/gu, "")}`;
    try {
      await this.run(target, `put ${sftpQuote(local)} ${sftpQuote(temporary)}\nchmod 600 ${sftpQuote(temporary)}\nrename ${sftpQuote(temporary)} ${sftpQuote(remote)}\n`);
    } catch (error) {
      await this.run(target, `-rm ${sftpQuote(temporary)}\n`).catch(() => undefined);
      throw error;
    }
  }

  private async run(target: SshTarget, batch: string): Promise<void> {
    if (!this.knownHostsFile) throw new Error("App-private known_hosts file is required");
    const result = await this.runner.run(this.args(target), batch, { timeoutMs: 120_000 });
    if (result.code !== 0) throw new SshCommandError("SFTP staging failed", result);
  }

  /** Bind a verified SSH target for the next bounded transfer. */
  withTarget(target: SshTarget): SecretUploader {
    assertSshTarget(target);
    return {
      ensureDirectory: (remoteDirectory: string): Promise<void> => this.ensureDirectoryForTarget(target, remoteDirectory),
      upload: (localPath: string, remotePath: string): Promise<void> => this.uploadForTarget(target, localPath, remotePath)
    };
  }

  private args(target: SshTarget): string[] {
    assertSshTarget(target);
    const args = ["-P", String(target.port)];
    for (const option of SSH_SAFE_OPTIONS) args.push("-o", option);
    if (this.knownHostsFile) args.push("-o", `UserKnownHostsFile=${this.knownHostsFile}`);
    args.push("-b", "-", `${target.user}@${target.host}`);
    return args;
  }
}

export class SpawnCommandRunner implements CommandRunner {
  async run(command: string, args: readonly string[], options: { timeoutMs?: number } = {}): Promise<CommandResult> {
    const child = spawn(command, [...args], {
      shell: false,
      windowsHide: true,
      stdio: ["ignore", "pipe", "pipe"]
    });
    if (!child.stdout || !child.stderr) throw new Error("OpenSSH pipes unavailable");
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    let stdoutBytes = 0;
    let stderrBytes = 0;
    child.stdout.on("data", (chunk: Buffer) => {
      const remaining = MAX_COMMAND_OUTPUT_BYTES - stdoutBytes;
      if (remaining <= 0) return;
      const bounded = chunk.subarray(0, remaining);
      stdout.push(bounded);
      stdoutBytes += bounded.byteLength;
    });
    child.stderr.on("data", (chunk: Buffer) => {
      const remaining = MAX_COMMAND_OUTPUT_BYTES - stderrBytes;
      if (remaining <= 0) return;
      const bounded = chunk.subarray(0, remaining);
      stderr.push(bounded);
      stderrBytes += bounded.byteLength;
    });
    const timeout = options.timeoutMs ? setTimeout(() => child.kill("SIGTERM"), options.timeoutMs) : undefined;
    try {
      const [result] = (await once(child, "close")) as [number | null];
      return {
        code: result ?? 1,
        stdout: Buffer.concat(stdout).toString("utf8"),
        stderr: Buffer.concat(stderr).toString("utf8")
      };
    } finally {
      if (timeout) clearTimeout(timeout);
    }
  }
}

export class SpawnSftpRunner implements SftpRunner {
  async run(args: readonly string[], batch: string, options: { timeoutMs?: number } = {}): Promise<CommandResult> {
    const child = spawn(SFTP_COMMAND, [...args], {
      shell: false,
      windowsHide: true,
      stdio: ["pipe", "pipe", "pipe"]
    });
    if (!child.stdin || !child.stdout || !child.stderr) throw new Error("SFTP pipes unavailable");
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    let stdoutBytes = 0;
    let stderrBytes = 0;
    child.stdout.on("data", (chunk: Buffer) => {
      const remaining = MAX_COMMAND_OUTPUT_BYTES - stdoutBytes;
      if (remaining <= 0) return;
      const bounded = chunk.subarray(0, remaining);
      stdout.push(bounded);
      stdoutBytes += bounded.byteLength;
    });
    child.stderr.on("data", (chunk: Buffer) => {
      const remaining = MAX_COMMAND_OUTPUT_BYTES - stderrBytes;
      if (remaining <= 0) return;
      const bounded = chunk.subarray(0, remaining);
      stderr.push(bounded);
      stderrBytes += bounded.byteLength;
    });
    child.stdin.end(batch, "utf8");
    const timeout = options.timeoutMs ? setTimeout(() => child.kill("SIGTERM"), options.timeoutMs) : undefined;
    try {
      const [result] = (await once(child, "close")) as [number | null];
      return {
        code: result ?? 1,
        stdout: Buffer.concat(stdout).toString("utf8"),
        stderr: Buffer.concat(stderr).toString("utf8")
      };
    } finally {
      if (timeout) clearTimeout(timeout);
    }
  }
}

function assertSshToken(value: string, label: string): void {
  if (!value || value.length > 253 || /[\s\r\n/\\:@]/u.test(value) || value.startsWith("-")) {
    throw new TypeError(`Invalid SSH ${label}`);
  }
}

function assertSshTarget(target: SshTarget): void {
  assertSshToken(target.host, "host");
  assertSshToken(target.user, "user");
  if (!Number.isInteger(target.port) || target.port < 1 || target.port > 65_535) throw new TypeError("Invalid SSH port");
}

function assertSftpRemotePath(value: string): string {
  if (!value.startsWith("/") || value.length > 2048 || /[\0\r\n]/u.test(value) || /[;&|`$<>]/u.test(value) || value.split("/").some((part) => part === ".." || !/^[A-Za-z0-9._-]*$/u.test(part))) {
    throw new TypeError("Invalid SFTP remote path");
  }
  return value.replace(/\/+/gu, "/").replace(/\/$/u, "") || "/";
}

function assertSftpLocalPath(value: string): string {
  if (!value.startsWith("/") || value.length > 4096 || /[\0\r\n]/u.test(value) || value.split("/").some((part) => part === "..")) throw new TypeError("Invalid SFTP local path");
  return value;
}

function sftpQuote(value: string): string {
  if (/[\0\r\n]/u.test(value)) throw new TypeError("Invalid SFTP path");
  return `"${value.replace(/[\\"]/gu, "\\$&")}"`;
}

function isSafeRemoteToken(value: string): boolean {
  return /^[A-Za-z0-9_./:@=+,-]+$/u.test(value);
}

function isNotFound(error: unknown): boolean {
  return Boolean(error && typeof error === "object" && "code" in error && error.code === "ENOENT");
}

function parseSshConfig(output: string): Record<string, string> {
  const values: Record<string, string> = {};
  for (const line of output.split("\n")) {
    const match = /^([A-Za-z][A-Za-z0-9]*)\s+([^\s]+)\s*$/u.exec(line.trim());
    if (!match) continue;
    const key = match[1]?.toLowerCase();
    const value = match[2];
    if (key && value) values[key] = value;
  }
  return values;
}

function hostPinKey(target: SshTarget): string {
  return createHash("sha256")
    .update(`${target.user}\n${target.host}\n${target.port}`, "utf8")
    .digest("base64url");
}

export function normalizeFingerprint(value: string): string {
  const normalized = value.trim();
  if (!/^SHA256\/[A-Za-z0-9+/=_-]+$/u.test(normalized)) throw new TypeError("Invalid SSH host fingerprint");
  return normalized.replace(/=+$/u, "");
}

export function fingerprintFromKeyscanLine(line: string): string {
  const fields = line.trim().split(/\s+/u);
  const key = fields[2];
  if (!fields[1] || !key || !/^[A-Za-z0-9+/]+={0,2}$/u.test(key)) throw new TypeError("Invalid ssh-keyscan output");
  const digest = createHash("sha256").update(Buffer.from(key, "base64")).digest("base64").replace(/=+$/u, "");
  return `SHA256/${digest}`;
}
