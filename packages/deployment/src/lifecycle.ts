import { spawn } from "node:child_process";
import { isAbsolute, resolve } from "node:path";
import type { CommandResult, CommandRunner, ComposeOperation, LifecycleOptions, LifecycleResult } from "./types.js";
import { assertProjectName, projectNameForInstallation } from "./validation.js";

const COMMAND_OUTPUT_LIMIT = 128 * 1024;
const ALLOWED_SERVICES = new Set(["server", "tunnel"]);

function bounded(value: string): string {
  if (Buffer.byteLength(value, "utf8") <= COMMAND_OUTPUT_LIMIT) return value;
  return `${value.slice(0, COMMAND_OUTPUT_LIMIT - 32)}\n[output truncated]`;
}

function assertComposeFile(file: string): string {
  if (!isAbsolute(file)) throw new TypeError("Compose file must be an absolute path");
  const resolved = resolve(file);
  if (!resolved.endsWith(".yaml") && !resolved.endsWith(".yml")) throw new TypeError("Compose file must be YAML");
  return resolved;
}

export function composeCommand(projectName: string, composeFile: string, operation: ComposeOperation, service?: string): readonly string[] {
  assertProjectName(projectName);
  const file = assertComposeFile(composeFile);
  const prefix = ["compose", "--project-name", projectName, "--file", file, "--ansi", "never"];
  switch (operation) {
    case "config":
      return [...prefix, "config", "--quiet"];
    case "pull":
      return [...prefix, "pull", "--quiet"];
    case "start":
      return [...prefix, "up", "--detach", "--no-build"];
    case "stop":
      return [...prefix, "stop", "--timeout", "30"];
    case "status":
      return [...prefix, "ps", "--format", "json"];
    case "logs":
      if (!service || !ALLOWED_SERVICES.has(service)) throw new TypeError("Logs service must be server or tunnel");
      return [...prefix, "logs", "--no-color", "--tail", "200", service];
    case "rollback":
      return [...prefix, "up", "--detach", "--no-build"];
  }
}

export function composeDownCommand(projectName: string, composeFile: string, removeReplica: boolean): readonly string[] {
  assertProjectName(projectName);
  const file = assertComposeFile(composeFile);
  const prefix = ["compose", "--project-name", projectName, "--file", file, "--ansi", "never"];
  return removeReplica
    ? [...prefix, "down", "--timeout", "30", "--volumes"]
    : [...prefix, "down", "--timeout", "30"];
}

export class NodeCommandRunner implements CommandRunner {
  public run(command: string, args: readonly string[], options: Parameters<CommandRunner["run"]>[2] = {}): Promise<CommandResult> {
    if (command !== "docker") {
      throw new TypeError("Deployment runner only permits the docker executable");
    }
    return new Promise((resolvePromise, reject) => {
      const child = spawn(command, [...args], {
        cwd: options.cwd,
        env: options.env ? { ...process.env, ...options.env } : process.env,
        shell: false,
        stdio: ["ignore", "pipe", "pipe"]
      });
      const stdout: Buffer[] = [];
      const stderr: Buffer[] = [];
      let stdoutBytes = 0;
      let stderrBytes = 0;
      const collect = (target: Buffer[], value: Buffer, current: number): number => {
        const remaining = Math.max(0, COMMAND_OUTPUT_LIMIT - current);
        if (remaining > 0) target.push(value.subarray(0, remaining));
        return current + value.byteLength;
      };
      child.stdout.on("data", (chunk: Buffer) => { stdoutBytes = collect(stdout, chunk, stdoutBytes); });
      child.stderr.on("data", (chunk: Buffer) => { stderrBytes = collect(stderr, chunk, stderrBytes); });
      let timer: NodeJS.Timeout | undefined;
      const abort = (): void => { child.kill("SIGTERM"); };
      if (options.timeoutMs && options.timeoutMs > 0) timer = setTimeout(abort, options.timeoutMs);
      options.signal?.addEventListener("abort", abort, { once: true });
      child.once("error", (error) => {
        if (timer) clearTimeout(timer);
        reject(error);
      });
      child.once("close", (code, signal) => {
        if (timer) clearTimeout(timer);
        options.signal?.removeEventListener("abort", abort);
        const stdoutValue = bounded(Buffer.concat(stdout).toString("utf8"));
        const stderrValue = bounded(Buffer.concat(stderr).toString("utf8"));
        resolvePromise({ code: code ?? (signal ? 128 : 1), stdout: stdoutValue, stderr: stderrValue });
      });
    });
  }
}

export class ComposeLifecycle {
  public constructor(private readonly options: LifecycleOptions) {
    assertProjectName(options.project.projectName);
    if (options.project.projectName !== projectNameForInstallation(options.project.installationId)) {
      throw new Error("Compose project does not match its installation id");
    }
    assertComposeFile(options.composeFile);
  }

  public async run(operation: ComposeOperation, service?: string): Promise<LifecycleResult> {
    const command = composeCommand(this.options.project.projectName, this.options.composeFile, operation, service);
    return this.execute(operation, command);
  }

  public async update(): Promise<readonly LifecycleResult[]> {
    const pull = await this.run("pull");
    const start = await this.run("start");
    return [pull, start];
  }

  /** Stop and remove only this project's containers and networks. */
  public async remove(options: { readonly removeReplica: boolean }): Promise<LifecycleResult> {
    const command = composeDownCommand(this.options.project.projectName, this.options.composeFile, options.removeReplica);
    return this.execute("stop", command);
  }

  private async execute(operation: ComposeOperation | "stop", command: readonly string[]): Promise<LifecycleResult> {
    const [executable, ...args] = command;
    if (!executable) throw new Error("Missing Compose executable");
    const runOptions = this.options.timeoutMs === undefined ? undefined : { timeoutMs: this.options.timeoutMs };
    const result = await this.options.runner.run("docker", [executable, ...args], runOptions);
    if (result.code !== 0) {
      throw new Error(`Compose ${operation} failed with exit code ${result.code}: ${result.stderr.slice(0, 512)}`);
    }
    return { operation: operation === "stop" ? "stop" : operation, command: ["docker", ...command], result };
  }
}
