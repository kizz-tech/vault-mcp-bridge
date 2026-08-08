import { chmod, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Readable } from "node:stream";

import { describe, expect, it } from "vitest";

import { agentStatus, parseAgentCommand, readAgentSetupPlan, readRuntimeKeyFromStdin, validateAgentSetupPlan } from "../src/agent-command.js";
import { EMPTY_STATE } from "../src/types.js";

const plan = (vaultRoot: string) => ({
  version: 1,
  vaultRoot,
  server: { host: "server.example.invalid", user: "operator", port: 22 },
  openai: { tunnelId: `tunnel_${"a".repeat(32)}` }
});

describe("Codex-facing agent command contract", () => {
  it("accepts only the bounded two-phase command grammar", () => {
    expect(parseAgentCommand(["status", "--json"])).toEqual({ name: "status" });
    expect(parseAgentCommand(["prepare", "--config", "/tmp/private-plan.json", "--runtime-key-stdin", "--json"])).toEqual({
      name: "prepare",
      configPath: "/tmp/private-plan.json",
      runtimeKeyStdin: true
    });
    expect(parseAgentCommand(["setup", "--approve-host-fingerprint", "SHA256/example", "--json"])).toEqual({
      name: "setup",
      approvedFingerprint: "SHA256/example"
    });
    expect(() => parseAgentCommand(["setup", "--trust-any-host"])).toThrow(/agent_command_invalid/u);
    expect(() => parseAgentCommand(["prepare", "--config", "relative.json", "--runtime-key-stdin"])).toThrow(/path/u);
  });

  it("keeps the non-secret setup plan strict and private", async () => {
    expect(validateAgentSetupPlan(plan("/tmp/synthetic-vault"))).toEqual(plan("/tmp/synthetic-vault"));
    expect(() => validateAgentSetupPlan({ ...plan("/tmp/synthetic-vault"), runtimeKey: "secret" })).toThrow(/config/u);
    const directory = await mkdtemp(join(tmpdir(), "vmb-agent-plan-"));
    const path = join(directory, "plan.json");
    await writeFile(path, JSON.stringify(plan("/tmp/synthetic-vault")), { mode: 0o600 });
    expect(await readAgentSetupPlan(path)).toEqual(plan("/tmp/synthetic-vault"));
    await chmod(path, 0o644);
    await expect(readAgentSetupPlan(path)).rejects.toThrow(/permissions/u);
  });

  it("reads a bounded runtime key without returning it in status", async () => {
    const key = "TEST_RUNTIME_API_KEY_000000000";
    expect(await readRuntimeKeyFromStdin(Readable.from([`${key}\n`]))).toBe(key);
    await expect(readRuntimeKeyFromStdin(Readable.from(["short"]))).rejects.toThrow(/runtime_key/u);
    const status = agentStatus({
      ...EMPTY_STATE,
      vault: { name: "Private name", noteCount: 12, bytes: 42 },
      server: { label: "private-host", host: "private-host", user: "operator", port: 22, connected: false }
    });
    expect(JSON.stringify(status)).not.toContain("Private name");
    expect(JSON.stringify(status)).not.toContain("private-host");
  });
});
