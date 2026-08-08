import { describe, expect, it } from "vitest";

import { HostKeyChangedError, MemoryHostKeyPinStore, OpenSshAdapter, fingerprintFromKeyscanLine, normalizeFingerprint, openSshHostKeyAlgorithms, type CommandResult, type CommandRunner, type KnownHostsWriter, type SshTarget } from "../src/ssh.js";

class FakeRunner implements CommandRunner {
  calls: Array<{ command: string; args: readonly string[] }> = [];
  constructor(private readonly responses: CommandResult[]) {}
  async run(command: string, args: readonly string[]): Promise<CommandResult> {
    this.calls.push({ command, args });
    return this.responses.shift() ?? { code: 0, stdout: "", stderr: "" };
  }
}

class FakeKnownHostsWriter implements KnownHostsWriter {
  lines: string[] = [];
  async write(_target: SshTarget, line: string): Promise<void> { this.lines.push(line); }
}

describe("OpenSSH adapter", () => {
  it("uses argv without shell interpolation and resolves aliases", async () => {
    const runner = new FakeRunner([
      { code: 0, stdout: "hostname real.example.invalid\nuser deploy\nport 2222\n", stderr: "" },
      { code: 0, stdout: "", stderr: "" }
    ]);
    const adapter = new OpenSshAdapter(runner, "/tmp/vault-bridge-known_hosts", new FakeKnownHostsWriter());
    await adapter.check(OpenSshAdapter.fromInput({ host: "alias", user: "deploy", port: 22 }));
    expect(runner.calls[0]?.command).toBe("/usr/bin/ssh");
    expect(runner.calls[0]?.args).toContain("-G");
    expect(runner.calls[0]?.args).not.toContain("shell=true");
    expect(runner.calls[1]?.args).toContain("BatchMode=yes");
    expect(runner.calls[1]?.args).toContain("StrictHostKeyChecking=yes");
    expect(runner.calls[1]?.args).toContain("ForwardX11=no");
    expect(runner.calls[1]?.args).toContain("RequestTTY=no");
    expect(runner.calls[1]?.args).toContain("ConnectTimeout=15");
    expect(runner.calls[1]?.args.at(-1)).toBe("true");
  });

  it("rejects option injection in targets and remote commands", async () => {
    expect(() => OpenSshAdapter.fromInput({ host: "-oProxyCommand=bad", user: "deploy", port: 22 })).toThrow();
    const adapter = new OpenSshAdapter(new FakeRunner([]));
    await expect(adapter.runFixed({ host: "host.example.invalid", user: "deploy", port: 22 }, [])).rejects.toThrow();
    await expect(adapter.runFixed({ host: "host.example.invalid", user: "deploy", port: 22 }, ["-oProxyCommand=bad"])).rejects.toThrow();
    await expect(adapter.runFixed({ host: "host.example.invalid", user: "deploy", port: 22 }, ["true"], { timeoutMs: 999 })).rejects.toThrow();
  });

  it("pins fingerprints and fails closed on change", () => {
    const first = "SHA256/abcDEF_123";
    const adapter = new OpenSshAdapter(new FakeRunner([]));
    expect(adapter.verifyHostFingerprint({ host: "host.example.invalid", user: "deploy", port: 22 }, first).fingerprint).toBe(first);
    expect(() => adapter.verifyHostFingerprint({ host: "host.example.invalid", user: "deploy", port: 22, hostKeyFingerprint: first }, "SHA256/different")).toThrow(HostKeyChangedError);
    expect(normalizeFingerprint("SHA256/abcDEF_123===")).toBe(first);
  });

  it("computes an OpenSSH SHA-256 fingerprint from keyscan output", () => {
    const line = "host.example.invalid ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB7";
    expect(fingerprintFromKeyscanLine(line)).toMatch(/^SHA256\/[A-Za-z0-9+/]+$/u);
    expect(openSshHostKeyAlgorithms("ssh-rsa")).toBe("rsa-sha2-512,rsa-sha2-256");
  });

  it("requires explicit confirmation before persisting a first-seen host key", async () => {
    const fingerprint = "SHA256/first-key";
    const resolveResponse = { code: 0, stdout: "hostname host.example.invalid\nuser deploy\nport 22\n", stderr: "" };
    const keyscanResponse = { code: 0, stdout: `host ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB7\n`, stderr: "" };
    const writer = new FakeKnownHostsWriter();
    const runner = new FakeRunner([resolveResponse, keyscanResponse]);
    const adapter = new OpenSshAdapter(runner, "/tmp/vault-bridge-known_hosts", writer);
    const pins = new MemoryHostKeyPinStore();
    await expect(adapter.ensurePinned({ host: "host.example.invalid", user: "deploy", port: 22 }, pins, async () => false)).rejects.toThrow("not confirmed");
    // Use a real keyscan-derived value for the positive path.
    const actual = fingerprintFromKeyscanLine("host ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB7");
    const secondRunner = new FakeRunner([resolveResponse, keyscanResponse]);
    const second = new OpenSshAdapter(secondRunner, "/tmp/vault-bridge-known_hosts", writer);
    const target = await second.ensurePinned({ host: "host.example.invalid", user: "deploy", port: 22 }, pins, async (candidate) => candidate === actual);
    expect(target.hostKeyFingerprint).toBe(actual);
    expect(target.hostKeyAlgorithm).toBe("ssh-ed25519");
    expect(await pins.get(target)).toBe(actual);
    expect(writer.lines).toContain("host.example.invalid ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB7");
    expect(fingerprint).not.toBe(actual);
  });

  it("rejects a changed key before writing a new known-host record", async () => {
    const first = "host ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB7\n";
    const changed = "host ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIC8\n";
    const resolveResponse = { code: 0, stdout: "hostname host.example.invalid\nuser deploy\nport 22\n", stderr: "" };
    const writer = new FakeKnownHostsWriter();
    const pins = new MemoryHostKeyPinStore();
    const bootstrap = new OpenSshAdapter(new FakeRunner([resolveResponse, { code: 0, stdout: first, stderr: "" }]), "/tmp/known_hosts", writer);
    const pinned = await bootstrap.ensurePinned({ host: "host.example.invalid", user: "deploy", port: 22 }, pins, async () => true);
    const before = writer.lines.length;
    const changedAdapter = new OpenSshAdapter(new FakeRunner([resolveResponse, { code: 0, stdout: changed, stderr: "" }]), "/tmp/known_hosts", writer);
    await expect(changedAdapter.ensurePinned(pinned, pins, async () => true)).rejects.toBeInstanceOf(HostKeyChangedError);
    expect(writer.lines).toHaveLength(before);
  });
});
