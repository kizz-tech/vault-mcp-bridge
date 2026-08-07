import { describe, expect, it } from "vitest";

import { OpenSftpAdapter, type CommandResult, type SftpRunner } from "../src/ssh.js";

class FakeSftp implements SftpRunner {
  batches: string[] = [];
  async run(args: readonly string[], batch: string): Promise<CommandResult> {
    this.batches.push(`${args.join(" ")}\n${batch}`);
    return { code: 0, stdout: "", stderr: "" };
  }
}

describe("bounded SFTP staging", () => {
  it("uses app host-key options and remote temp rename/chmod", async () => {
    const runner = new FakeSftp();
    const adapter = new OpenSftpAdapter(runner, "/private/app/known_hosts");
    const uploader = adapter.withTarget({ host: "server.example.invalid", user: "deploy", port: 22 });
    await uploader.ensureDirectory("/home/deploy/.vault-bridge");
    await uploader.upload("/private/app/staging/file", "/home/deploy/.vault-bridge/secret");
    expect(runner.batches[0]).toContain("UserKnownHostsFile=/private/app/known_hosts");
    expect(runner.batches[1]).toContain("chmod 600");
    expect(runner.batches[1]).toContain("rename");
    expect(runner.batches[1]).not.toContain("sh -c");
  });
});
