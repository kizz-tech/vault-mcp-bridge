import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { buildPrivateImportCommand, runPrivateSync, validatePrivateSyncConfig } from "../src/private-sync.js";
import type { ScanResult } from "@vault-mcp-bridge/agent-core";
import { sha256Base64Url } from "@vault-mcp-bridge/contracts";

const config = (root: string) => ({
  version: 1 as const,
  vaultRoot: root,
  vaultId: "vault_private_test_0001",
  deviceId: "private_import_test_0001",
  sshHost: "synthetic-host",
  remoteDirectory: "/opt/vault-mcp-bridge/vmb-synthetic",
  projectName: "vmb-synthetic",
});

const scan = (): ScanResult => {
  const content = "# Synthetic note\n";
  return {
    files: [{ id: "document_private_test_0001", title: "Synthetic note", relativePath: "note.md", bytes: content.length, content, contentType: "markdown", sha256: sha256Base64Url(content), modifiedAt: "2026-01-01T00:00:00.000Z" }],
    excluded: [],
    hidden: 0,
    symlinks: 0,
    errors: [],
    bytes: content.length,
  };
};

describe("private SSH snapshot publisher", () => {
  it("builds only the fixed Docker import command from validated fields", () => {
    const value = validatePrivateSyncConfig(config("/tmp/synthetic-vault"));
    const command = buildPrivateImportCommand(value);
    expect(command).toContain("docker compose --env-file .env -f compose.yaml exec -T runtime node dist/cli.js private-import");
    expect(command).not.toContain("/tmp/synthetic-vault");
    expect(() => validatePrivateSyncConfig({ ...value, remoteDirectory: "/tmp/unsafe;id" })).toThrow(/SSH target/u);
    expect(() => validatePrivateSyncConfig({ ...value, sshUser: "operator", sshPort: 22 })).toThrow(/SSH target/u);
    expect(validatePrivateSyncConfig({
      ...value,
      sshUser: "operator",
      sshPort: 2222,
      sshKnownHostsFile: "/tmp/synthetic-known-hosts",
    })).toMatchObject({ sshUser: "operator", sshPort: 2222 });
  });

  it("persists a pending generation and skips an unchanged projection", async () => {
    const directory = await mkdtemp(join(tmpdir(), "vmb-private-sync-"));
    const configPath = join(directory, "config.json");
    await writeFile(configPath, JSON.stringify(config("/tmp/synthetic-vault")), { mode: 0o600 });
    let uploads = 0;
    const uploader = async ({ snapshotJson }: { snapshotJson: string }) => {
      uploads += 1;
      const snapshot = JSON.parse(snapshotJson) as { version: 1; snapshotId: string; vaultId: string; generation: number; digest: string; documents: unknown[] };
      return {
        version: snapshot.version,
        accepted: true,
        idempotent: false,
        snapshotId: snapshot.snapshotId,
        vaultId: snapshot.vaultId,
        generation: snapshot.generation,
        digest: snapshot.digest,
        documentCount: snapshot.documents.length,
        receivedAt: new Date().toISOString(),
      };
    };
    const scanner = { scan: async () => scan() };
    const first = await runPrivateSync({ configPath, scanner, uploader });
    expect(first).toMatchObject({ status: "uploaded", generation: 1, documentCount: 1 });
    const second = await runPrivateSync({ configPath, scanner, uploader });
    expect(second).toMatchObject({ status: "unchanged", generation: 1, documentCount: 1 });
    expect(uploads).toBe(1);
    expect(JSON.parse(await readFile(join(directory, "sync-state.json"), "utf8"))).toMatchObject({ lastGeneration: 1 });
  });
});
