import { describe, expect, it } from "vitest";
import { sha256Base64Url } from "@vault-mcp-bridge/contracts";
import { loadConfig } from "../src/config.js";
import { registerVaultTools, type McpServerLike } from "../src/mcp.js";
import { importPrivateSnapshot } from "../src/private-import.js";
import { assertPrivateStdioConfig } from "../src/private-stdio-config.js";
import { SnapshotError, VaultStore } from "../src/store.js";
import type { Snapshot } from "../src/types.js";

const vaultId = "vault_private_test_0001";
const deviceId = "private_import_test_0001";

const makeSnapshot = (generation = 1): Snapshot => {
  const text = "# Synthetic private tunnel note\n\nFixture only.";
  const base = {
    version: 1 as const,
    snapshotId: `00000000-0000-4000-8000-00000000000${generation}`,
    vaultId,
    generation,
    createdAt: new Date(1_700_000_000_000 + generation * 1000).toISOString(),
    documents: [{
      id: "document_private_test_0001",
      title: "Synthetic tunnel note",
      mediaType: "text/markdown" as const,
      text,
      sourceHash: sha256Base64Url(text),
      modifiedAt: new Date(1_700_000_000_000).toISOString(),
    }],
  };
  return { ...base, digest: VaultStore.makeSnapshotDigest(base) };
};

const privateConfig = () => loadConfig({
  NODE_ENV: "production",
  SERVER_DATABASE_PATH: "/tmp/vault-bridge-private-test.sqlite",
  MCP_VAULT_ID: vaultId,
});

describe("OpenAI Secure MCP Tunnel mode", () => {
  it("fails closed unless its explicit private stdio boundary is configured", () => {
    const config = privateConfig();
    expect(() => assertPrivateStdioConfig(config, {})).toThrow(/MCP_STDIO_PRIVATE_TUNNEL/u);
    expect(() => assertPrivateStdioConfig(config, {
      MCP_STDIO_PRIVATE_TUNNEL: "1",
      CONTROL_PLANE_TUNNEL_ID: "tunnel_synthetic_0001",
    })).not.toThrow();
  });

  it("registers only read-only search and fetch without HTTP OAuth metadata", () => {
    const tools: Array<{ name: string; config: Record<string, unknown> }> = [];
    const fake = {
      registerTool(name: string, config: Record<string, unknown>) {
        tools.push({ name, config });
      },
    } as McpServerLike;
    const store = new VaultStore(":memory:");
    registerVaultTools(fake, store, privateConfig());
    expect(tools.map((tool) => tool.name)).toEqual(["search", "fetch"]);
    for (const tool of tools) {
      expect(tool.config).not.toHaveProperty("securitySchemes");
      expect(tool.config.annotations).toMatchObject({
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      });
    }
    store.close();
  });

  it("atomically imports validated generations and preserves idempotence", () => {
    const store = new VaultStore(":memory:");
    const first = makeSnapshot(1);
    const accepted = importPrivateSnapshot(store, { expectedVaultId: vaultId, deviceId, snapshotJson: JSON.stringify(first) });
    expect(accepted).toMatchObject({ accepted: true, idempotent: false, generation: 1, documentCount: 1 });
    expect(importPrivateSnapshot(store, { expectedVaultId: vaultId, deviceId, snapshotJson: JSON.stringify(first) }).idempotent).toBe(true);
    expect(store.search(vaultId, "Synthetic", 10).results).toHaveLength(1);

    const second = makeSnapshot(2);
    expect(importPrivateSnapshot(store, { expectedVaultId: vaultId, deviceId, snapshotJson: JSON.stringify(second) }).generation).toBe(2);
    expect(store.getActive(vaultId)?.generation).toBe(2);
    store.close();
  });

  it("rejects invalid content and the wrong vault without changing active data", () => {
    const store = new VaultStore(":memory:");
    const first = makeSnapshot(1);
    importPrivateSnapshot(store, { expectedVaultId: vaultId, deviceId, snapshotJson: JSON.stringify(first) });
    const tampered = { ...makeSnapshot(2), documents: [{ ...makeSnapshot(2).documents[0]!, text: "tampered" }] };
    expect(() => importPrivateSnapshot(store, { expectedVaultId: vaultId, deviceId, snapshotJson: JSON.stringify(tampered) })).toThrow(SnapshotError);
    expect(() => importPrivateSnapshot(store, { expectedVaultId: "vault_other_test_00001", deviceId, snapshotJson: JSON.stringify(makeSnapshot(2)) })).toThrow(/not allowed/u);
    expect(store.getActive(vaultId)?.generation).toBe(1);
    store.close();
  });
});
