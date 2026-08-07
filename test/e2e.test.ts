import { resolve } from "node:path";
import { Client, StreamableHTTPClientTransport } from "@modelcontextprotocol/client";
import { normalizeVaultId } from "../packages/contracts/src/index.js";
import { buildSnapshot, scanVault } from "../packages/vault-core/src/index.js";
import { afterEach, describe, expect, it } from "vitest";
import { createApp, createPairingCode, type VaultBridgeApp } from "../apps/server/src/app.js";
import { loadConfig } from "../apps/server/src/config.js";
import { VaultStore } from "../apps/server/src/store.js";
import { generateDeviceKeypair, HttpRemoteClient } from "../apps/agent/src/remote-client.js";

let runtime: VaultBridgeApp | undefined;
let mcpClient: Client | undefined;
const originalFetch = globalThis.fetch;

afterEach(async () => {
  await mcpClient?.close().catch(() => undefined);
  mcpClient = undefined;
  globalThis.fetch = originalFetch;
  await runtime?.close();
  runtime = undefined;
});

describe("synthetic vertical slice", () => {
  it("pairs, scans, publishes, checks status, searches and fetches over MCP", async () => {
    const token = "synthetic-e2e-mcp-token";
    const store = new VaultStore(":memory:");
    runtime = await createApp({
      store,
      config: loadConfig({
        NODE_ENV: "test",
        MCP_DEV_TOKEN: token,
        ALLOWED_HOSTS: "127.0.0.1,localhost",
        ALLOWED_ORIGINS: "http://127.0.0.1:8787,http://localhost:8787",
      }),
    });
    const baseUrl = "http://127.0.0.1:8787";
    const injectFetch: typeof fetch = async (input, init) => {
      const request = new Request(input, init);
      const url = new URL(request.url);
      const payload = request.method === "GET" || request.method === "HEAD" ? undefined : await request.text();
      const response = await runtime!.app.inject({
        method: request.method,
        url: `${url.pathname}${url.search}`,
        headers: Object.fromEntries(request.headers.entries()),
        ...(payload ? { payload } : {}),
      });
      const headers = new Headers();
      for (const [name, value] of Object.entries(response.headers)) {
        if (Array.isArray(value)) for (const item of value) headers.append(name, String(item));
        else if (value !== undefined) headers.set(name, String(value));
      }
      return new Response(response.rawPayload, { status: response.statusCode, headers });
    };
    globalThis.fetch = injectFetch;

    const vaultId = normalizeVaultId("synthetic-e2e");
    const pairing = createPairingCode(store, vaultId, 600);
    const keys = generateDeviceKeypair();
    const deviceId = "agent_synthetic_e2e_0001";
    const publisher = new HttpRemoteClient(true);
    const paired = await publisher.pair({ url: baseUrl, code: pairing.code, agentId: deviceId, vaultId, publicKey: keys.publicKey, label: "synthetic e2e" });
    expect(paired).toMatchObject({ deviceId, vaultId });

    const before = await publisher.status({ url: baseUrl, deviceId, vaultId, privateKey: keys.privateKey });
    expect(before.generation).toBeUndefined();

    const scan = await scanVault(resolve("fixtures/vault"), { idKey: "synthetic-e2e-id-key", vaultId });
    expect(scan.filesIncluded).toBe(3);
    expect(scan.documents.map((document) => document.relativePath)).not.toContain(".obsidian/app.json");
    const snapshot = buildSnapshot(scan, { generation: 1, createdAt: "2026-08-07T00:00:00.000Z" });
    await publisher.upload({
      url: baseUrl,
      deviceId,
      vaultId,
      privateKey: keys.privateKey,
      snapshot: { snapshot, body: JSON.stringify(snapshot), snapshotId: snapshot.snapshotId, generation: snapshot.generation },
    });
    const after = await publisher.status({ url: baseUrl, deviceId, vaultId, privateKey: keys.privateKey });
    expect(after).toMatchObject({ ok: true, vaultId, generation: 1, snapshotId: snapshot.snapshotId });

    mcpClient = new Client(
      { name: "vault-bridge-e2e", version: "0.1.0" },
      { versionNegotiation: { mode: { pin: "2026-07-28" } } },
    );
    const transport = new StreamableHTTPClientTransport(new URL("/mcp", baseUrl), {
      authProvider: { token: async () => token },
      fetch: injectFetch,
    });
    await mcpClient.connect(transport);
    const tools = await mcpClient.listTools();
    expect(tools.tools.map((tool) => tool.name).sort()).toEqual(["fetch", "search"]);

    const search = await mcpClient.callTool({ name: "search", arguments: { query: "синтетическая" } });
    const searchOutput = search.structuredContent as { results: Array<{ id: string; title: string; url: string }> };
    expect(searchOutput.results.length).toBeGreaterThan(0);
    expect(searchOutput.results[0]?.url).toBe("");
    const fetched = await mcpClient.callTool({ name: "fetch", arguments: { id: searchOutput.results[0]!.id } });
    const fetchOutput = fetched.structuredContent as { text: string; url: string };
    expect(fetchOutput.text).toContain("синтетическая");
    expect(fetchOutput.url).toBe("");

    await mcpClient.close();
    mcpClient = new Client({ name: "vault-bridge-legacy-e2e", version: "0.1.0" });
    const legacyTransport = new StreamableHTTPClientTransport(new URL("/mcp", baseUrl), {
      authProvider: { token: async () => token },
      fetch: injectFetch,
    });
    await mcpClient.connect(legacyTransport);
    expect((await mcpClient.listTools()).tools.map((tool) => tool.name).sort()).toEqual(["fetch", "search"]);
  });
});
