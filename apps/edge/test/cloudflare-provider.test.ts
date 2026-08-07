import { describe, expect, it } from "vitest";

import type { SecretReference } from "@vault-mcp-bridge/contracts";
import { CloudflareApiError, CloudflareTunnelProvider } from "../src/cloudflare-provider.js";
import { createMcpWorkerSource, createPublisherWorkerSource } from "../src/cloudflare-worker.js";
import { MemoryCredentialVault } from "../src/providers.js";

const envelope = (result: unknown, status = 200): Response => new Response(JSON.stringify({ success: status < 400, result }), {
  status,
  headers: { "content-type": "application/json" }
});

const csr = "-----BEGIN CERTIFICATE REQUEST-----\n" + "A".repeat(256) + "\n-----END CERTIFICATE REQUEST-----\n";
const installationId = "inst_1234567890abcdef1234567890abcdef";

type FakeCloudflareState = {
  associations: Set<string>;
  tunnelNumber: number;
  dnsNumber: number;
  deleteFailures: Set<string>;
  missingDeletes: Set<string>;
  routeFailure: boolean;
  associationWrites: string[][];
};

const fakeCloudflare = (state: FakeCloudflareState): typeof fetch => async (input, init) => {
  const url = input.toString();
  const method = init?.method ?? "GET";
  if (url.endsWith("/cfd_tunnel") && method === "POST") return envelope({ id: `tunnel_${++state.tunnelNumber}_abcdefghijklmnop` });
  if (url.endsWith("/configurations")) return envelope({});
  if (url.endsWith("/token")) return envelope("tunnel-token-abcdefghijklmnopqrstuvwxyz-0123456789");
  if (url.endsWith("/dns_records") && method === "POST") return envelope({ id: `dns_record_${++state.dnsNumber}_abcdefghijklmnop` });
  if (url.endsWith("/client_certificates") && method === "POST") return envelope({
    id: "certificate_abcdefghijklmnop",
    certificate: "-----BEGIN CERTIFICATE-----\nQUJDRA==\n-----END CERTIFICATE-----\n",
    fingerprint_sha256: "AA:".repeat(31) + "AA"
  });
  if (url.endsWith("/hostname_associations") && method === "GET") return envelope({ hostnames: [...state.associations] });
  if (url.endsWith("/hostname_associations") && method === "PUT") {
    const body = JSON.parse(String(init?.body ?? "{}")) as { hostnames?: string[] };
    state.associations = new Set(body.hostnames ?? []);
    state.associationWrites.push(body.hostnames ?? []);
    return envelope({ hostnames: [...state.associations] });
  }
  if (url.includes("/workers/scripts/") && !url.endsWith("/secrets") && method === "PUT") return envelope({});
  if (url.endsWith("/secrets") && method === "PUT") return envelope({});
  if (url.endsWith("/workers/routes") && method === "POST") {
    if (state.routeFailure) return envelope(null, 500);
    return envelope({ id: "worker_route_abcdefghijklmnop" });
  }
  if (method === "DELETE") {
    const resource = url.includes("/workers/routes/")
      ? "route"
      : url.includes("/workers/scripts/")
        ? "worker"
        : url.includes("/client_certificates/")
          ? "certificate"
          : url.includes("/dns_records/")
            ? "dns"
            : url.endsWith("/connections")
              ? "connections"
              : url.includes("/cfd_tunnel/")
                ? "tunnel"
                : "unknown";
    if (state.deleteFailures.has(resource)) return envelope(null, 500);
    if (state.missingDeletes.has(resource)) return envelope(null, 404);
    return envelope({});
  }
  throw new Error(`unexpected request: ${method} ${url}`);
};

const providerOptions = (credentials: MemoryCredentialVault, fetcher: typeof fetch) => ({
  accountId: "account_abcdefghijklmnop",
  zoneId: "zone_abcdefghijklmnop",
  zoneName: "vault.example.test",
  apiToken: "cf-token-abcdefghijklmnopqrstuvwxyz",
  credentials,
  dedicatedZone: true as const,
  introspectionBaseUrl: "https://edge.example.test",
  apiBaseUrl: "https://api.example.test/client/v4/",
  fetcher
});

class PartialPutVault extends MemoryCredentialVault {
  readonly written = new Set<string>();

  override async put(reference: SecretReference, value: string): Promise<void> {
    if (reference.id.startsWith("publisher_edge_attestation_")) throw new Error("synthetic credential write failure");
    await super.put(reference, value);
    this.written.add(reference.id);
  }
}

describe("Cloudflare tunnel provider", () => {
  it("provisions bounded installation resources and keeps account authority at the edge", async () => {
    const credentials = new MemoryCredentialVault();
    const requests: Array<{ url: string; init?: RequestInit }> = [];
    let dns = 0;
    const fetcher: typeof fetch = async (input, init) => {
      const url = input.toString();
      requests.push({ url, ...(init ? { init } : {}) });
      if (url.endsWith("/cfd_tunnel") && init?.method === "POST") return envelope({ id: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" });
      if (url.endsWith("/configurations")) return envelope({});
      if (url.endsWith("/token")) return envelope("tunnel-token-abcdefghijklmnopqrstuvwxyz-0123456789");
      if (url.endsWith("/dns_records") && init?.method === "POST") return envelope({ id: `dns_record_${++dns}_abcdefghijklmnop` });
      if (url.endsWith("/client_certificates") && init?.method === "POST") return envelope({
        id: "certificate_abcdefghijklmnop",
        certificate: "-----BEGIN CERTIFICATE-----\nQUJDRA==\n-----END CERTIFICATE-----\n",
        fingerprint_sha256: "AA:".repeat(31) + "AA"
      });
      if (url.endsWith("/hostname_associations") && init?.method === "GET") return envelope({ hostnames: [] });
      if (url.endsWith("/hostname_associations") && init?.method === "PUT") return envelope({ hostnames: [] });
      if (url.includes("/workers/scripts/") && !url.endsWith("/secrets") && init?.method === "PUT") return envelope({});
      if (url.endsWith("/secrets") && init?.method === "PUT") return envelope({});
      if (url.endsWith("/workers/routes") && init?.method === "POST") return envelope({ id: "worker_route_abcdefghijklmnop" });
      throw new Error(`unexpected request: ${init?.method ?? "GET"} ${url}`);
    };
    const provider = new CloudflareTunnelProvider({
      accountId: "account_abcdefghijklmnop",
      zoneId: "zone_abcdefghijklmnop",
      zoneName: "vault.example.test",
      apiToken: "cf-token-abcdefghijklmnopqrstuvwxyz",
      credentials,
      dedicatedZone: true,
      introspectionBaseUrl: "https://edge.example.test",
      apiBaseUrl: "https://api.example.test/client/v4/",
      fetcher
    });

    const result = await provider.provision({ installationId, vaultId: "vault_1234567890abcdef1234567890abcdef", ownerId: "owner_1234567890abcdef", publisherCsr: csr });
    expect(result.mcpHost).toMatch(/^mcp-.+\.vault\.example\.test$/u);
    expect(result.publisherHost).toMatch(/^publish-.+\.vault\.example\.test$/u);
    expect(credentials.has(result.tunnelCredential)).toBe(true);
    expect(credentials.has(result.publisherMtlsCredential)).toBe(true);
    expect(credentials.has(result.publisherEdgeAttestation)).toBe(true);
    expect(credentials.has(result.mcpEdgeAttestation)).toBe(true);
    expect(requests.every((request) => request.init?.headers instanceof Headers && (request.init.headers as Headers).get("authorization")?.startsWith("Bearer "))).toBe(true);
    expect(requests.some((request) => request.url.includes("cloudflare-token"))).toBe(false);
    const uploads = requests.filter((request) => request.url.includes("/workers/scripts/") && request.init?.body instanceof FormData);
    expect(uploads).toHaveLength(2);
    const mcpUpload = uploads.find((request) => request.url.includes("/vmb-mcp-"));
    expect(mcpUpload).toBeDefined();
    const metadata = JSON.parse(await ((mcpUpload!.init!.body as FormData).get("metadata") as Blob).text()) as { bindings?: Array<{ name: string; type: string; text: string }> };
    expect(metadata.bindings).toEqual([
      { name: "INTROSPECTION_URL", type: "plain_text", text: `https://edge.example.test/v1/installations/${installationId}/oauth/introspect` },
      { name: "INSTALLATION_ID", type: "plain_text", text: installationId },
    ]);
    const mcpSource = await ((mcpUpload!.init!.body as FormData).get("worker.mjs") as Blob).text();
    expect(mcpSource).toContain('const MCP_ATTESTATION_SECRET = "MCP_EDGE_ATTESTATION_SECRET"');
    expect(requests.some((request) => request.url.includes("/vmb-mcp-") && request.url.endsWith("/secrets") && String(request.init?.body).includes("MCP_EDGE_ATTESTATION_SECRET"))).toBe(true);
    const mcpRoute = requests.find((request) => request.url.endsWith("/workers/routes") && String(request.init?.body).includes("vmb-mcp-"));
    expect(mcpRoute).toBeDefined();
  });

  it("generates a Worker that rejects spoofed identity headers and signs the exact origin request", () => {
    const source = createPublisherWorkerSource({
      installationId,
      publisherHost: "publish-fixture.vault.example.test",
      hiddenOriginHost: "origin-fixture.vault.example.test",
      certificateFingerprint: "AA:".repeat(31) + "AA"
    });
    expect(source).toContain('tls.certVerified === "SUCCESS"');
    expect(source).toContain('tls.certRevoked !== "1"');
    expect(source).toContain('headers.delete(name)');
    expect(source).toContain('request.method.toUpperCase()');
    expect(source).toContain('url.pathname + url.search');
    expect(source).not.toContain("cf-token-");
  });

  it("generates an MCP worker bound to one installation and never embeds its secret", () => {
    const source = createMcpWorkerSource({
      installationId,
      mcpHost: "mcp-fixture.vault.example.test",
      introspectionUrl: `https://edge.example.test/v1/installations/${installationId}/oauth/introspect`,
    });
    expect(source).toContain("const INTROSPECTION_URL = \"INTROSPECTION_URL\"");
    expect(source).toContain("const INSTALLATION_ID = \"INSTALLATION_ID\"");
    expect(source).toContain("INTROSPECTION_RESPONSE_BYTES = 16384");
    expect(source).toContain('url.pathname !== "/mcp"');
    expect(source).toContain("boundedJson(response)");
    expect(source).not.toContain("cf-token-");
    expect(() => createMcpWorkerSource({
      installationId,
      mcpHost: "mcp-fixture.vault.example.test",
      introspectionUrl: "https://edge.example.test/v1/installations/another/oauth/introspect",
    })).toThrow(/installation-mismatched/u);
  });

  it("fails closed when the API response is malformed", async () => {
    const provider = new CloudflareTunnelProvider({
      accountId: "account_abcdefghijklmnop",
      zoneId: "zone_abcdefghijklmnop",
      zoneName: "vault.example.test",
      apiToken: "cf-token-abcdefghijklmnopqrstuvwxyz",
      credentials: new MemoryCredentialVault(),
      dedicatedZone: true,
      introspectionBaseUrl: "https://edge.example.test",
      apiBaseUrl: "https://api.example.test/client/v4/",
      fetcher: async () => new Response("not-json", { status: 200 })
    });
    await expect(provider.provision({ installationId, vaultId: "vault_1234567890abcdef1234567890abcdef", ownerId: "owner_1234567890abcdef", publisherCsr: csr })).rejects.toBeInstanceOf(CloudflareApiError);
  });

  it("keeps local references when external cleanup is partial, then retries idempotently", async () => {
    const credentials = new MemoryCredentialVault();
    const state: FakeCloudflareState = {
      associations: new Set(),
      tunnelNumber: 0,
      dnsNumber: 0,
      deleteFailures: new Set(["route"]),
      missingDeletes: new Set(),
      routeFailure: false,
      associationWrites: []
    };
    const provider = new CloudflareTunnelProvider(providerOptions(credentials, fakeCloudflare(state)));
    const input = { installationId, vaultId: "vault_1234567890abcdef1234567890abcdef", ownerId: "owner_1234567890abcdef", publisherCsr: csr };
    const result = await provider.provision(input);

    await expect(provider.revoke(input, result)).rejects.toBeInstanceOf(AggregateError);
    expect(credentials.has(result.tunnelCredential)).toBe(true);
    expect(credentials.has(result.publisherMtlsCredential)).toBe(true);
    expect(credentials.has(result.publisherEdgeAttestation)).toBe(true);
    expect(credentials.has(result.mcpEdgeAttestation)).toBe(true);

    state.deleteFailures.clear();
    state.missingDeletes = new Set(["route", "worker", "certificate", "dns", "connections", "tunnel"]);
    await expect(provider.revoke(input, result)).resolves.toBeUndefined();
    expect(credentials.has(result.tunnelCredential)).toBe(false);
    expect(credentials.has(result.publisherMtlsCredential)).toBe(false);
    expect(credentials.has(result.publisherEdgeAttestation)).toBe(false);
    expect(credentials.has(result.mcpEdgeAttestation)).toBe(false);
  });

  it("surfaces rollback failure and retains credentials for a later cleanup retry", async () => {
    const credentials = new PartialPutVault();
    const state: FakeCloudflareState = {
      associations: new Set(),
      tunnelNumber: 0,
      dnsNumber: 0,
      deleteFailures: new Set(["tunnel"]),
      missingDeletes: new Set(),
      routeFailure: false,
      associationWrites: []
    };
    const provider = new CloudflareTunnelProvider(providerOptions(credentials, fakeCloudflare(state)));
    const promise = provider.provision({ installationId, vaultId: "vault_1234567890abcdef1234567890abcdef", ownerId: "owner_1234567890abcdef", publisherCsr: csr });
    const error = await promise.catch((value: unknown) => value);
    expect(error).toBeInstanceOf(CloudflareApiError);
    expect((error as CloudflareApiError).operation).toBe("provision-installation");
    expect((error as CloudflareApiError).cause).toBeInstanceOf(AggregateError);

    // The first two refs were written before the third write failed. Since the
    // tunnel delete failed, they remain available for a retry instead of being
    // revoked while a provider resource may still be live.
    expect([...credentials.written].some((id) => id.startsWith("tunnel_"))).toBe(true);
    expect([...credentials.written].some((id) => id.startsWith("publisher_mtls_"))).toBe(true);
  });

  it("recovers a partial V2 journal created before the MCP route exists", async () => {
    const credentials = new MemoryCredentialVault();
    const state: FakeCloudflareState = {
      associations: new Set(),
      tunnelNumber: 0,
      dnsNumber: 0,
      deleteFailures: new Set(["tunnel"]),
      missingDeletes: new Set(),
      routeFailure: true,
      associationWrites: []
    };
    const provider = new CloudflareTunnelProvider(providerOptions(credentials, fakeCloudflare(state)));
    const input = { installationId, vaultId: "vault_1234567890abcdef1234567890abcdef", ownerId: "owner_1234567890abcdef", publisherCsr: csr };
    await expect(provider.provision(input)).rejects.toBeInstanceOf(CloudflareApiError);

    // The failed publisher route leaves a V2 provisioning receipt without an
    // MCP route. A retry must decode and clean it rather than orphan it.
    state.routeFailure = false;
    state.deleteFailures.clear();
    await expect(provider.provision(input)).resolves.toEqual(expect.objectContaining({ mcpEdgeAttestation: expect.any(Object) }));
  });

  it("serializes replace-all hostname association updates across installations", async () => {
    const state: FakeCloudflareState = {
      associations: new Set(),
      tunnelNumber: 0,
      dnsNumber: 0,
      deleteFailures: new Set(),
      missingDeletes: new Set(),
      routeFailure: false,
      associationWrites: []
    };
    const fetcher = fakeCloudflare(state);
    const providerA = new CloudflareTunnelProvider(providerOptions(new MemoryCredentialVault(), fetcher));
    const providerB = new CloudflareTunnelProvider(providerOptions(new MemoryCredentialVault(), fetcher));
    const inputA = { installationId: "inst_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", vaultId: "vault_1234567890abcdef1234567890abcdef", ownerId: "owner_1234567890abcdef", publisherCsr: csr };
    const inputB = { installationId: "inst_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB", vaultId: "vault_1234567890abcdef1234567890abcdef", ownerId: "owner_1234567890abcdef", publisherCsr: csr };
    await Promise.all([providerA.provision(inputA), providerB.provision(inputB)]);

    expect(state.associations.size).toBe(2);
    expect(state.associationWrites.some((hosts) => hosts.length === 2)).toBe(true);
  });
});
