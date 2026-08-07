import { describe, expect, it } from "vitest";

import { EdgeControlClient } from "../src/edge-client.js";
import { validateProductConfig } from "../src/product-config.js";

const config = validateProductConfig({
  edgeOrigin: "https://edge.example.invalid",
  ownerIssuer: "https://issuer.example.invalid",
  ownerAuthorizationEndpoint: "https://issuer.example.invalid/oauth/authorize",
  ownerTokenEndpoint: "https://issuer.example.invalid/oauth/token",
  ownerJwksUri: "https://issuer.example.invalid/.well-known/jwks.json",
  ownerAudience: "edge-api",
  ownerClientId: "desktop",
  images: {
    serverRepository: "ghcr.io/example/server",
    serverDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    tunnelRepository: "cloudflare/cloudflared",
    tunnelDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
  }
});

describe("edge control client", () => {
  it("sends owner bearer and bounded idempotency header without logging values", async () => {
    const calls: Request[] = [];
    const fakeFetch = async (input: string | URL, init?: RequestInit): Promise<Response> => {
      calls.push(new Request(input, init));
      return new Response(JSON.stringify({ installation: { installationId: "inst_requested_1234", providerResourceId: "managed", endpointBundle: {} } }), { status: 201, headers: { "content-type": "application/json" } });
    };
    const client = new EdgeControlClient(config, { async getAccessToken() { return "opaque-owner-token"; }, async clear() {} }, { fetch: fakeFetch });
    await expect(client.createInstallation({ installationId: "inst_requested_1234", vaultId: "vault_requested_1234", idempotencyKey: "setup-id:edge:0001" })).rejects.toThrow();
    const request = calls[0];
    expect(request?.headers.get("authorization")).toBe("Bearer opaque-owner-token");
    expect(request?.headers.get("idempotency-key")).toMatch(/^idemp_[A-Za-z0-9_-]+$/u);
    expect(request?.url).toContain("/v1/installations");
  });

  it("revokes exactly one installation and treats only a not-found receipt as idempotent", async () => {
    const calls: Request[] = [];
    const fakeFetch = async (input: string | URL, init?: RequestInit): Promise<Response> => {
      calls.push(new Request(input, init));
      return new Response(null, { status: 204 });
    };
    const client = new EdgeControlClient(config, { async getAccessToken() { return "opaque-owner-token"; }, async clear() {} }, { fetch: fakeFetch });
    await client.revokeInstallation("inst_requested_1234", "setup-id:disconnect:0001");
    expect(calls).toHaveLength(1);
    expect(calls[0]?.method).toBe("POST");
    expect(new URL(calls[0]!.url).pathname).toBe("/v1/installations/inst_requested_1234/revoke");
    expect(calls[0]?.headers.get("idempotency-key")).toMatch(/^idemp_[A-Za-z0-9_-]+$/u);

    const absent = new EdgeControlClient(config, { async getAccessToken() { return "opaque-owner-token"; }, async clear() {} }, {
      fetch: async () => new Response(JSON.stringify({ error: "installation_not_found" }), { status: 404, headers: { "content-type": "application/json" } })
    });
    await expect(absent.revokeInstallation("inst_requested_1234")).resolves.toBeUndefined();
    const unavailable = new EdgeControlClient(config, { async getAccessToken() { return "opaque-owner-token"; }, async clear() {} }, {
      fetch: async () => new Response(JSON.stringify({ error: "upstream_unavailable" }), { status: 503, headers: { "content-type": "application/json" } })
    });
    await expect(unavailable.revokeInstallation("inst_requested_1234")).rejects.toThrow("upstream_unavailable");
  });
});
