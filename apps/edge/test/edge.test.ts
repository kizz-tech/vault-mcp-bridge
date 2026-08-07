import { afterEach, describe, expect, it } from "vitest";
import { createDecipheriv, createPublicKey, diffieHellman, generateKeyPairSync, hkdfSync } from "node:crypto";
import { createEdgeApp, type CreateEdgeAppOptions, type EdgeApp } from "../src/app.js";
import { hashOpaque, pkceChallenge } from "../src/crypto.js";
import { DeterministicTunnelProvider, ExternalTunnelProvider, MemoryCredentialVault } from "../src/providers.js";

const ownerToken = "owner-token-for-tests";
const ownerId = "owner-test";
const vaultId = "vault_test_fixture_123456";

const apps: EdgeApp[] = [];

const makeApp = async (configOverrides: Record<string, unknown> = {}, optionOverrides: Partial<CreateEdgeAppOptions> = {}): Promise<EdgeApp> => {
  const app = await createEdgeApp({
    config: {
      nodeEnv: "test",
      mode: "self-hosted",
      origin: "https://edge.example.test",
      issuer: "https://edge.example.test",
      providerName: "local",
      devOwnerToken: ownerToken,
      devOwnerId: ownerId,
      ...(configOverrides as object),
    },
    ...optionOverrides,
  });
  apps.push(app);
  return app;
};

const auth = { authorization: `Bearer ${ownerToken}` };

const createInstallation = async (app: EdgeApp, owner = ownerId, vault = vaultId) => {
  const response = await app.app.inject({ method: "POST", url: "/v1/installations", headers: owner === ownerId ? auth : { authorization: `Bearer token-${owner}` }, payload: { vaultId: vault } });
  expect(response.statusCode).toBe(201);
  return response.json<{ installation: { installationId: string; mcpResourceUrl?: string; endpointBundle: { mcpResourceUrl: string } } }>().installation;
};

const register = async (app: EdgeApp, installationId: string, resource: string, redirectUri = "http://127.0.0.1:4555/callback") => {
  const response = await app.app.inject({
    method: "POST",
    url: "/oauth/register",
    payload: { installation_id: installationId, resource, redirect_uris: [redirectUri], grant_types: ["authorization_code", "refresh_token"], response_types: ["code"], token_endpoint_auth_method: "none" },
  });
  expect(response.statusCode).toBe(201);
  return response.json<{ client_id: string }>();
};

const authorize = async (app: EdgeApp, params: Record<string, string>) => {
  const query = new URLSearchParams(params);
  return app.app.inject({ method: "GET", url: `/oauth/authorize?${query.toString()}` });
};

afterEach(async () => {
  while (apps.length) await apps.pop()?.close();
});

describe("edge state and abuse bounds", () => {
  it("makes installation creation idempotent and binds the key to owner and vault", async () => {
    const app = await makeApp();
    const key = "install-operation-key-0001";
    const first = await app.app.inject({ method: "POST", url: "/v1/installations", headers: { ...auth, "idempotency-key": key }, payload: { vaultId } });
    expect(first.statusCode).toBe(201);
    const firstId = first.json().installation.installationId;
    const replay = await app.app.inject({ method: "POST", url: "/v1/installations", headers: { ...auth, "idempotency-key": key }, payload: { vaultId } });
    expect(replay.statusCode).toBe(200);
    expect(replay.json().installation.installationId).toBe(firstId);
    const conflict = await app.app.inject({ method: "POST", url: "/v1/installations", headers: { ...auth, "idempotency-key": key }, payload: { vaultId: "vault_test_fixture_654321" } });
    expect(conflict.statusCode).toBe(409);
    const invalid = await app.app.inject({ method: "POST", url: "/v1/installations", headers: { ...auth, "idempotency-key": "short" }, payload: { vaultId } });
    expect(invalid.statusCode).toBe(400);
  });

  it("caps DCR, authorization-code, and lease state without exposing ownership", async () => {
    const app = await makeApp({ limits: { maxClientsTotal: 1, maxClientsPerInstallation: 1, maxAuthorizationCodes: 1, maxCredentialLeases: 1 }, autoApproveOwnerId: ownerId });
    const installation = await createInstallation(app);
    const resource = installation.endpointBundle.mcpResourceUrl;
    const redirectUri = "http://127.0.0.1:4560/callback";
    const firstClient = await register(app, installation.installationId, resource, redirectUri);
    const secondClient = await app.app.inject({ method: "POST", url: "/oauth/register", payload: { installation_id: installation.installationId, resource, redirect_uris: ["http://127.0.0.1:4561/callback"] } });
    expect(secondClient.statusCode).toBe(503);
    expect(secondClient.json().error).toBe("server_error");
    const verifier = "q".repeat(64);
    const authParams = { client_id: firstClient.client_id, redirect_uri: redirectUri, response_type: "code", resource, code_challenge: pkceChallenge(verifier), code_challenge_method: "S256" };
    const firstCode = await authorize(app, authParams);
    expect(firstCode.statusCode).toBe(302);
    const secondCode = await authorize(app, authParams);
    expect(secondCode.statusCode).toBe(503);
    const leaseClient = generateKeyPairSync("x25519");
    const leaseKey = Buffer.from(leaseClient.publicKey.export({ format: "der", type: "spki" })).toString("base64url");
    const leaseOne = await app.app.inject({ method: "POST", url: `/v1/installations/${installation.installationId}/credentials/lease`, headers: auth, payload: { kind: "tunnel", client_public_key: leaseKey } });
    expect(leaseOne.statusCode).toBe(201);
    const leaseTwo = await app.app.inject({ method: "POST", url: `/v1/installations/${installation.installationId}/credentials/lease`, headers: auth, payload: { kind: "tunnel", client_public_key: leaseKey } });
    expect(leaseTwo.statusCode).toBe(429);
  });

  it("prunes expired authorization codes before applying the cap", async () => {
    let nowValue = Date.now();
    const app = await makeApp({ limits: { maxAuthorizationCodes: 1 }, autoApproveOwnerId: ownerId }, { now: () => nowValue });
    const installation = await createInstallation(app);
    const resource = installation.endpointBundle.mcpResourceUrl;
    const redirectUri = "http://127.0.0.1:4562/callback";
    const client = await register(app, installation.installationId, resource, redirectUri);
    const params = { client_id: client.client_id, redirect_uri: redirectUri, response_type: "code", resource, code_challenge: pkceChallenge("z".repeat(64)), code_challenge_method: "S256" };
    expect((await authorize(app, params)).statusCode).toBe(302);
    nowValue += 301_000;
    expect((await authorize(app, params)).statusCode).toBe(302);
  });

  it("bounds installations and reclaims only an exact revoked installation", async () => {
    const app = await makeApp({ limits: { maxInstallations: 1 } });
    const first = await createInstallation(app);
    const blocked = await app.app.inject({ method: "POST", url: "/v1/installations", headers: auth, payload: { vaultId: "vault_test_fixture_654321" } });
    expect(blocked.statusCode).toBe(503);
    const revoked = await app.app.inject({ method: "POST", url: `/v1/installations/${first.installationId}/revoke`, headers: auth });
    expect(revoked.statusCode).toBe(200);
    const replacement = await app.app.inject({ method: "POST", url: "/v1/installations", headers: auth, payload: { vaultId: "vault_test_fixture_654321" } });
    expect(replacement.statusCode).toBe(201);
    expect(app.store.installations.size).toBe(1);
  });

  it("distinguishes an absent installation from a provider revocation failure", async () => {
    const delegate = new DeterministicTunnelProvider({ origin: "https://edge.example.test" });
    const app = await makeApp({}, {
      provider: {
        provision: (input) => delegate.provision(input),
        rotate: (input, previous) => delegate.rotate(input, previous),
        async revoke() { throw new Error("provider unavailable"); }
      }
    });
    const installation = await createInstallation(app);
    const failed = await app.app.inject({ method: "POST", url: `/v1/installations/${installation.installationId}/revoke`, headers: auth });
    expect(failed.statusCode).toBe(503);
    expect(failed.json().error).toBe("upstream_unavailable");
    const absent = await app.app.inject({ method: "POST", url: "/v1/installations/inst_missing_123456/revoke", headers: auth });
    expect(absent.statusCode).toBe(404);
    expect(absent.json().error).toBe("installation_not_found");
  });

  it("rate-limits owner control operations and does not trust forwarded IP by default", async () => {
    const app = await makeApp({ limits: { rateBurst: 1, ratePerMinute: 1 } });
    const first = await app.app.inject({ method: "POST", url: "/v1/installations", headers: { ...auth, "x-forwarded-for": "198.51.100.10" }, payload: { vaultId } });
    expect(first.statusCode).toBe(201);
    const second = await app.app.inject({ method: "POST", url: "/v1/installations", headers: { ...auth, "x-forwarded-for": "203.0.113.9" }, payload: { vaultId: "vault_test_fixture_654321" } });
    expect(second.statusCode).toBe(429);
  });
});

describe("edge owner and installation boundary", () => {
  it("normalizes a trailing issuer slash and rejects path-based origins", async () => {
    const app = await makeApp({ origin: "https://edge.example.test/", issuer: "https://edge.example.test/" });
    expect(app.oauth.authorizationServerMetadata().issuer).toBe("https://edge.example.test");
    await expect(makeApp({ origin: "https://edge.example.test/base" })).rejects.toThrow(/origin URL/u);
  });

  it("provisions an opaque endpoint bundle without returning secret material", async () => {
    const app = await makeApp();
    const installation = await createInstallation(app);
    expect(installation.endpointBundle.mcpResourceUrl).toContain("/mcp");
    expect(installation.endpointBundle.tunnelCredential).toEqual(expect.objectContaining({ provider: "remote-file" }));
    expect(installation.endpointBundle.publisherMtlsCredential).toEqual(expect.objectContaining({ provider: "remote-file" }));
    expect(installation.endpointBundle.publisherEdgeAttestation).toEqual(expect.objectContaining({ provider: "remote-file" }));
    expect(installation.endpointBundle.mcpEdgeAttestation).toEqual(expect.objectContaining({ provider: "remote-file" }));
    expect(installation.endpointBundle.publisherEdgeAttestation.id).not.toBe(installation.endpointBundle.publisherMtlsCredential.id);
    expect(installation.endpointBundle.mcpEdgeAttestation.id).not.toBe(installation.endpointBundle.publisherEdgeAttestation.id);
    const serialized = JSON.stringify(installation);
    expect(serialized).not.toContain("tunnel-");
    expect(serialized).not.toContain("mtls-");
    expect(serialized).not.toContain("edge-attestation-");
    expect(serialized).not.toContain("mcp-edge-attestation-");
    const metadata = await app.app.inject({ method: "GET", url: `/.well-known/oauth-protected-resource?resource=${encodeURIComponent(installation.endpointBundle.mcpResourceUrl)}` });
    expect(metadata.statusCode).toBe(200);
    expect(metadata.json()).toMatchObject({ resource: installation.endpointBundle.mcpResourceUrl, scopes_supported: ["vault:read"] });
  });

  it("requires the owner boundary and never accepts a renderer-supplied owner id", async () => {
    const app = await makeApp();
    const missing = await app.app.inject({ method: "POST", url: "/v1/installations", payload: { vaultId } });
    expect(missing.statusCode).toBe(401);
    const forged = await app.app.inject({ method: "POST", url: "/v1/installations", headers: auth, payload: { vaultId }, query: { ownerId: "forged" } });
    expect(forged.statusCode).toBe(201);
    const list = await app.app.inject({ method: "GET", url: "/v1/installations", headers: auth });
    expect(list.json().installations).toHaveLength(1);
    expect(list.json().installations[0].ownerId).toBe(ownerId);
  });
});

describe("OAuth 2.1 PKCE", () => {
  it("completes authorization code flow, preserves state/resource, and rotates refresh tokens", async () => {
    const app = await makeApp({ autoApproveOwnerId: ownerId });
    const installation = await createInstallation(app);
    const resource = installation.endpointBundle.mcpResourceUrl;
    const redirectUri = "http://127.0.0.1:4555/callback";
    const client = await register(app, installation.installationId, resource, redirectUri);
    const verifier = "v".repeat(64);
    const authorization = await authorize(app, {
      client_id: client.client_id,
      redirect_uri: redirectUri,
      response_type: "code",
      scope: "vault:read",
      resource,
      code_challenge: pkceChallenge(verifier),
      code_challenge_method: "S256",
      state: "state-123",
      nonce: "nonce-123",
    });
    expect(authorization.statusCode).toBe(302);
    const location = new URL(authorization.headers.location ?? "");
    expect(location.searchParams.get("state")).toBe("state-123");
    const token = await app.app.inject({
      method: "POST",
      url: "/oauth/token",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      payload: new URLSearchParams({ grant_type: "authorization_code", code: location.searchParams.get("code") ?? "", client_id: client.client_id, redirect_uri: redirectUri, code_verifier: verifier, resource }).toString(),
    });
    expect(token.statusCode).toBe(200);
    const tokenBody = token.json<{ access_token: string; refresh_token: string; token_type: string }>();
    expect(tokenBody.token_type).toBe("Bearer");
    const verified = await app.oauth.verifyAccessToken(tokenBody.access_token, { installationId: installation.installationId, resource });
    expect(verified.scope).toBe("vault:read");
    expect(verified.subject).toBe(ownerId);
    const refresh = await app.app.inject({
      method: "POST",
      url: "/oauth/token",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      payload: new URLSearchParams({ grant_type: "refresh_token", refresh_token: tokenBody.refresh_token, client_id: client.client_id, resource }).toString(),
    });
    expect(refresh.statusCode).toBe(200);
    expect(refresh.json().refresh_token).not.toBe(tokenBody.refresh_token);
    const replay = await app.app.inject({
      method: "POST",
      url: "/oauth/token",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      payload: new URLSearchParams({ grant_type: "refresh_token", refresh_token: tokenBody.refresh_token, client_id: client.client_id, resource }).toString(),
    });
    expect(replay.statusCode).toBe(400);
    expect(replay.json().error).toBe("invalid_grant");
  });

  it("revokes a client epoch, cascades codes and refresh tokens, and allows a new authorization", async () => {
    const app = await makeApp({ autoApproveOwnerId: ownerId });
    const installation = await createInstallation(app);
    const resource = installation.endpointBundle.mcpResourceUrl;
    const redirectUri = "http://127.0.0.1:4558/callback";
    const client = await register(app, installation.installationId, resource, redirectUri);
    const verifier = "r".repeat(64);
    const authorizeOnce = async (value: string) => {
      const response = await authorize(app, {
        client_id: client.client_id,
        redirect_uri: redirectUri,
        response_type: "code",
        resource,
        code_challenge: pkceChallenge(value),
        code_challenge_method: "S256",
      });
      expect(response.statusCode).toBe(302);
      return new URL(response.headers.location ?? "").searchParams.get("code") ?? "";
    };
    const firstCode = await authorizeOnce(verifier);
    const pendingCode = await authorizeOnce("s".repeat(64));
    expect(pendingCode).not.toBe(firstCode);
    const token = await app.app.inject({
      method: "POST",
      url: "/oauth/token",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      payload: new URLSearchParams({ grant_type: "authorization_code", code: firstCode, client_id: client.client_id, redirect_uri: redirectUri, code_verifier: verifier, resource }).toString(),
    });
    expect(token.statusCode).toBe(200);
    const tokenBody = token.json<{ access_token: string; refresh_token: string }>();
    const beforeEpoch = app.oauth.getClient(client.client_id)?.revocationEpoch;
    expect(beforeEpoch).toBe(0);
    const revoked = await app.app.inject({
      method: "POST",
      url: "/oauth/revoke",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      payload: new URLSearchParams({ token: tokenBody.access_token, client_id: client.client_id }).toString(),
    });
    expect(revoked.statusCode).toBe(200);
    expect(app.oauth.getClient(client.client_id)?.revocationEpoch).toBe(1);
    expect([...app.store.authorizationCodes.values()].some((record) => record.clientId === client.client_id)).toBe(false);
    expect([...app.store.refreshTokens.values()].some((record) => record.clientId === client.client_id)).toBe(false);
    await expect(app.oauth.verifyAccessToken(tokenBody.access_token, { installationId: installation.installationId, resource })).rejects.toMatchObject({ error: "invalid_token" });

    const nextCode = await authorizeOnce("t".repeat(64));
    const nextToken = await app.app.inject({
      method: "POST",
      url: "/oauth/token",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      payload: new URLSearchParams({ grant_type: "authorization_code", code: nextCode, client_id: client.client_id, redirect_uri: redirectUri, code_verifier: "t".repeat(64), resource }).toString(),
    });
    expect(nextToken.statusCode).toBe(200);
    await expect(app.oauth.verifyAccessToken(nextToken.json<{ access_token: string }>().access_token, { installationId: installation.installationId, resource })).resolves.toMatchObject({ revocationEpoch: 1 });
    // The old refresh token was removed by the client-scope cascade.
    const replayRefresh = await app.app.inject({
      method: "POST",
      url: "/oauth/token",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      payload: new URLSearchParams({ grant_type: "refresh_token", refresh_token: tokenBody.refresh_token, client_id: client.client_id, resource }).toString(),
    });
    expect(replayRefresh.statusCode).toBe(400);
  });

  it("authenticates installation-scoped introspection with the distinct MCP edge credential", async () => {
    const credentials = new MemoryCredentialVault();
    const app = await makeApp({ autoApproveOwnerId: ownerId }, { credentialVault: credentials });
    const installation = await createInstallation(app);
    const resource = installation.endpointBundle.mcpResourceUrl;
    const redirectUri = "http://127.0.0.1:4559/callback";
    const client = await register(app, installation.installationId, resource, redirectUri);
    const verifier = "u".repeat(64);
    const authorization = await authorize(app, { client_id: client.client_id, redirect_uri: redirectUri, response_type: "code", resource, code_challenge: pkceChallenge(verifier), code_challenge_method: "S256" });
    const code = new URL(authorization.headers.location ?? "").searchParams.get("code") ?? "";
    const tokenResponse = await app.app.inject({
      method: "POST", url: "/oauth/token", headers: { "content-type": "application/x-www-form-urlencoded" },
      payload: new URLSearchParams({ grant_type: "authorization_code", code, client_id: client.client_id, redirect_uri: redirectUri, code_verifier: verifier, resource }).toString(),
    });
    const accessToken = tokenResponse.json<{ access_token: string }>().access_token;
    const secret = await credentials.get(installation.endpointBundle.mcpEdgeAttestation);
    expect(secret).toBeTruthy();
    const introspect = async (bearer: string, token = accessToken) => app.app.inject({
      method: "POST",
      url: `/v1/installations/${installation.installationId}/oauth/introspect`,
      headers: { "content-type": "application/json", authorization: `Bearer ${bearer}` },
      payload: { token },
    });
    expect((await introspect(secret ?? "")).statusCode).toBe(200);
    expect((await introspect(secret ?? "")).json()).toEqual({ active: true });
    const wrong = await introspect("wrong-introspection-secret");
    expect(wrong.statusCode).toBe(401);
    const revoked = await app.app.inject({
      method: "POST", url: "/oauth/revoke", headers: { "content-type": "application/x-www-form-urlencoded" },
      payload: new URLSearchParams({ token: accessToken, client_id: client.client_id }).toString(),
    });
    expect(revoked.statusCode).toBe(200);
    expect((await introspect(secret ?? "")).json()).toEqual({ active: false });
    const unknown = await app.app.inject({ method: "POST", url: "/v1/installations/inst_unknown_123456/oauth/introspect", headers: { "content-type": "application/json", authorization: "Bearer wrong" }, payload: { token: accessToken } });
    expect(unknown.statusCode).toBe(200);
    expect(unknown.json()).toEqual({ active: false });
  });

  it("rejects wrong verifier without consuming the code, then rejects replay", async () => {
    const app = await makeApp({ autoApproveOwnerId: ownerId });
    const installation = await createInstallation(app);
    const redirectUri = "http://127.0.0.1:4556/callback";
    const client = await register(app, installation.installationId, installation.endpointBundle.mcpResourceUrl, redirectUri);
    const verifier = "a".repeat(64);
    const authorization = await authorize(app, {
      client_id: client.client_id,
      redirect_uri: redirectUri,
      response_type: "code",
      resource: installation.endpointBundle.mcpResourceUrl,
      code_challenge: pkceChallenge(verifier),
      code_challenge_method: "S256",
    });
    const code = new URL(authorization.headers.location ?? "").searchParams.get("code") ?? "";
    const wrong = await app.app.inject({
      method: "POST", url: "/oauth/token", headers: { "content-type": "application/x-www-form-urlencoded" },
      payload: new URLSearchParams({ grant_type: "authorization_code", code, client_id: client.client_id, redirect_uri: redirectUri, code_verifier: "b".repeat(64), resource: installation.endpointBundle.mcpResourceUrl }).toString(),
    });
    expect(wrong.statusCode).toBe(400);
    const missingResource = await app.app.inject({
      method: "POST", url: "/oauth/token", headers: { "content-type": "application/x-www-form-urlencoded" },
      payload: new URLSearchParams({ grant_type: "authorization_code", code, client_id: client.client_id, redirect_uri: redirectUri, code_verifier: verifier }).toString(),
    });
    expect(missingResource.statusCode).toBe(400);
    const mismatchedResource = await app.app.inject({
      method: "POST", url: "/oauth/token", headers: { "content-type": "application/x-www-form-urlencoded" },
      payload: new URLSearchParams({ grant_type: "authorization_code", code, client_id: client.client_id, redirect_uri: redirectUri, code_verifier: verifier, resource: "https://other.example.test/mcp" }).toString(),
    });
    expect(mismatchedResource.statusCode).toBe(400);
    const success = await app.app.inject({
      method: "POST", url: "/oauth/token", headers: { "content-type": "application/x-www-form-urlencoded" },
      payload: new URLSearchParams({ grant_type: "authorization_code", code, client_id: client.client_id, redirect_uri: redirectUri, code_verifier: verifier, resource: installation.endpointBundle.mcpResourceUrl }).toString(),
    });
    expect(success.statusCode).toBe(200);
    const replay = await app.app.inject({
      method: "POST", url: "/oauth/token", headers: { "content-type": "application/x-www-form-urlencoded" },
      payload: new URLSearchParams({ grant_type: "authorization_code", code, client_id: client.client_id, redirect_uri: redirectUri, code_verifier: verifier, resource: installation.endpointBundle.mcpResourceUrl }).toString(),
    });
    expect(replay.statusCode).toBe(400);
  });

  it("fails closed for wrong redirect and cross-installation resource/client use", async () => {
    const app = await makeApp({ autoApproveOwnerId: ownerId });
    const first = await createInstallation(app);
    const second = await createInstallation(app, ownerId, "vault_test_fixture_654321");
    const redirectUri = "http://127.0.0.1:4557/callback";
    const client = await register(app, first.installationId, first.endpointBundle.mcpResourceUrl, redirectUri);
    const wrongRedirect = await authorize(app, {
      client_id: client.client_id,
      redirect_uri: "http://127.0.0.1:4557/other",
      response_type: "code",
      resource: first.endpointBundle.mcpResourceUrl,
      code_challenge: pkceChallenge("c".repeat(64)),
      code_challenge_method: "S256",
    });
    expect(wrongRedirect.statusCode).toBe(400);
    const wrongResource = await authorize(app, {
      client_id: client.client_id,
      redirect_uri: redirectUri,
      response_type: "code",
      resource: second.endpointBundle.mcpResourceUrl,
      code_challenge: pkceChallenge("c".repeat(64)),
      code_challenge_method: "S256",
    });
    expect(wrongResource.statusCode).toBe(400);
  });

  it("serves discovery and public JWKS without private key members", async () => {
    const app = await makeApp();
    const metadata = await app.app.inject({ method: "GET", url: "/.well-known/oauth-authorization-server" });
    expect(metadata.statusCode).toBe(200);
    expect(metadata.json()).toMatchObject({ code_challenge_methods_supported: ["S256"], token_endpoint_auth_methods_supported: ["none"] });
    const jwks = await app.app.inject({ method: "GET", url: "/.well-known/jwks.json" });
    expect(jwks.statusCode).toBe(200);
    expect(jwks.json().keys[0]).not.toHaveProperty("d");
    expect(jwks.json().keys[0]).toHaveProperty("kid");
  });
});

describe("provider boundary", () => {
  it("keeps credentials in the vault and makes external provider use explicit", async () => {
    const credentials = new MemoryCredentialVault();
    const app = await makeApp({}, { credentialVault: credentials });
    const installation = await createInstallation(app);
    expect(credentials.has(installation.endpointBundle.tunnelCredential)).toBe(true);
    expect(credentials.has(installation.endpointBundle.publisherMtlsCredential)).toBe(true);
    expect(credentials.has(installation.endpointBundle.publisherEdgeAttestation)).toBe(true);
    expect(credentials.has(installation.endpointBundle.mcpEdgeAttestation)).toBe(true);
    await expect(new ExternalTunnelProvider("cloudflare").provision({ installationId: installation.installationId, vaultId, ownerId })).rejects.toThrow("EDGE_PROVIDER_NOT_CONFIGURED");
  });

  it("materializes one privileged credential through a short-lived X25519 envelope", async () => {
    const app = await makeApp();
    const installation = await createInstallation(app);
    const client = generateKeyPairSync("x25519");
    const clientPublicKey = Buffer.from(client.publicKey.export({ format: "der", type: "spki" })).toString("base64url");
    const lease = await app.app.inject({
      method: "POST",
      url: `/v1/installations/${installation.installationId}/credentials/lease`,
      headers: auth,
      payload: { kind: "tunnel", client_public_key: clientPublicKey },
    });
    expect(lease.statusCode).toBe(201);
    const leaseBody = lease.json<{ leaseId: string; serverPublicKey: string; algorithm: string }>();
    expect(leaseBody.algorithm).toBe("X25519-HKDF-SHA256-AES-256-GCM");
    expect(leaseBody).not.toHaveProperty("secret");
    const redeemed = await app.app.inject({ method: "POST", url: `/v1/credential-leases/${leaseBody.leaseId}/redeem`, headers: auth });
    expect(redeemed.statusCode).toBe(200);
    const encrypted = redeemed.json<{ ciphertext: string; nonce: string; tag: string; serverPublicKey: string; kind: string }>();
    expect(encrypted.kind).toBe("tunnel");
    expect(JSON.stringify(encrypted)).not.toContain("tunnel-");
    const serverPublicKey = createPublicKey({ key: Buffer.from(encrypted.serverPublicKey, "base64url"), format: "der", type: "spki" });
    const shared = diffieHellman({ privateKey: client.privateKey, publicKey: serverPublicKey });
    const key = Buffer.from(hkdfSync("sha256", shared, Buffer.from(hashOpaque(`${installation.installationId}:${leaseBody.leaseId}`), "base64url"), Buffer.from("vault-bridge/credential-lease", "utf8"), 32));
    const decipher = createDecipheriv("aes-256-gcm", key, Buffer.from(encrypted.nonce, "base64url"));
    decipher.setAAD(Buffer.from(`${installation.installationId}:${leaseBody.leaseId}:tunnel`, "utf8"));
    decipher.setAuthTag(Buffer.from(encrypted.tag, "base64url"));
    const secret = Buffer.concat([decipher.update(Buffer.from(encrypted.ciphertext, "base64url")), decipher.final()]).toString("utf8");
    expect(secret).toMatch(/^tunnel-/u);
    const replay = await app.app.inject({ method: "POST", url: `/v1/credential-leases/${leaseBody.leaseId}/redeem`, headers: auth });
    expect(replay.statusCode).toBe(404);
  });

  it("fails closed in production when owner identity or durable OAuth keys are absent", async () => {
    await expect(createEdgeApp({
      config: {
        nodeEnv: "production",
        mode: "managed",
        origin: "https://edge.example.test",
        issuer: "https://edge.example.test",
        providerName: "cloudflare",
      },
    })).rejects.toThrow("production owner identity verification is not configured");
  });

  it("fails closed in production when a durable edge store is not injected", async () => {
    await expect(createEdgeApp({
      config: {
        nodeEnv: "production",
        mode: "managed",
        origin: "https://edge.example.test",
        issuer: "https://edge.example.test",
        providerName: "cloudflare",
        ownerIssuer: "https://identity.example.test",
        ownerAudience: "vault-bridge-owner",
        ownerAuthorizationUrl: "https://identity.example.test/authorize",
        ownerJwks: { keys: [{ kty: "OKP", crv: "Ed25519", x: "A".repeat(43), kid: "owner-key", alg: "EdDSA" }] },
      },
    })).rejects.toThrow("EDGE_DURABLE_STORE_REQUIRED");
  });
});
