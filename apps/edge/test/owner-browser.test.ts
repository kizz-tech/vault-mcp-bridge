import { describe, expect, it } from "vitest";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { canonicalOwnerId } from "../src/owner.js";
import {
  MemoryOwnerBrowserStateStore,
  OwnerBrowserError,
  OwnerBrowserOidcBridge,
} from "../src/owner-browser.js";

const issuer = "https://accounts.example.test";
const edgeOrigin = "https://edge.example.test";
const redirectUri = `${edgeOrigin}/owner/callback`;
const returnUrl = `${edgeOrigin}/oauth/authorize?client_id=client_fixture&redirect_uri=https%3A%2F%2F127.0.0.1%3A4555%2Fcallback`;

describe("owner browser OIDC bridge", () => {
  it("starts public S256 PKCE and verifies a local ID token once", async () => {
    const { privateKey, publicKey } = await generateKeyPair("RS256");
    const publicJwk = await exportJWK(publicKey);
    publicJwk.kid = "owner-fixture";
    let randomCounter = 0;
    let tokenCalls = 0;
    let request: RequestInit | undefined;
    const bridge = new OwnerBrowserOidcBridge({
      issuer,
      clientId: "owner-client-fixture",
      authorizationEndpoint: `${issuer}/authorize`,
      tokenEndpoint: `${issuer}/token`,
      redirectUri,
      origin: edgeOrigin,
      jwks: { keys: [publicJwk] },
      random: (size) => Buffer.alloc(size, ++randomCounter),
      fetch: async (_input, init) => {
        request = init;
        tokenCalls += 1;
        const body = new URLSearchParams(String(init?.body));
        const idToken = await new SignJWT({ nonce: new URL(login.authorizationUrl).searchParams.get("nonce") ?? "" })
          .setProtectedHeader({ alg: "RS256", kid: "owner-fixture" })
          .setIssuer(issuer)
          .setAudience("owner-client-fixture")
          .setSubject("subject-fixture")
          .setExpirationTime("5m")
          .sign(privateKey);
        expect(body.get("code_verifier")).toBeTruthy();
        return new Response(JSON.stringify({ access_token: "TEST_ACCESS_TOKEN_VALUE", id_token: idToken }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      },
    });

    const login = bridge.startLogin({ returnUrl });
    const authorization = new URL(login.authorizationUrl);
    expect(authorization.searchParams.get("response_type")).toBe("code");
    expect(authorization.searchParams.get("code_challenge_method")).toBe("S256");
    expect(authorization.searchParams.get("code_challenge")).toHaveLength(43);
    expect(authorization.searchParams.get("client_secret")).toBeNull();

    const result = await bridge.handleCallback(`${redirectUri}?code=code-fixture&state=${encodeURIComponent(login.state)}`);
    expect(result).toEqual({ ownerId: canonicalOwnerId(issuer, "subject-fixture"), returnUrl });
    expect(tokenCalls).toBe(1);
    expect(request?.method).toBe("POST");
    expect(request?.redirect).toBe("error");
    expect(String(request?.body)).not.toContain("client_secret");
    await expect(bridge.handleCallback(`${redirectUri}?code=code-fixture&state=${encodeURIComponent(login.state)}`)).rejects.toMatchObject({ code: "invalid_state" });
  });

  it("hashes state, bounds the store, and reclaims expired records", () => {
    let now = 1_000;
    const store = new MemoryOwnerBrowserStateStore({ maxEntries: 1, ttlMs: 10, now: () => now });
    const record = { verifier: "verifier", nonce: "nonce", returnUrl, expiresAt: now + 10 };
    store.set("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", record);
    expect([...store.entries()][0]?.[0]).not.toContain("state-fixture");
    expect(() => store.set("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB", record)).toThrowError(/capacity/u);
    now += 11;
    expect(store.consume("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")).toBeUndefined();
    store.set("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB", { ...record, expiresAt: now + 10 });
    expect(store.size).toBe(1);
  });

  it("rejects cross-origin return URLs and non-loopback HTTP", () => {
    const options = {
      issuer,
      clientId: "owner-client-fixture",
      authorizationEndpoint: `${issuer}/authorize`,
      tokenEndpoint: `${issuer}/token`,
      redirectUri,
      origin: edgeOrigin,
      verifyIdToken: async () => ({ payload: { iss: issuer, aud: "owner-client-fixture", nonce: "n", sub: "s" } }),
    } as const;
    const bridge = new OwnerBrowserOidcBridge(options);
    expect(() => bridge.startLogin({ returnUrl: "https://evil.example.test/oauth/authorize" })).toThrowError(OwnerBrowserError);
    expect(() => new OwnerBrowserOidcBridge({ ...options, authorizationEndpoint: "http://accounts.example.test/authorize" })).toThrowError(/HTTPS/u);
    expect(() => new OwnerBrowserOidcBridge({ ...options, authorizationEndpoint: "http://127.0.0.1/authorize", tokenEndpoint: "http://127.0.0.1/token", redirectUri: "http://127.0.0.1:8787/callback", origin: "http://127.0.0.1:8787" })).toThrowError(/HTTPS/u);
    expect(new OwnerBrowserOidcBridge({ ...options, allowLoopbackDev: true, authorizationEndpoint: "http://127.0.0.1/authorize", tokenEndpoint: "http://127.0.0.1/token", redirectUri: "http://127.0.0.1:8787/callback", origin: "http://127.0.0.1:8787" })).toBeInstanceOf(OwnerBrowserOidcBridge);
  });
});
