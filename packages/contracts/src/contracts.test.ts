import { generateKeyPairSync } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  FetchInputSchema,
  FetchOutputSchema,
  EndpointBundleSchema,
  InstallationStateSchema,
  SearchInputSchema,
  SnapshotDocumentSchema,
  canonicalSignedRequestPayload,
  computeSnapshotDigest,
  normalizeVaultId,
  sha256Base64Url,
  signCanonicalRequest,
  verifyCanonicalRequest,
  verifySnapshotDigest,
  type Snapshot
} from "./index.js";

const id = "0123456789abcdefghijklmnopqrstuv";
const text = "hello";
const document = {
  id,
  title: "Demo",
  mediaType: "text/markdown" as const,
  text,
  sourceHash: sha256Base64Url(text),
  modifiedAt: "2026-08-07T00:00:00.000Z"
};

describe("protocol contracts", () => {
  it("rejects a source hash that does not cover document text", () => {
    expect(() => SnapshotDocumentSchema.parse({ ...document, sourceHash: sha256Base64Url("tampered") })).toThrow();
  });

  it("keeps search input and result count bounded", () => {
    expect(SearchInputSchema.parse({ query: "find me" })).toEqual({ query: "find me" });
    expect(() => SearchInputSchema.parse({ query: "x".repeat(513) })).toThrow();
    expect(() => FetchInputSchema.parse({ id })).not.toThrow();
    expect(() => FetchOutputSchema.parse({ id, title: "Demo", text, url: "https://example.invalid/doc" })).not.toThrow();
    expect(() => FetchOutputSchema.parse({ id, title: "Demo", text, url: "" })).not.toThrow();
    expect(() => FetchOutputSchema.parse({ id, title: "Demo", text, url: "http://example.invalid/doc" })).toThrow();
  });

  it("canonicalizes snapshot documents independent of input order", () => {
    const second = { ...document, id: "abcdefghijklmnopqrstuvwxyz012345" };
    const first = { version: 1 as const, snapshotId: "b2d6eaa8-9db3-4a8f-9c4e-3f6d5d0e08f5", vaultId: id, generation: 2, createdAt: "2026-08-07T00:00:00.000Z", documents: [document, second] };
    const reversed = { ...first, documents: [second, document] };
    expect(computeSnapshotDigest(first)).toBe(computeSnapshotDigest(reversed));
    const snapshot = {
      ...first,
      digest: computeSnapshotDigest(first)
    } satisfies Snapshot;
    expect(verifySnapshotDigest(snapshot)).toBe(true);
    expect(verifySnapshotDigest({ ...snapshot, documents: [{ ...document, text: "changed" }, second] })).toBe(false);
    expect(verifySnapshotDigest({ ...snapshot, snapshotId: "8b2a4d9f-ced4-4857-96ab-02e9626e1691" })).toBe(false);
  });

  it("signs the canonical request envelope with Ed25519", () => {
    const fields = { method: "post", path: "/v1/snapshots", timestamp: 1_754_521_600, nonce: "n-1", digest: "d-1" };
    expect(canonicalSignedRequestPayload(fields)).toBe("POST\n/v1/snapshots\n1754521600\nn-1\nd-1");
    const keys = generateKeyPairSync("ed25519");
    const signature = signCanonicalRequest(fields, keys.privateKey);
    expect(verifyCanonicalRequest(fields, signature, keys.publicKey)).toBe(true);
    expect(verifyCanonicalRequest({ ...fields, nonce: "n-2" }, signature, keys.publicKey)).toBe(false);
  });

  it("normalizes human vault aliases and preserves opaque ids", () => {
    expect(normalizeVaultId("my-vault")).toBe(normalizeVaultId(" my-vault "));
    expect(normalizeVaultId("my-vault")).toMatch(/^vault_[A-Za-z0-9_-]{43}$/u);
    expect(normalizeVaultId("vault_test_0000001")).toBe("vault_test_0000001");
    expect(() => normalizeVaultId("../outside")).toThrow(/unsupported/u);
  });

  it("keeps product state secret-free and separates MCP from publisher hosts", () => {
    const verification = {
      issuer: "https://auth.example.invalid/",
      audience: "https://mcp.example.invalid/mcp",
      keys: [{ kty: "OKP", kid: "key-1", crv: "Ed25519", x: "public-only" }],
      issuedAt: "2026-08-07T00:00:00.000Z",
      expiresAt: "2026-08-08T00:00:00.000Z"
    };
    const endpoint = {
      version: 1 as const,
      installationId: id,
      vaultId: id,
      mcpResourceUrl: "https://mcp.example.invalid/mcp",
      publisherUrl: "https://publish.example.invalid/v1/snapshots",
      mcpHost: "mcp.example.invalid",
      publisherHost: "publish.example.invalid",
      oauthIssuer: "https://auth.example.invalid/",
      oauthAuthorizationEndpoint: "https://auth.example.invalid/authorize",
      oauthTokenEndpoint: "https://auth.example.invalid/token",
      oauthJwksUri: "https://auth.example.invalid/jwks",
      oauthProtectedResourceMetadataUrl: "https://mcp.example.invalid/.well-known/oauth-protected-resource",
      oauthAudience: verification.audience,
      tunnelCredential: { provider: "remote-file" as const, id: "tunnel_0123456789abcdef" },
      publisherMtlsCredential: { provider: "safe-storage" as const, id: "mtls_0123456789abcdef" },
      publisherEdgeAttestation: { provider: "remote-file" as const, id: "attestation_0123456789abcdef" },
      mcpEdgeAttestation: { provider: "remote-file" as const, id: "mcp_attestation_0123456789abcdef" },
      oauthVerificationBundle: verification
    };

    expect(EndpointBundleSchema.parse(endpoint)).toEqual(endpoint);
    expect(() => EndpointBundleSchema.parse({ ...endpoint, publisherHost: endpoint.mcpHost })).toThrow(/separate/u);
    expect(() => EndpointBundleSchema.parse({ ...endpoint, publisherEdgeAttestation: endpoint.tunnelCredential })).toThrow(/distinct/u);
    expect(() => EndpointBundleSchema.parse({ ...endpoint, mcpEdgeAttestation: endpoint.publisherEdgeAttestation })).toThrow(/distinct/u);

    const state = InstallationStateSchema.parse({
      version: 1,
      installationId: id,
      vaultId: id,
      stage: "ready",
      status: "ready",
      serverCopy: "active",
      sshTarget: { host: "server.example.invalid", user: "deploy", port: 22 },
      endpoint,
      updatedAt: "2026-08-07T00:00:00.000Z"
    });
    expect(JSON.stringify(state)).not.toMatch(/"(?:accessToken|refreshToken|privateKey|secretValue)":/u);
  });
});
