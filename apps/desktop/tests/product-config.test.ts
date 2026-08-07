import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import { loadProductConfig, validateProductConfig } from "../src/product-config.js";

const base = {
  edgeOrigin: "https://edge.example.invalid",
  ownerIssuer: "https://issuer.example.invalid/",
  ownerAuthorizationEndpoint: "https://issuer.example.invalid/oauth/authorize",
  ownerTokenEndpoint: "https://issuer.example.invalid/oauth/token",
  ownerJwksUri: "https://issuer.example.invalid/.well-known/jwks.json",
  ownerAudience: "edge-api",
  ownerClientId: "desktop-client",
  images: {
    serverRepository: "ghcr.io/example/server",
    serverDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    tunnelRepository: "cloudflare/cloudflared",
    tunnelDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
  }
};

describe("desktop product config", () => {
  it("keeps issuer trailing slash and rejects secrets", () => {
    const config = validateProductConfig(base);
    expect(config.ownerIssuer).toBe(base.ownerIssuer);
    expect(() => validateProductConfig({ ...base, accessToken: "secret" })).toThrow();
    expect(() => validateProductConfig({ ...base, runtimeMode: "host" })).toThrow("config_runtime_mode_invalid");
    expect(() => validateProductConfig({ ...base, edgeOrigin: "https://edge.example.invalid/api" })).toThrow("config_edge_origin_invalid");
    expect(() => validateProductConfig({ ...base, ownerTokenEndpoint: "https://issuer.example.invalid/oauth/token?secret=fixed" })).toThrow("config_owner_token_endpoint_invalid");
  });

  it("allows loopback only when explicitly enabled", () => {
    expect(() => validateProductConfig({ ...base, edgeOrigin: "http://127.0.0.1:8790" })).toThrow();
    expect(validateProductConfig({ ...base, edgeOrigin: "http://127.0.0.1:8790", development: true }, true).edgeOrigin).toContain("127.0.0.1");
  });

  it("does not let an ambient development environment silently enable loopback", async () => {
    await expect(loadProductConfig({
      env: {
        NODE_ENV: "development",
        VAULT_BRIDGE_EDGE_ORIGIN: "http://127.0.0.1:8790",
        VAULT_BRIDGE_OWNER_ISSUER: base.ownerIssuer,
        VAULT_BRIDGE_OWNER_AUTHORIZATION_ENDPOINT: base.ownerAuthorizationEndpoint,
        VAULT_BRIDGE_OWNER_TOKEN_ENDPOINT: base.ownerTokenEndpoint,
        VAULT_BRIDGE_OWNER_JWKS_URI: base.ownerJwksUri,
        VAULT_BRIDGE_OWNER_AUDIENCE: base.ownerAudience,
        VAULT_BRIDGE_OWNER_CLIENT_ID: base.ownerClientId,
        VAULT_BRIDGE_SERVER_IMAGE_REPOSITORY: base.images.serverRepository,
        VAULT_BRIDGE_SERVER_IMAGE_DIGEST: base.images.serverDigest,
        VAULT_BRIDGE_TUNNEL_IMAGE_REPOSITORY: base.images.tunnelRepository,
        VAULT_BRIDGE_TUNNEL_IMAGE_DIGEST: base.images.tunnelDigest
      }
    })).rejects.toThrow("config_edge_origin_https_required");
  });

  it("rejects broad installation roots before remote cleanup can target them", () => {
    for (const installationDirectory of ["/", "/home", "/tmp", "/srv", "/home/deploy", "/srv/../etc"]) {
      expect(() => validateProductConfig({ ...base, installationDirectory })).toThrow("config_installation_directory_invalid");
    }
    expect(validateProductConfig({ ...base, installationDirectory: "/srv/vault-bridge" }).installationDirectory).toBe("/srv/vault-bridge");
  });

  it("uses a user override before the packaged public configuration", async () => {
    const directory = await mkdtemp(join(tmpdir(), "vault-bridge-config-"));
    const userConfig = join(directory, "user.json");
    const packagedConfig = join(directory, "packaged.json");
    await writeFile(userConfig, JSON.stringify({ ...base, ownerClientId: "user-override" }));
    await writeFile(packagedConfig, JSON.stringify({ ...base, ownerClientId: "packaged-default" }));

    await expect(loadProductConfig({ filePaths: [join(directory, "missing.json"), userConfig, packagedConfig], env: { NODE_ENV: "production" } }))
      .resolves.toMatchObject({ ownerClientId: "user-override" });
  });

  it("keeps the checked-in public configuration example valid and secret-free", async () => {
    const value: unknown = JSON.parse(await readFile(new URL("../product-config.example.json", import.meta.url), "utf8"));
    expect(validateProductConfig(value)).toMatchObject({ runtimeMode: "rootless", syncIntervalMinutes: 5 });
  });
});
