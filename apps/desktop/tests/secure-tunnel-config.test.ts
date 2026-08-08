import { describe, expect, it } from "vitest";

import { validateSecureTunnelProductConfig } from "../src/secure-tunnel-config.js";

describe("secure tunnel product config", () => {
  it("requires an immutable image in production", () => {
    const digest = "a".repeat(64);
    expect(validateSecureTunnelProductConfig({ image: `ghcr.io/example/vault-bridge@sha256:${digest}` })).toEqual({
      image: `ghcr.io/example/vault-bridge@sha256:${digest}`,
      syncIntervalMinutes: 5
    });
    expect(() => validateSecureTunnelProductConfig({ image: "ghcr.io/example/vault-bridge:latest" })).toThrow(/digest/u);
  });

  it("allows an explicit mutable development image only in development", () => {
    expect(validateSecureTunnelProductConfig({ image: "vault-mcp-bridge-secure-tunnel:local", syncIntervalMinutes: 10 }, true)).toEqual({
      image: "vault-mcp-bridge-secure-tunnel:local",
      syncIntervalMinutes: 10
    });
  });
});
