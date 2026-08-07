import { describe, expect, it } from "vitest";

import {
  assertTrustedSender,
  isAllowedAppUrl,
  isAllowedExternalUrl,
  isAllowedMcpResourceUrl,
  isIpcChannel,
  isWithinDirectory
} from "../src/security.js";

describe("desktop renderer security boundary", () => {
  it("accepts only the private app renderer origin", () => {
    expect(isAllowedAppUrl("vaultbridge://app/index.html")).toBe(true);
    expect(isAllowedAppUrl("https://renderer/index.html")).toBe(false);
    expect(isAllowedAppUrl("vaultbridge://other/index.html")).toBe(false);
    expect(isAllowedAppUrl("vaultbridge://app@evil/index.html")).toBe(false);
    expect(isAllowedAppUrl("vaultbridge://app/index.html?next=https://evil")).toBe(true);
  });

  it("accepts only credential-free HTTPS links for external navigation", () => {
    expect(isAllowedExternalUrl("https://mcp.example.invalid/connect")).toBe(true);
    expect(isAllowedExternalUrl("http://mcp.example.invalid/connect")).toBe(false);
    expect(isAllowedExternalUrl("https://user:pass@mcp.example.invalid")).toBe(false);
    expect(isAllowedExternalUrl("https://mcp.example.invalid/?token=secret")).toBe(false);
    expect(isAllowedExternalUrl("https://mcp.example.invalid/#token")).toBe(false);
  });

  it("copies only an exact credential-free HTTPS MCP resource", () => {
    expect(isAllowedMcpResourceUrl("https://mcp.example.invalid/mcp")).toBe(true);
    expect(isAllowedMcpResourceUrl("http://mcp.example.invalid/mcp")).toBe(false);
    expect(isAllowedMcpResourceUrl("https://mcp.example.invalid/mcp?token=secret")).toBe(false);
    expect(isAllowedMcpResourceUrl("https://user:pass@mcp.example.invalid/mcp")).toBe(false);
    expect(isAllowedMcpResourceUrl("https://mcp.example.invalid/other")).toBe(false);
  });

  it("requires both the expected web contents and app origin", () => {
    expect(() => assertTrustedSender(7, "vaultbridge://app/index.html", 7)).not.toThrow();
    expect(() => assertTrustedSender(8, "vaultbridge://app/index.html", 7)).toThrow();
    expect(() => assertTrustedSender(7, "file:///tmp/index.html", 7)).toThrow();
  });

  it("keeps IPC channels explicit and path checks boundary-safe", () => {
    expect(isIpcChannel("state:get")).toBe(true);
    expect(isIpcChannel("security:disconnect")).toBe(true);
    expect(isIpcChannel("security:remove-server-copy")).toBe(true);
    expect(isIpcChannel("shell:exec")).toBe(false);
    expect(isWithinDirectory("/app/dist/renderer", "/app/dist/renderer/index.html")).toBe(true);
    expect(isWithinDirectory("/app/dist/renderer", "/app/dist/renderer/../main.js")).toBe(false);
  });
});
