import { describe, expect, it } from "vitest";

import { SafeStorageOwnerTokenProvider } from "../src/oauth-client.js";

class MemorySecrets {
  value: string | null = null;
  async put(_ref: string, value: string): Promise<void> { this.value = value; }
  async get(_ref: string): Promise<string | null> { return this.value; }
  async remove(): Promise<void> { this.value = null; }
}

describe("owner token provider", () => {
  it("never returns expired access tokens and can clear the keychain ref", async () => {
    const secrets = new MemorySecrets();
    const provider = new SafeStorageOwnerTokenProvider(secrets);
    await secrets.put("owner.oauth.tokens", JSON.stringify({ accessToken: "opaque", expiresAt: Date.now() + 60_000 }));
    await expect(provider.getAccessToken()).resolves.toBe("opaque");
    await secrets.put("owner.oauth.tokens", JSON.stringify({ accessToken: "expired", expiresAt: Date.now() - 1 }));
    await expect(provider.getAccessToken()).resolves.toBeUndefined();
    await provider.clear();
    await expect(provider.getAccessToken()).resolves.toBeUndefined();
  });
});
