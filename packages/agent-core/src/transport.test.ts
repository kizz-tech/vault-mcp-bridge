import { describe, expect, it } from "vitest";
import { NodeHttpsPublisherTransport, type PublisherRequestExecutor, type PublisherTlsCredentialProvider } from "./transport.js";

const tlsProvider: PublisherTlsCredentialProvider = {
  async get() {
    return { certificate: "-----BEGIN CERTIFICATE-----synthetic-----END CERTIFICATE-----", privateKey: "-----BEGIN PRIVATE KEY-----synthetic-----END PRIVATE KEY-----" };
  }
};

describe("publisher HTTPS transport", () => {
  it("injects ephemeral client credentials and rejects redirects", async () => {
    let captured: Parameters<PublisherRequestExecutor>[0] | undefined;
    const executor: PublisherRequestExecutor = async (input) => {
      captured = input;
      return { statusCode: 200, headers: { "content-length": "2" }, body: "{}" };
    };
    const transport = new NodeHttpsPublisherTransport({ credentialProvider: tlsProvider, requireMtls: true, executor });
    const response = await transport.request({ url: new URL("https://publisher.example/v1/status"), method: "GET" });
    expect(response.statusCode).toBe(200);
    expect(captured?.tls?.certificate).toContain("CERTIFICATE");
    expect(captured?.tls?.privateKey).toContain("PRIVATE KEY");
    const redirect = new NodeHttpsPublisherTransport({ executor: async () => ({ statusCode: 302, headers: {}, body: "" }) });
    await expect(redirect.request({ url: new URL("https://publisher.example/redirect"), method: "GET" })).rejects.toThrow("redirect refused");
  });

  it("fails closed when production mTLS material is unavailable", async () => {
    const missing: PublisherTlsCredentialProvider = { async get() { return undefined; } };
    const transport = new NodeHttpsPublisherTransport({ credentialProvider: missing, requireMtls: true, executor: async () => ({ statusCode: 200, headers: {}, body: "{}" }) });
    await expect(transport.request({ url: new URL("https://publisher.example/v1/status"), method: "GET" })).rejects.toThrow("publisher_mtls_credentials_required");
  });

  it("allows loopback HTTP only when explicitly enabled and bounds request bodies", async () => {
    const executor: PublisherRequestExecutor = async () => ({ statusCode: 200, headers: {}, body: "{}" });
    const transport = new NodeHttpsPublisherTransport({ allowLoopbackHttp: true, executor });
    await expect(transport.request({ url: new URL("http://127.0.0.1:8787/v1/status"), method: "GET" })).resolves.toMatchObject({ statusCode: 200 });
    await expect(new NodeHttpsPublisherTransport({ executor }).request({ url: new URL("http://127.0.0.1:8787/v1/status"), method: "GET" })).rejects.toThrow("HTTPS is required");
    await expect(transport.request({ url: new URL("https://publisher.example/v1/upload"), method: "POST", body: "x".repeat(16 * 1024 * 1024 + 1) })).rejects.toThrow("request body is too large");
  });
});
