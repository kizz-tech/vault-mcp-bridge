import { NodeHttpsPublisherTransport, type PublisherTlsCredentialProvider, type RemoteClient, type PublisherStatus } from "@vault-mcp-bridge/agent-core";
import { CONTRACT_VERSION, PairDeviceResponseSchema, PublisherStatusResponseSchema, UploadReceiptSchema, sha256Base64Url, signCanonicalRequest } from "@vault-mcp-bridge/contracts";
import type { PublisherRequest } from "@vault-mcp-bridge/agent-core";

const RESPONSE_LIMIT = 2 * 1024 * 1024;

function opaqueNonce(): string {
  return `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 18)}`;
}

function allowedUrl(value: string, allowLoopback: boolean): URL {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error("publisher_url_invalid");
  }
  const loopback = ["localhost", "127.0.0.1", "::1"].includes(url.hostname.toLowerCase());
  if (url.protocol !== "https:" && !(allowLoopback && url.protocol === "http:" && loopback)) throw new Error("publisher_https_required");
  if (url.username || url.password || url.search || url.hash) throw new Error("publisher_url_invalid");
  return url;
}

export class DesktopPublisherClient implements RemoteClient {
  private readonly transport: NodeHttpsPublisherTransport;

  public constructor(
    private readonly allowLoopback: boolean,
    credentialProvider: PublisherTlsCredentialProvider
  ) {
    this.transport = new NodeHttpsPublisherTransport({ credentialProvider, requireMtls: true, allowLoopbackHttp: allowLoopback });
  }

  async pair(input: Parameters<RemoteClient["pair"]>[0]): Promise<Awaited<ReturnType<RemoteClient["pair"]>>> {
    const root = allowedUrl(input.url, this.allowLoopback);
    const url = new URL("/v1/pairing/consume", root);
    const value = await this.request(url, "POST", JSON.stringify({ version: CONTRACT_VERSION, pairCode: input.code, agentId: input.agentId, publicKey: input.publicKey, ...(input.vaultId ? { vaultId: input.vaultId } : {}), ...(input.label ? { label: input.label } : {}) }));
    const response = PairDeviceResponseSchema.parse(value);
    return { deviceId: response.deviceId, vaultId: response.vaultId, receipt: response };
  }

  async upload(input: Parameters<RemoteClient["upload"]>[0]): Promise<unknown> {
    const root = allowedUrl(input.url, this.allowLoopback);
    const url = new URL("/v1/snapshots", root);
    const snapshot = input.snapshot.snapshot as { digest?: string };
    if (!snapshot.digest) throw new Error("snapshot_digest_required");
    const timestamp = Math.floor(Date.now() / 1000);
    const nonce = opaqueNonce();
    const signature = signCanonicalRequest({ method: "POST", path: url.pathname, timestamp, nonce, digest: snapshot.digest }, input.privateKey);
    const value = await this.request(url, "POST", JSON.stringify({ deviceId: input.deviceId, vaultId: input.vaultId, timestamp, nonce, signature, snapshot: input.snapshot.snapshot }));
    return UploadReceiptSchema.parse(value);
  }

  async status(input: Parameters<RemoteClient["status"]>[0]): Promise<PublisherStatus> {
    const root = allowedUrl(input.url, this.allowLoopback);
    const url = new URL("/v1/status", root);
    url.searchParams.set("vaultId", input.vaultId);
    const timestamp = Math.floor(Date.now() / 1000);
    const nonce = opaqueNonce();
    const signature = signCanonicalRequest({ method: "GET", path: url.pathname, timestamp, nonce, digest: sha256Base64Url(input.vaultId) }, input.privateKey);
    const value = await this.request(url, "GET", undefined, {
      accept: "application/json",
      "x-bridge-device-id": input.deviceId,
      "x-bridge-vault-id": input.vaultId,
      "x-bridge-timestamp": String(timestamp),
      "x-bridge-nonce": nonce,
      "x-bridge-signature": signature
    });
    const response = PublisherStatusResponseSchema.parse(value);
    const activatedAt = response.active?.activatedAt;
    return {
      ok: true,
      checkedAt: new Date().toISOString(),
      ...(response.vaultId ? { vaultId: response.vaultId } : {}),
      ...(typeof response.active?.generation === "number" ? { generation: response.active.generation } : {}),
      ...(response.active?.snapshotId ? { snapshotId: response.active.snapshotId } : {}),
      ...(typeof activatedAt === "number" ? { freshnessSeconds: Math.max(0, timestamp - activatedAt) } : {})
    };
  }

  private async request(url: URL, method: string, body?: string, headers: Record<string, string> = {}): Promise<unknown> {
    const request: PublisherRequest = {
      url,
      method,
      headers: { ...headers, ...(body === undefined ? {} : { "content-type": "application/json" }) },
      ...(body === undefined ? {} : { body })
    };
    const response = await this.transport.request(request);
    if (Buffer.byteLength(response.body, "utf8") > RESPONSE_LIMIT) throw new Error("publisher_response_too_large");
    let value: unknown;
    try {
      value = response.body ? JSON.parse(response.body) as unknown : {};
    } catch {
      throw new Error("publisher_response_invalid");
    }
    if (response.statusCode < 200 || response.statusCode >= 300) throw new Error(`publisher_request_failed_${response.statusCode}`);
    return value;
  }
}
