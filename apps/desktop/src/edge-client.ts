import { createHash } from "node:crypto";
import { EndpointBundleSchema, OpaqueIdSchema } from "@vault-mcp-bridge/contracts";

import type { EdgeInstallation } from "@vault-mcp-bridge/orchestrator";
import type { OwnerTokenProvider } from "./oauth-client.js";
import type { ProductConfig } from "./product-config.js";

export type CredentialKind = "tunnel" | "publisher-mtls" | "publisher-edge-attestation" | "mcp-edge-attestation";

export interface CredentialLeaseResponse {
  readonly leaseId: string;
  readonly serverPublicKey: string;
  readonly expiresAt: string;
  readonly algorithm: "X25519-HKDF-SHA256-AES-256-GCM";
}

export interface MaterializedCredential {
  readonly leaseId: string;
  readonly kind: CredentialKind;
  readonly ciphertext: string;
  readonly nonce: string;
  readonly tag: string;
  readonly serverPublicKey: string;
  readonly algorithm: "X25519-HKDF-SHA256-AES-256-GCM";
}

export interface EdgeCredentialPort {
  createCredentialLease(installationId: string, kind: CredentialKind, clientPublicKey: string): Promise<CredentialLeaseResponse>;
  redeemCredentialLease(leaseId: string): Promise<MaterializedCredential>;
}

export interface EdgeControlPort extends EdgeCredentialPort {
  createInstallation(input: CreateInstallationInput): Promise<EdgeInstallation>;
  getInstallation(installationId: string): Promise<EdgeInstallation | undefined>;
  revokeInstallation(installationId: string, idempotencyKey?: string): Promise<void>;
}

export interface CreateInstallationInput {
  readonly installationId: string;
  readonly vaultId: string;
  readonly idempotencyKey: string;
  readonly publisherCsr?: string;
}

export interface FetchLike {
  (input: string | URL, init?: RequestInit): Promise<Response>;
}

class EdgeRequestError extends Error {
  public constructor(readonly status: number, readonly code: string) {
    super(code);
    this.name = "EdgeRequestError";
  }
}

const RESPONSE_LIMIT = 2 * 1024 * 1024;
const ALGORITHM = "X25519-HKDF-SHA256-AES-256-GCM" as const;

function edgeOrigin(value: string, allowLoopback: boolean): URL {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error("edge_origin_invalid");
  }
  const loopback = ["localhost", "127.0.0.1", "::1"].includes(parsed.hostname.toLowerCase());
  if (parsed.protocol !== "https:" && !(allowLoopback && parsed.protocol === "http:" && loopback)) throw new Error("edge_https_required");
  if (parsed.username || parsed.password || parsed.pathname !== "/" || parsed.search || parsed.hash) throw new Error("edge_origin_invalid");
  return parsed;
}

function objectValue(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("edge_response_invalid");
  return value as Record<string, unknown>;
}

function stringField(value: unknown, field: string, max = 512): string {
  if (typeof value !== "string" || value.length === 0 || value.length > max) throw new Error(`edge_${field}_invalid`);
  return value;
}

async function readJson(response: Response): Promise<unknown> {
  const length = Number(response.headers.get("content-length") ?? 0);
  if (Number.isFinite(length) && length > RESPONSE_LIMIT) throw new Error("edge_response_too_large");
  const body = await response.arrayBuffer();
  if (body.byteLength > RESPONSE_LIMIT) throw new Error("edge_response_too_large");
  try {
    return body.byteLength ? JSON.parse(new TextDecoder().decode(body)) as unknown : {};
  } catch {
    throw new Error("edge_response_invalid");
  }
}

function endpointInstallation(value: unknown): EdgeInstallation {
  const record = objectValue(value);
  const endpointBundle = EndpointBundleSchema.parse(record.endpointBundle);
  const installationId = stringField(record.installationId, "installation_id");
  OpaqueIdSchema.parse(installationId);
  const provider = stringField(record.providerResourceId ?? record.provider ?? "managed-edge", "provider", 256);
  return {
    installationRef: installationId,
    endpointUrl: endpointBundle.mcpResourceUrl,
    oauthIssuerUrl: endpointBundle.oauthIssuer,
    provider,
    endpointBundle
  };
}

function parseLease(value: unknown): CredentialLeaseResponse {
  const record = objectValue(value);
  if (record.algorithm !== ALGORITHM) throw new Error("edge_lease_algorithm_invalid");
  return {
    leaseId: stringField(record.leaseId, "lease_id", 256),
    serverPublicKey: stringField(record.serverPublicKey, "server_public_key", 1024),
    expiresAt: stringField(record.expiresAt, "expires_at", 128),
    algorithm: ALGORITHM
  };
}

function parseMaterialized(value: unknown): MaterializedCredential {
  const record = objectValue(value);
  if (record.algorithm !== ALGORITHM) throw new Error("edge_lease_algorithm_invalid");
  const kind = record.kind;
  if (kind !== "tunnel" && kind !== "publisher-mtls" && kind !== "publisher-edge-attestation" && kind !== "mcp-edge-attestation") throw new Error("edge_lease_kind_invalid");
  return {
    leaseId: stringField(record.leaseId, "lease_id", 256),
    kind,
    ciphertext: stringField(record.ciphertext, "ciphertext", RESPONSE_LIMIT),
    nonce: stringField(record.nonce, "nonce", 128),
    tag: stringField(record.tag, "tag", 128),
    serverPublicKey: stringField(record.serverPublicKey, "server_public_key", 1024),
    algorithm: ALGORITHM
  };
}

export class EdgeControlClient implements EdgeControlPort {
  private readonly origin: URL;
  private readonly fetcher: FetchLike;

  public constructor(
    private readonly config: ProductConfig,
    private readonly tokenProvider: OwnerTokenProvider,
    options: { fetch?: FetchLike; allowLoopback?: boolean } = {}
  ) {
    this.origin = edgeOrigin(config.edgeOrigin, options.allowLoopback === true || config.development === true);
    this.fetcher = options.fetch ?? ((input, init) => fetch(input, init));
  }

  async createInstallation(input: CreateInstallationInput): Promise<EdgeInstallation> {
    OpaqueIdSchema.parse(input.vaultId);
    OpaqueIdSchema.parse(input.installationId);
    const idempotencyKey = edgeIdempotencyKey(input.idempotencyKey);
    if (input.publisherCsr !== undefined && (input.publisherCsr.length === 0 || input.publisherCsr.length > 64 * 1024 || !/^-----BEGIN CERTIFICATE REQUEST-----[\s\S]+-----END CERTIFICATE REQUEST-----\s*$/u.test(input.publisherCsr))) throw new Error("edge_publisher_csr_invalid");
    const value = await this.request("/v1/installations", "POST", { vaultId: input.vaultId, installationId: input.installationId, ...(input.publisherCsr ? { publisherCsr: input.publisherCsr } : {}) }, idempotencyKey);
    const record = objectValue(value).installation;
    const result = endpointInstallation(record);
    if (result.installationRef !== input.installationId) throw new Error("edge_installation_id_mismatch");
    return result;
  }

  async getInstallation(installationId: string): Promise<EdgeInstallation | undefined> {
    try {
      const value = await this.request(`/v1/installations/${encodeURIComponent(installationId)}`, "GET");
      return endpointInstallation(objectValue(value).installation);
    } catch {
      return undefined;
    }
  }

  async revokeInstallation(installationId: string, idempotencyKey?: string): Promise<void> {
    OpaqueIdSchema.parse(installationId);
    try {
      await this.request(
        `/v1/installations/${encodeURIComponent(installationId)}/revoke`,
        "POST",
        undefined,
        idempotencyKey === undefined ? undefined : edgeIdempotencyKey(idempotencyKey)
      );
    } catch (error) {
      // A missing installation is already revoked from this client's point of
      // view.  Do not treat other errors as success: the caller must retain
      // its receipt until the edge has acknowledged the kill switch.
      if (error instanceof EdgeRequestError && error.status === 404 && error.code === "installation_not_found") return;
      throw error;
    }
  }

  async createCredentialLease(installationId: string, kind: CredentialKind, clientPublicKey: string): Promise<CredentialLeaseResponse> {
    stringField(installationId, "installation_id", 256);
    if (!["tunnel", "publisher-mtls", "publisher-edge-attestation", "mcp-edge-attestation"].includes(kind)) throw new Error("edge_lease_kind_invalid");
    return parseLease(await this.request(`/v1/installations/${encodeURIComponent(installationId)}/credentials/lease`, "POST", { kind, client_public_key: clientPublicKey }));
  }

  async redeemCredentialLease(leaseId: string): Promise<MaterializedCredential> {
    return parseMaterialized(await this.request(`/v1/credential-leases/${encodeURIComponent(leaseId)}/redeem`, "POST"));
  }

  private async request(path: string, method: string, body?: unknown, idempotencyKey?: string): Promise<unknown> {
    const token = await this.tokenProvider.getAccessToken();
    if (!token) throw new Error("owner_auth_required");
    const response = await this.fetcher(new URL(path, this.origin), {
      method,
      redirect: "error",
      headers: { accept: "application/json", authorization: `Bearer ${token}`, ...(body === undefined ? {} : { "content-type": "application/json" }), ...(idempotencyKey ? { "Idempotency-Key": idempotencyKey } : {}) },
      ...(body === undefined ? {} : { body: JSON.stringify(body) })
    });
    const value = await readJson(response);
    if (!response.ok) {
      const record = value && typeof value === "object" ? value as Record<string, unknown> : {};
      const error = typeof record.error === "string" ? record.error : "edge_request_failed";
      throw new EdgeRequestError(response.status, error.slice(0, 128));
    }
    return value;
  }
}

export { ALGORITHM };

function edgeIdempotencyKey(value: string): string {
  if (value.length < 16 || value.length > 512 || /[\0\r\n]/u.test(value)) throw new Error("edge_idempotency_key_invalid");
  return `idemp_${createHash("sha256").update(value, "utf8").digest("base64url")}`;
}
