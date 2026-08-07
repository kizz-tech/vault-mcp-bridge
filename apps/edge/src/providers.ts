import { randomBytes } from "node:crypto";
import { OpaqueIdSchema, type SecretReference } from "@vault-mcp-bridge/contracts";
import { randomOpaque } from "./crypto.js";

export type ProvisionTunnelInput = {
  installationId: string;
  vaultId: string;
  ownerId: string;
  /** PKCS#10 CSR generated on the owner's Mac. The TLS private key never
   * crosses the desktop boundary. Managed providers may require this field;
   * deterministic development providers deliberately ignore it. */
  publisherCsr?: string;
};

export type ProvisionedTunnel = {
  providerResourceId: string;
  mcpResourceUrl: string;
  publisherUrl: string;
  mcpHost: string;
  publisherHost: string;
  tunnelCredential: SecretReference;
  publisherMtlsCredential: SecretReference;
  /** Shared edge↔server attestation material, never reused as client mTLS. */
  publisherEdgeAttestation: SecretReference;
  /** Distinct credential used only by the MCP data-plane worker when it asks
   * the edge to introspect an access token. It is never reused for publisher
   * attestation or client mTLS. */
  mcpEdgeAttestation: SecretReference;
};

/** Secret storage is deliberately separate from the provider and endpoint API. */
export interface CredentialVault {
  put(reference: SecretReference, value: string): Promise<void>;
  get(reference: SecretReference): Promise<string | null>;
  revoke(reference: SecretReference): Promise<void>;
}

export class MemoryCredentialVault implements CredentialVault {
  private readonly values = new Map<string, string>();

  async put(reference: SecretReference, value: string): Promise<void> {
    this.values.set(reference.id, value);
  }

  async get(reference: SecretReference): Promise<string | null> {
    return this.values.get(reference.id) ?? null;
  }

  async revoke(reference: SecretReference): Promise<void> {
    this.values.delete(reference.id);
  }

  /** Test-only visibility into the reference store; it never returns values. */
  has(reference: SecretReference): boolean {
    return this.values.has(reference.id);
  }
}

export interface TunnelProvider {
  provision(input: ProvisionTunnelInput): Promise<ProvisionedTunnel>;
  rotate(input: ProvisionTunnelInput, previous: ProvisionedTunnel): Promise<ProvisionedTunnel>;
  revoke(input: ProvisionTunnelInput, current: ProvisionedTunnel): Promise<void>;
}

export type DeterministicTunnelProviderOptions = {
  /** Public control-plane origin; HTTPS is required outside tests. */
  origin: string;
  credentials?: CredentialVault;
  allowHttp?: boolean;
  now?: () => number;
};

const safeSlug = (installationId: string): string => {
  const value = installationId.replace(/[^A-Za-z0-9-]/gu, "-").toLowerCase();
  return value.slice(0, 48).replace(/^-+|-+$/gu, "") || "installation";
};

const makeReference = (provider: SecretReference["provider"], prefix: string): SecretReference => ({
  provider,
  id: `${prefix}_${randomBytes(18).toString("hex")}`,
});

/**
 * Deterministic local provider used for tests and self-hosted development.
 * It models the important production boundary: only opaque secret references
 * leave the provider, while secret material is kept in CredentialVault.
 */
export class DeterministicTunnelProvider implements TunnelProvider {
  readonly credentials: CredentialVault;
  private readonly origin: URL;
  private readonly allowHttp: boolean;
  private readonly now: () => number;

  constructor(options: DeterministicTunnelProviderOptions) {
    this.origin = new URL(options.origin);
    this.allowHttp = options.allowHttp ?? false;
    if (this.origin.protocol !== "https:" && !this.allowHttp) throw new Error("edge origin must use HTTPS");
    this.credentials = options.credentials ?? new MemoryCredentialVault();
    this.now = options.now ?? Date.now;
  }

  async provision(input: ProvisionTunnelInput): Promise<ProvisionedTunnel> {
    OpaqueIdSchema.parse(input.installationId);
    OpaqueIdSchema.parse(input.vaultId);
    if (!input.ownerId || input.ownerId.length > 256) throw new Error("owner id is invalid");
    return this.create(input.installationId);
  }

  async rotate(input: ProvisionTunnelInput, previous: ProvisionedTunnel): Promise<ProvisionedTunnel> {
    await this.credentials.revoke(previous.tunnelCredential);
    await this.credentials.revoke(previous.publisherMtlsCredential);
    await this.credentials.revoke(previous.publisherEdgeAttestation);
    if (previous.mcpEdgeAttestation) await this.credentials.revoke(previous.mcpEdgeAttestation);
    return this.create(input.installationId);
  }

  async revoke(_input: ProvisionTunnelInput, current: ProvisionedTunnel): Promise<void> {
    await this.credentials.revoke(current.tunnelCredential);
    await this.credentials.revoke(current.publisherMtlsCredential);
    await this.credentials.revoke(current.publisherEdgeAttestation);
    if (current.mcpEdgeAttestation) await this.credentials.revoke(current.mcpEdgeAttestation);
  }

  private async create(installationId: string): Promise<ProvisionedTunnel> {
    const slug = safeSlug(installationId);
    const base = this.origin.hostname;
    const mcpHost = `mcp-${slug}.${base}`;
    const publisherHost = `publish-${slug}.${base}`;
    const mcpResourceUrl = new URL("/mcp", `${this.origin.protocol}//${mcpHost}`).toString();
    const publisherUrl = new URL("/", `${this.origin.protocol}//${publisherHost}`).toString();
    const tunnelCredential = makeReference("remote-file", "tunnel");
    const publisherMtlsCredential = makeReference("remote-file", "publisher-mtls");
    const publisherEdgeAttestation = makeReference("remote-file", "publisher-edge-attestation");
    const mcpEdgeAttestation = makeReference("remote-file", "mcp-edge-attestation");
    await this.credentials.put(tunnelCredential, `tunnel-${randomOpaque(32)}-${this.now()}`);
    await this.credentials.put(publisherMtlsCredential, `mtls-${randomOpaque(48)}-${this.now()}`);
    await this.credentials.put(publisherEdgeAttestation, `edge-attestation-${randomOpaque(48)}-${this.now()}`);
    await this.credentials.put(mcpEdgeAttestation, `mcp-edge-attestation-${randomOpaque(48)}-${this.now()}`);
    return {
      providerResourceId: `local_${randomBytes(18).toString("hex")}`,
      mcpResourceUrl,
      publisherUrl,
      mcpHost,
      publisherHost,
      tunnelCredential,
      publisherMtlsCredential,
      publisherEdgeAttestation,
      mcpEdgeAttestation,
    };
  }
}

/**
 * Credential-gated adapter for a real managed provider. The interface is
 * intentionally explicit so adding a Cloudflare (or another provider) client
 * cannot accidentally leak an account-wide token into the desktop app.
 */
export class ExternalTunnelProvider implements TunnelProvider {
  constructor(private readonly providerName: string, private readonly accountCredentialReference?: string) {}

  private unavailable(): never {
    if (!this.accountCredentialReference) {
      throw new Error(`EDGE_PROVIDER_NOT_CONFIGURED:${this.providerName}`);
    }
    throw new Error(`EDGE_PROVIDER_ADAPTER_NOT_IMPLEMENTED:${this.providerName}`);
  }

  async provision(_input: ProvisionTunnelInput): Promise<ProvisionedTunnel> {
    return this.unavailable();
  }

  async rotate(_input: ProvisionTunnelInput, _previous: ProvisionedTunnel): Promise<ProvisionedTunnel> {
    return this.unavailable();
  }

  async revoke(_input: ProvisionTunnelInput, _current: ProvisionedTunnel): Promise<void> {
    return this.unavailable();
  }
}
