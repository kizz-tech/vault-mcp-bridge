import { createHash, randomBytes } from "node:crypto";

import type { SecretReference } from "@vault-mcp-bridge/contracts";

import { createMcpWorkerSource, createPublisherWorkerSource } from "./cloudflare-worker.js";
import type { CredentialVault, ProvisionedTunnel, ProvisionTunnelInput, TunnelProvider } from "./providers.js";

const DEFAULT_API = "https://api.cloudflare.com/client/v4";
const MAX_RESPONSE_BYTES = 2 * 1024 * 1024;
const DEFAULT_TIMEOUT_MS = 15_000;
const HOST_RE = /^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/u;
const ID_RE = /^[A-Za-z0-9_-]{3,128}$/u;

type JsonRecord = Record<string, unknown>;

type ProviderReceipt = {
  version: 1 | 2;
  tunnelId: string;
  dnsRecordIds: string[];
  certificateId: string;
  publisherHost: string;
  workerScript: string;
  workerRouteId: string;
  mcpWorkerScript?: string;
  mcpWorkerRouteId?: string;
};

type ProviderJournal = {
  version: 1 | 2;
  installationId: string;
  status: "provisioning" | "ready";
  receipt: Partial<ProviderReceipt> & { dnsRecordIds: string[] };
  associationsChanged: boolean;
  associationPending: boolean;
  tunnelCredential: SecretReference;
  publisherMtlsCredential: SecretReference;
  publisherEdgeAttestation: SecretReference;
  mcpEdgeAttestation?: SecretReference;
};

export type CloudflareTunnelProviderOptions = {
  accountId: string;
  zoneId: string;
  zoneName: string;
  apiToken: string;
  credentials: CredentialVault;
  /** Hostname association updates are replace-all. Requiring an explicitly
   * dedicated zone prevents this controller from mutating unrelated mTLS
   * policy in a shared zone by accident. */
  dedicatedZone: true;
  apiBaseUrl?: string;
  /** HTTPS edge control-plane origin. The provider appends the installation
   * introspection path; credentials and query/fragment components are rejected. */
  introspectionBaseUrl: string;
  fetcher?: typeof fetch;
  timeoutMs?: number;
  certificateValidityDays?: number;
  maxPublisherBodyBytes?: number;
};

export class CloudflareApiError extends Error {
  constructor(readonly operation: string, readonly status?: number, options?: ErrorOptions) {
    super(`cloudflare operation failed: ${operation}`, options);
    this.name = "CloudflareApiError";
  }
}

/**
 * Cloudflare replaces the complete hostname-association set on every PUT.
 * Keep those read/modify/write transactions behind one in-process queue. The
 * edge service is intentionally single-writer, so this closes the lost-update
 * window between installations handled by this process. It cannot coordinate
 * a second edge process or an out-of-band Cloudflare administrator.
 */
const processMutationChains = new Map<string, Promise<void>>();

async function withProcessSingleWriter<T>(key: string, operation: () => Promise<T>): Promise<T> {
  const previous = processMutationChains.get(key) ?? Promise.resolve();
  let release!: () => void;
  const gate = new Promise<void>((resolve) => { release = resolve; });
  const queued = previous.then(() => gate);
  processMutationChains.set(key, queued);
  await previous;
  try {
    return await operation();
  } finally {
    release();
    if (processMutationChains.get(key) === queued) processMutationChains.delete(key);
  }
}

function object(value: unknown, operation: string): JsonRecord {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new CloudflareApiError(operation);
  return value as JsonRecord;
}

function stringField(value: JsonRecord, field: string, operation: string): string {
  const candidate = value[field];
  if (typeof candidate !== "string" || candidate.length === 0 || candidate.length > 64 * 1024) throw new CloudflareApiError(operation);
  return candidate;
}

function safeId(value: string, field: string): string {
  if (!ID_RE.test(value)) throw new Error(`${field} is invalid`);
  return value;
}

function safeHost(value: string, field: string): string {
  const host = value.toLowerCase().replace(/\.$/u, "");
  if (!HOST_RE.test(host)) throw new Error(`${field} is invalid`);
  return host;
}

function safeSlug(installationId: string): string {
  const readable = installationId.toLowerCase().replace(/[^a-z0-9-]/gu, "-").replace(/^-+|-+$/gu, "").slice(0, 28) || "installation";
  const suffix = createHash("sha256").update(installationId, "utf8").digest("hex").slice(0, 10);
  return `${readable}-${suffix}`;
}

function secretReference(prefix: string): SecretReference {
  return { provider: "remote-file", id: `${prefix}_${randomBytes(18).toString("base64url")}` };
}

function encodeReceipt(value: ProviderReceipt): string {
  return `cf1_${Buffer.from(JSON.stringify(value), "utf8").toString("base64url")}`;
}

function decodeReceipt(value: string): ProviderReceipt {
  if (!value.startsWith("cf1_") || value.length > 64 * 1024) throw new Error("cloudflare provider receipt is invalid");
  let parsed: unknown;
  try { parsed = JSON.parse(Buffer.from(value.slice(4), "base64url").toString("utf8")) as unknown; } catch { throw new Error("cloudflare provider receipt is invalid"); }
  const record = object(parsed, "decode-receipt");
  const dnsRecordIds = record.dnsRecordIds;
  if ((record.version !== 1 && record.version !== 2) || !Array.isArray(dnsRecordIds) || dnsRecordIds.some((id) => typeof id !== "string" || !ID_RE.test(id))) {
    throw new Error("cloudflare provider receipt is invalid");
  }
  const decodeOptionalId = (field: string): string | undefined => {
    const candidate = record[field];
    if (candidate === undefined) return undefined;
    return safeId(stringField(record, field, "decode-receipt"), field);
  };
  const mcpWorkerScript = decodeOptionalId("mcpWorkerScript");
  const mcpWorkerRouteId = decodeOptionalId("mcpWorkerRouteId");
  if (record.version === 2 && (!mcpWorkerScript || !mcpWorkerRouteId)) throw new Error("cloudflare provider receipt is invalid");
  return {
    version: record.version,
    tunnelId: safeId(stringField(record, "tunnelId", "decode-receipt"), "tunnel id"),
    dnsRecordIds: [...dnsRecordIds] as string[],
    certificateId: safeId(stringField(record, "certificateId", "decode-receipt"), "certificate id"),
    publisherHost: safeHost(stringField(record, "publisherHost", "decode-receipt"), "publisher host"),
    workerScript: safeId(stringField(record, "workerScript", "decode-receipt"), "worker script"),
    workerRouteId: safeId(stringField(record, "workerRouteId", "decode-receipt"), "worker route id"),
    ...(mcpWorkerScript !== undefined ? { mcpWorkerScript } : {}),
    ...(mcpWorkerRouteId !== undefined ? { mcpWorkerRouteId } : {}),
  };
}

function journalReference(installationId: string): SecretReference {
  return { provider: "remote-file", id: `cloudflare_journal_${safeSlug(installationId)}` };
}

function encodeJournal(value: ProviderJournal): string {
  return `cfj1_${Buffer.from(JSON.stringify(value), "utf8").toString("base64url")}`;
}

function decodeJournal(value: string): ProviderJournal {
  if (!value.startsWith("cfj1_") || value.length > 64 * 1024) throw new Error("cloudflare provider journal is invalid");
  let parsed: unknown;
  try { parsed = JSON.parse(Buffer.from(value.slice(5), "base64url").toString("utf8")) as unknown; } catch { throw new Error("cloudflare provider journal is invalid"); }
  const record = object(parsed, "decode-journal");
  const receipt = object(record.receipt, "decode-journal");
  const dnsRecordIds = receipt.dnsRecordIds;
  if ((record.version !== 1 && record.version !== 2) || (record.status !== "provisioning" && record.status !== "ready") || typeof record.installationId !== "string" || record.installationId.length === 0 ||
      typeof record.associationsChanged !== "boolean" || typeof record.associationPending !== "boolean" ||
      (receipt.version !== 1 && receipt.version !== 2) || !Array.isArray(dnsRecordIds) || dnsRecordIds.some((id) => typeof id !== "string" || !ID_RE.test(id))) {
    throw new Error("cloudflare provider journal is invalid");
  }
  const decodeOptionalId = (field: string): string | undefined => {
    const value = receipt[field];
    if (value === undefined) return undefined;
    return safeId(stringField(receipt, field, "decode-journal"), field);
  };
  const tunnelId = decodeOptionalId("tunnelId");
  const certificateId = decodeOptionalId("certificateId");
  const workerScript = decodeOptionalId("workerScript");
  const workerRouteId = decodeOptionalId("workerRouteId");
  const mcpWorkerScript = decodeOptionalId("mcpWorkerScript");
  const mcpWorkerRouteId = decodeOptionalId("mcpWorkerRouteId");
  // A provisioning journal is intentionally checkpointed after each remote
  // mutation.  Its V2 receipt is therefore allowed to be partial until the
  // MCP route has been created; a ready V2 journal must be complete.
  if (record.version === 2 && record.status === "ready" && (!mcpWorkerScript || !mcpWorkerRouteId)) throw new Error("cloudflare provider journal is invalid");
  const publisherHost = receipt.publisherHost;
  if (publisherHost !== undefined && typeof publisherHost !== "string") throw new Error("cloudflare provider journal is invalid");
  const decodeReference = (field: string): SecretReference => {
    const candidate = object(record[field], "decode-journal");
    const provider = candidate.provider;
    const id = candidate.id;
    if (provider !== "remote-file" ||
        typeof id !== "string" || id.length === 0 || id.length > 512) {
      throw new Error("cloudflare provider journal is invalid");
    }
    return { provider, id };
  };
  const mcpEdgeAttestation = record.mcpEdgeAttestation === undefined ? undefined : decodeReference("mcpEdgeAttestation");
  if (record.version === 2 && !mcpEdgeAttestation) throw new Error("cloudflare provider journal is invalid");
  return {
    version: record.version,
    installationId: record.installationId,
    status: record.status,
    receipt: {
      version: receipt.version,
      ...(tunnelId !== undefined ? { tunnelId } : {}),
      dnsRecordIds: [...dnsRecordIds] as string[],
      ...(publisherHost !== undefined ? { publisherHost: safeHost(publisherHost, "publisher host") } : {}),
      ...(certificateId !== undefined ? { certificateId } : {}),
      ...(workerScript !== undefined ? { workerScript } : {}),
      ...(workerRouteId !== undefined ? { workerRouteId } : {}),
      ...(mcpWorkerScript !== undefined ? { mcpWorkerScript } : {}),
      ...(mcpWorkerRouteId !== undefined ? { mcpWorkerRouteId } : {}),
    },
    associationsChanged: record.associationsChanged,
    associationPending: record.associationPending,
    tunnelCredential: decodeReference("tunnelCredential"),
    publisherMtlsCredential: decodeReference("publisherMtlsCredential"),
    publisherEdgeAttestation: decodeReference("publisherEdgeAttestation"),
    ...(mcpEdgeAttestation !== undefined ? { mcpEdgeAttestation } : {}),
  };
}

class CloudflareApiClient {
  private readonly base: URL;
  private readonly timeoutMs: number;

  constructor(
    private readonly apiToken: string,
    private readonly fetcher: typeof fetch,
    baseUrl: string,
    timeoutMs: number,
  ) {
    if (apiToken.length < 20 || apiToken.length > 4096 || /\s/u.test(apiToken)) throw new Error("Cloudflare API token is invalid");
    this.base = new URL(baseUrl.endsWith("/") ? baseUrl : `${baseUrl}/`);
    if (this.base.protocol !== "https:" && !["127.0.0.1", "localhost", "::1"].includes(this.base.hostname)) throw new Error("Cloudflare API must use HTTPS");
    this.timeoutMs = timeoutMs;
  }

  async request(path: string, operation: string, init: RequestInit = {}): Promise<unknown> {
    if (path.startsWith("/") || path.includes("..")) throw new CloudflareApiError(operation);
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const headers = new Headers(init.headers);
      headers.set("authorization", `Bearer ${this.apiToken}`);
      headers.set("accept", "application/json");
      if (init.body && !(init.body instanceof FormData) && !headers.has("content-type")) headers.set("content-type", "application/json");
      const response = await this.fetcher(new URL(path, this.base), { ...init, headers, redirect: "error", signal: controller.signal });
      const announced = Number(response.headers.get("content-length") ?? "0");
      if (Number.isFinite(announced) && announced > MAX_RESPONSE_BYTES) throw new CloudflareApiError(operation, response.status);
      const body = await response.text();
      if (Buffer.byteLength(body, "utf8") > MAX_RESPONSE_BYTES) throw new CloudflareApiError(operation, response.status);
      if (!response.ok) throw new CloudflareApiError(operation, response.status);
      if (!body) return null;
      let envelope: unknown;
      try { envelope = JSON.parse(body) as unknown; } catch { throw new CloudflareApiError(operation, response.status); }
      const record = object(envelope, operation);
      if (record.success !== true || !("result" in record)) throw new CloudflareApiError(operation, response.status);
      return record.result;
    } catch (error) {
      if (error instanceof CloudflareApiError) throw error;
      throw new CloudflareApiError(operation);
    } finally {
      clearTimeout(timer);
    }
  }
}

/** Concrete production provider. Cloudflare account authority never crosses
 * this edge process; desktop receives only one-use leases for installation
 * scoped tunnel/certificate material. */
export class CloudflareTunnelProvider implements TunnelProvider {
  private readonly accountId: string;
  private readonly zoneId: string;
  private readonly zoneName: string;
  private readonly credentials: CredentialVault;
  private readonly api: CloudflareApiClient;
  private readonly associationMutationKey: string;
  private readonly introspectionBaseUrl: URL;
  private readonly certificateValidityDays: number;
  private readonly maxPublisherBodyBytes: number;

  constructor(options: CloudflareTunnelProviderOptions) {
    if (options.dedicatedZone !== true) throw new Error("Cloudflare provider requires an explicitly dedicated zone");
    this.accountId = safeId(options.accountId, "Cloudflare account id");
    this.zoneId = safeId(options.zoneId, "Cloudflare zone id");
    this.zoneName = safeHost(options.zoneName, "Cloudflare zone name");
    this.credentials = options.credentials;
    let introspectionBaseUrl: URL;
    try { introspectionBaseUrl = new URL(options.introspectionBaseUrl); } catch { throw new Error("Cloudflare introspection base URL is invalid"); }
    if (introspectionBaseUrl.protocol !== "https:" || introspectionBaseUrl.username || introspectionBaseUrl.password || introspectionBaseUrl.search || introspectionBaseUrl.hash || introspectionBaseUrl.pathname !== "/") {
      throw new Error("Cloudflare introspection base URL must be an HTTPS origin");
    }
    this.introspectionBaseUrl = introspectionBaseUrl;
    const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1000 || timeoutMs > 60_000) throw new Error("Cloudflare timeout is invalid");
    const apiBaseUrl = options.apiBaseUrl ?? DEFAULT_API;
    this.api = new CloudflareApiClient(options.apiToken, options.fetcher ?? fetch, apiBaseUrl, timeoutMs);
    this.associationMutationKey = `cloudflare-mtls:${new URL(apiBaseUrl.endsWith("/") ? apiBaseUrl : `${apiBaseUrl}/`).toString()}:${this.accountId}:${this.zoneId}`;
    this.certificateValidityDays = options.certificateValidityDays ?? 365;
    if (!Number.isSafeInteger(this.certificateValidityDays) || this.certificateValidityDays < 1 || this.certificateValidityDays > 10 * 365) throw new Error("Cloudflare certificate validity is invalid");
    this.maxPublisherBodyBytes = options.maxPublisherBodyBytes ?? 3 * 1024 * 1024;
  }

  async provision(input: ProvisionTunnelInput): Promise<ProvisionedTunnel> {
    return withProcessSingleWriter(this.installationMutationKey(input.installationId), () => this.provisionOnce(input));
  }

  private async provisionOnce(input: ProvisionTunnelInput): Promise<ProvisionedTunnel> {
    if (!input.publisherCsr) throw new Error("Cloudflare publisher CSR is required");
    const slug = safeSlug(input.installationId);
    const mcpHost = safeHost(`mcp-${slug}.${this.zoneName}`, "MCP host");
    const publisherHost = safeHost(`publish-${slug}.${this.zoneName}`, "publisher host");
    const hiddenOriginHost = safeHost(`origin-${slug}.${this.zoneName}`, "publisher origin host");
    const workerScript = safeId(`vmb-pub-${slug}`.slice(0, 62), "Worker script");
    const mcpWorkerScript = safeId(`vmb-mcp-${slug}`.slice(0, 62), "MCP Worker script");
    const tunnelCredential = secretReference("tunnel");
    const publisherMtlsCredential = secretReference("publisher_mtls");
    const publisherEdgeAttestation = secretReference("publisher_edge_attestation");
    const mcpEdgeAttestation = secretReference("mcp_edge_attestation");
    const receipt: Partial<ProviderReceipt> & { dnsRecordIds: string[] } = { version: 2, dnsRecordIds: [], publisherHost, workerScript, mcpWorkerScript };
    const journalRef = journalReference(input.installationId);
    const journal: ProviderJournal = {
      version: 2,
      installationId: input.installationId,
      status: "provisioning",
      receipt,
      associationsChanged: false,
      associationPending: false,
      tunnelCredential,
      publisherMtlsCredential,
      publisherEdgeAttestation,
      mcpEdgeAttestation,
    };
    let associationsChanged = false;
    let journalRecoveryPending = true;

    try {
      // A durable journal lets a retry clean up the last known receipt before
      // allocating another deterministic installation. It cannot close the
      // tiny window after a provider mutation succeeds and before its journal
      // checkpoint is flushed; no external API transaction spans both writes.
      const previousJournalValue = await this.credentials.get(journalRef);
      journalRecoveryPending = false;
      if (previousJournalValue) {
        journalRecoveryPending = true;
        const previousJournal = decodeJournal(previousJournalValue);
        if (previousJournal.installationId !== input.installationId) throw new Error("cloudflare provider journal installation mismatch");
        await this.reconcileJournal(previousJournal, journalRef);
        journalRecoveryPending = false;
      }
      const checkpoint = async (): Promise<void> => {
        await this.credentials.put(journalRef, encodeJournal(journal));
      };
      await checkpoint();

      const tunnel = object(await this.api.request(`accounts/${this.accountId}/cfd_tunnel`, "create-tunnel", {
        method: "POST", body: JSON.stringify({ name: `vault-bridge-${slug}`, config_src: "cloudflare" })
      }), "create-tunnel");
      receipt.tunnelId = safeId(stringField(tunnel, "id", "create-tunnel"), "tunnel id");
      await checkpoint();

      await this.api.request(`accounts/${this.accountId}/cfd_tunnel/${receipt.tunnelId}/configurations`, "configure-tunnel", {
        method: "PUT",
        body: JSON.stringify({ config: { ingress: [
          { hostname: mcpHost, service: "http://server:8787", originRequest: { httpHostHeader: mcpHost } },
          { hostname: hiddenOriginHost, service: "http://server:8787", originRequest: { httpHostHeader: publisherHost } },
          { service: "http_status:404" }
        ] } })
      });
      const tokenResult = await this.api.request(`accounts/${this.accountId}/cfd_tunnel/${receipt.tunnelId}/token`, "get-tunnel-token", { method: "GET" });
      const tunnelToken = typeof tokenResult === "string" ? tokenResult : stringField(object(tokenResult, "get-tunnel-token"), "token", "get-tunnel-token");
      if (tunnelToken.length < 32 || tunnelToken.length > 16 * 1024) throw new CloudflareApiError("get-tunnel-token");

      const cname = `${receipt.tunnelId}.cfargotunnel.com`;
      for (const hostname of [mcpHost, publisherHost, hiddenOriginHost]) {
        const dns = object(await this.api.request(`zones/${this.zoneId}/dns_records`, "create-dns", {
          method: "POST", body: JSON.stringify({ type: "CNAME", name: hostname, content: cname, proxied: true, ttl: 1, comment: `Vault Bridge ${input.installationId}` })
        }), "create-dns");
        receipt.dnsRecordIds.push(safeId(stringField(dns, "id", "create-dns"), "DNS record id"));
        await checkpoint();
      }

      const certificate = object(await this.api.request(`zones/${this.zoneId}/client_certificates`, "issue-client-certificate", {
        method: "POST", body: JSON.stringify({ csr: input.publisherCsr, validity_days: this.certificateValidityDays })
      }), "issue-client-certificate");
      receipt.certificateId = safeId(stringField(certificate, "id", "issue-client-certificate"), "certificate id");
      const certificatePem = stringField(certificate, "certificate", "issue-client-certificate");
      const certificateFingerprint = stringField(certificate, "fingerprint_sha256", "issue-client-certificate");
      if (!certificatePem.includes("BEGIN CERTIFICATE") || !/^[A-Fa-f0-9:]{32,128}$/u.test(certificateFingerprint)) throw new CloudflareApiError("issue-client-certificate");
      await checkpoint();

      journal.associationPending = true;
      await checkpoint();
      associationsChanged = await this.mutateAssociations((currentAssociations, associationsPath) => {
        if (currentAssociations.includes(publisherHost)) return Promise.resolve(false);
        return this.api.request(associationsPath, "update-mtls-associations", {
          method: "PUT",
          body: JSON.stringify({ hostnames: [...currentAssociations, publisherHost].sort() })
        }).then(() => true);
      });
      journal.associationsChanged = associationsChanged;
      journal.associationPending = false;
      await checkpoint();

      const edgeSecret = randomBytes(48).toString("base64url");
      const mcpSecret = randomBytes(48).toString("base64url");
      const publisherSource = createPublisherWorkerSource({ installationId: input.installationId, publisherHost, hiddenOriginHost, certificateFingerprint, maxBodyBytes: this.maxPublisherBodyBytes });
      await this.uploadWorker(workerScript, publisherSource, []);
      await this.api.request(`accounts/${this.accountId}/workers/scripts/${workerScript}/secrets`, "put-worker-secret", {
        method: "PUT", body: JSON.stringify({ name: "EDGE_ATTESTATION_SECRET", text: edgeSecret, type: "secret_text" })
      });
      const route = object(await this.api.request(`zones/${this.zoneId}/workers/routes`, "create-worker-route", {
        method: "POST", body: JSON.stringify({ pattern: `${publisherHost}/*`, script: workerScript })
      }), "create-worker-route");
      receipt.workerRouteId = safeId(stringField(route, "id", "create-worker-route"), "Worker route id");
      await checkpoint();

      // The MCP worker owns a separate secret and is the only public data
      // plane route.  The exact installation introspection URL is passed as
      // a plain-text binding, never embedded in a secret or shared with the
      // publisher worker.
      const mcpSource = createMcpWorkerSource({
        installationId: input.installationId,
        mcpHost,
        introspectionUrl: this.introspectionUrl(input.installationId),
        maxBodyBytes: this.maxPublisherBodyBytes,
      });
      await this.uploadWorker(mcpWorkerScript, mcpSource, [
        { name: "INTROSPECTION_URL", text: this.introspectionUrl(input.installationId) },
        { name: "INSTALLATION_ID", text: input.installationId },
      ]);
      await this.api.request(`accounts/${this.accountId}/workers/scripts/${mcpWorkerScript}/secrets`, "put-mcp-worker-secret", {
        method: "PUT", body: JSON.stringify({ name: "MCP_EDGE_ATTESTATION_SECRET", text: mcpSecret, type: "secret_text" })
      });
      const mcpRoute = object(await this.api.request(`zones/${this.zoneId}/workers/routes`, "create-mcp-worker-route", {
        method: "POST", body: JSON.stringify({ pattern: `${mcpHost}/*`, script: mcpWorkerScript })
      }), "create-mcp-worker-route");
      receipt.mcpWorkerRouteId = safeId(stringField(mcpRoute, "id", "create-mcp-worker-route"), "MCP Worker route id");
      await checkpoint();

      await this.credentials.put(tunnelCredential, tunnelToken);
      await this.credentials.put(publisherMtlsCredential, JSON.stringify({ certificate: certificatePem, fingerprint: certificateFingerprint, certificateId: receipt.certificateId }));
      await this.credentials.put(publisherEdgeAttestation, edgeSecret);
      await this.credentials.put(mcpEdgeAttestation, mcpSecret);
      journal.status = "ready";
      await checkpoint();
      const complete = receipt as ProviderReceipt;
      return {
        providerResourceId: encodeReceipt(complete),
        mcpResourceUrl: `https://${mcpHost}/mcp`,
        publisherUrl: `https://${publisherHost}/`,
        mcpHost,
        publisherHost,
        tunnelCredential,
        publisherMtlsCredential,
        publisherEdgeAttestation,
        mcpEdgeAttestation,
      };
    } catch (error) {
      let rollbackError: unknown;
      try {
        await this.cleanup(receipt, associationsChanged || journal.associationPending);
        // Keep local references live until every external resource has been
        // removed. If either operation fails, a later retry still has both the
        // provider receipt and local credential references to work from.
        await this.revokeCredentials([tunnelCredential, publisherMtlsCredential, publisherEdgeAttestation, mcpEdgeAttestation]);
        if (!journalRecoveryPending) await this.credentials.revoke(journalRef);
      } catch (cleanupError) {
        rollbackError = cleanupError;
      }
      if (rollbackError) {
        const original = error instanceof Error ? error : new Error("cloudflare provisioning failed", { cause: error });
        throw new CloudflareApiError("provision-installation", error instanceof CloudflareApiError ? error.status : undefined, {
          cause: new AggregateError([original, rollbackError], "cloudflare provisioning rollback failed")
        });
      }
      if (error instanceof CloudflareApiError) throw error;
      throw new CloudflareApiError("provision-installation", undefined, {
        cause: error
      });
    }
  }

  async rotate(_input: ProvisionTunnelInput, _previous: ProvisionedTunnel): Promise<ProvisionedTunnel> {
    // Credential rotation needs a two-phase desktop/VPS acknowledgement before
    // old tunnel and attestation material can be revoked. Failing closed avoids
    // silently breaking a live publisher with an unsafe one-step rotation.
    throw new Error("cloudflare credential rotation requires coordinated deployment");
  }

  async revoke(input: ProvisionTunnelInput, current: ProvisionedTunnel): Promise<void> {
    await withProcessSingleWriter(this.installationMutationKey(input.installationId), async () => {
      const receipt = decodeReceipt(current.providerResourceId);
      await this.cleanup(receipt, true);
      // Local revocation follows successful external cleanup so a transient API
      // failure remains retryable with the same receipt and references.
      await this.revokeCredentials([current.tunnelCredential, current.publisherMtlsCredential, current.publisherEdgeAttestation, current.mcpEdgeAttestation]);
      await this.credentials.revoke(journalReference(input.installationId));
    });
  }

  private installationMutationKey(installationId: string): string {
    return `${this.associationMutationKey}:installation:${createHash("sha256").update(installationId, "utf8").digest("hex")}`;
  }

  private introspectionUrl(installationId: string): string {
    return new URL(`/v1/installations/${encodeURIComponent(installationId)}/oauth/introspect`, this.introspectionBaseUrl).toString();
  }

  private async reconcileJournal(journal: ProviderJournal, journalRef: SecretReference): Promise<void> {
    await this.cleanup(journal.receipt, journal.associationsChanged || journal.associationPending);
    await this.revokeCredentials([
      journal.tunnelCredential,
      journal.publisherMtlsCredential,
      journal.publisherEdgeAttestation,
      ...(journal.mcpEdgeAttestation ? [journal.mcpEdgeAttestation] : []),
    ]);
    await this.credentials.revoke(journalRef);
  }

  private associationHostnames(value: unknown): string[] {
    const result = object(value, "read-mtls-associations");
    const candidate = result.hostnames;
    if (!Array.isArray(candidate) || candidate.some((host) => typeof host !== "string" || !HOST_RE.test(host))) throw new CloudflareApiError("read-mtls-associations");
    return [...new Set(candidate.map((host) => String(host).toLowerCase()))];
  }

  private async mutateAssociations<T>(operation: (current: string[], path: string) => Promise<T>): Promise<T> {
    return withProcessSingleWriter(this.associationMutationKey, async () => {
      const path = `zones/${this.zoneId}/certificate_authorities/hostname_associations`;
      const current = this.associationHostnames(await this.api.request(path, "read-mtls-associations", { method: "GET" }));
      return operation(current, path);
    });
  }

  private async revokeCredentials(references: SecretReference[]): Promise<void> {
    const failures: unknown[] = [];
    for (const reference of references) {
      try {
        await this.credentials.revoke(reference);
      } catch (error) {
        failures.push(error);
      }
    }
    if (failures.length > 0) throw new AggregateError(failures, "cloudflare credential revocation failed");
  }

  private async uploadWorker(script: string, source: string, plainTextBindings: Array<{ name: string; text: string }>): Promise<void> {
    const form = new FormData();
    form.set("metadata", new Blob([JSON.stringify({
      main_module: "worker.mjs",
      compatibility_date: "2025-01-01",
      ...(plainTextBindings.length > 0 ? { bindings: plainTextBindings.map(({ name, text }) => ({ name, type: "plain_text", text })) } : {}),
    })], { type: "application/json" }));
    form.set("worker.mjs", new Blob([source], { type: "application/javascript+module" }), "worker.mjs");
    await this.api.request(`accounts/${this.accountId}/workers/scripts/${safeId(script, "script id")}`, "upload-worker", { method: "PUT", body: form });
  }

  private async cleanup(receipt: Partial<ProviderReceipt> & { dnsRecordIds?: string[]; publisherHost?: string }, removeAssociation: boolean): Promise<void> {
    const failures: unknown[] = [];
    const attempt = async (operation: () => Promise<unknown>, deletion = false): Promise<void> => {
      try {
        await operation();
      } catch (error) {
        // DELETE 404 means the resource is already gone. Other failures must
        // remain visible so callers never mark an installation revoked while
        // provider resources may still be live.
        if (deletion && error instanceof CloudflareApiError && error.status === 404) return;
        failures.push(error);
      }
    };
    // Routes must disappear before their scripts. This order avoids a public
    // hostname temporarily resolving to an unbound or replacement script.
    if (receipt.mcpWorkerRouteId) await attempt(() => this.api.request(`zones/${this.zoneId}/workers/routes/${safeId(receipt.mcpWorkerRouteId!, "MCP route id")}`, "delete-mcp-worker-route", { method: "DELETE" }), true);
    if (receipt.mcpWorkerScript) await attempt(() => this.api.request(`accounts/${this.accountId}/workers/scripts/${safeId(receipt.mcpWorkerScript!, "MCP script id")}`, "delete-mcp-worker", { method: "DELETE" }), true);
    if (receipt.workerRouteId) await attempt(() => this.api.request(`zones/${this.zoneId}/workers/routes/${safeId(receipt.workerRouteId!, "route id")}`, "delete-worker-route", { method: "DELETE" }), true);
    if (receipt.workerScript) await attempt(() => this.api.request(`accounts/${this.accountId}/workers/scripts/${safeId(receipt.workerScript!, "script id")}`, "delete-worker", { method: "DELETE" }), true);
    if (removeAssociation && receipt.publisherHost) {
      await attempt(() => this.mutateAssociations(async (current, path) => {
        if (!current.includes(receipt.publisherHost!)) return;
        await this.api.request(path, "update-mtls-associations", {
          method: "PUT",
          body: JSON.stringify({ hostnames: current.filter((host) => host !== receipt.publisherHost) })
        });
      }));
    }
    if (receipt.certificateId) await attempt(() => this.api.request(`zones/${this.zoneId}/client_certificates/${safeId(receipt.certificateId!, "certificate id")}`, "delete-client-certificate", { method: "DELETE" }), true);
    for (const id of [...(receipt.dnsRecordIds ?? [])].reverse()) {
      await attempt(() => this.api.request(`zones/${this.zoneId}/dns_records/${safeId(id, "DNS record id")}`, "delete-dns", { method: "DELETE" }), true);
    }
    if (receipt.tunnelId) {
      await attempt(() => this.api.request(`accounts/${this.accountId}/cfd_tunnel/${safeId(receipt.tunnelId!, "tunnel id")}/connections`, "disconnect-tunnel", { method: "DELETE" }), true);
      await attempt(() => this.api.request(`accounts/${this.accountId}/cfd_tunnel/${safeId(receipt.tunnelId!, "tunnel id")}`, "delete-tunnel", { method: "DELETE" }), true);
    }
    if (failures.length > 0) throw new AggregateError(failures, "cloudflare external cleanup failed");
  }
}
