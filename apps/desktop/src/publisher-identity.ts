import { createHash, createPrivateKey, webcrypto } from "node:crypto";

import { Pkcs10CertificateRequestGenerator, cryptoProvider } from "@peculiar/x509";
import { OpaqueIdSchema } from "@vault-mcp-bridge/contracts";

import type { SecretStore } from "./secret-store.js";

/** The value returned by the local publisher identity provider. */
export interface PublisherIdentity {
  /** Public PKCS#10 certificate request. This is the only field sent to an edge provider. */
  readonly csr: string;
  /** PKCS#8 PEM private key. Keep this value local to the desktop process. */
  readonly privateKey: string;
}

/**
 * Local identity seam used by the owner/edge adapter.
 *
 * Implementations must keep the private key inside the desktop trust boundary;
 * callers should pass only `csr` to a provider and use `privateKey` for local
 * mTLS configuration.
 */
export interface PublisherIdentityProvider {
  ensure(installationId: string): Promise<{ csr: string; privateKey: string }>;
}

export interface PublisherIdentityProviderOptions {
  readonly secrets: SecretStore;
}

const IDENTITY_VERSION = 1 as const;
const REFERENCE_PREFIX = "publisher.mtls.identity";
const MAX_CSR_BYTES = 16 * 1024;
const MAX_PRIVATE_KEY_BYTES = 16 * 1024;
const MAX_METADATA_BYTES = 64 * 1024;
const PRIVATE_KEY_LABEL = "PRIVATE KEY";
const CSR_LABEL = "CERTIFICATE REQUEST";

interface StoredPublisherIdentity {
  readonly version: typeof IDENTITY_VERSION;
  readonly installationId: string;
  readonly csr: string;
  readonly privateKey: string;
}

// @peculiar/x509 delegates signing and ASN.1 generation to the configured Web
// Crypto implementation. Node's webcrypto is the platform implementation for
// the desktop process; it does not involve a network or provider API.
cryptoProvider.set(webcrypto as unknown as Crypto);

/**
 * Return the deterministic, installation-scoped SecretStore reference.
 *
 * Hashing keeps the reference bounded and prevents an opaque id from becoming
 * a path-like storage key while still ensuring that different installations
 * cannot share a record.
 */
export function publisherIdentityReference(installationId: string): string {
  const validated = validateInstallationId(installationId);
  const digest = createHash("sha256").update(validated, "utf8").digest("base64url");
  return `${REFERENCE_PREFIX}.${digest}`;
}

/** Validate an installation id before it is used in a subject or storage key. */
export function validateInstallationId(installationId: string): string {
  try {
    return OpaqueIdSchema.parse(installationId);
  } catch {
    throw new TypeError("publisher_installation_id_invalid");
  }
}

/**
 * macOS-owned publisher mTLS identity backed by the desktop SecretStore.
 *
 * The constructor accepts the store directly for small integrations and an
 * options object for dependency-injection call sites.
 */
export class MacPublisherIdentityProvider implements PublisherIdentityProvider {
  private readonly secrets: SecretStore;
  private readonly inFlight = new Map<string, Promise<PublisherIdentity>>();

  constructor(secrets: SecretStore);
  constructor(options: PublisherIdentityProviderOptions);
  constructor(input: SecretStore | PublisherIdentityProviderOptions) {
    this.secrets = isSecretStore(input) ? input : input.secrets;
  }

  async ensure(installationId: string): Promise<PublisherIdentity> {
    const validated = validateInstallationId(installationId);
    const pending = this.inFlight.get(validated);
    if (pending) return pending;

    const operation = this.ensureStored(validated).finally(() => {
      this.inFlight.delete(validated);
    });
    this.inFlight.set(validated, operation);
    return operation;
  }

  private async ensureStored(installationId: string): Promise<PublisherIdentity> {
    const reference = publisherIdentityReference(installationId);
    const existing = await this.secrets.get(reference);
    if (existing !== null) return parseStoredIdentity(existing, installationId);

    const generated = await generateIdentity(installationId);
    const record: StoredPublisherIdentity = {
      version: IDENTITY_VERSION,
      installationId,
      csr: generated.csr,
      privateKey: generated.privateKey
    };
    const encoded = JSON.stringify(record);
    if (Buffer.byteLength(encoded, "utf8") > MAX_METADATA_BYTES) {
      throw new Error("publisher_identity_metadata_too_large");
    }
    // SecretStore is the only persistence boundary. No private key is sent to
    // an edge/provider; only this local encrypted store receives the record.
    await this.secrets.put(reference, encoded);
    return generated;
  }
}

/** Alias kept short for callers that do not need to mention the platform. */
export const PublisherIdentityStore = MacPublisherIdentityProvider;
/** Explicit desktop alias for dependency-injection call sites. */
export const DesktopPublisherIdentityProvider = MacPublisherIdentityProvider;

async function generateIdentity(installationId: string): Promise<PublisherIdentity> {
  const keys = await webcrypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"]
  );
  if (!("privateKey" in keys) || !("publicKey" in keys)) {
    throw new Error("publisher_identity_key_generation_failed");
  }

  const keyPair = keys as CryptoKeyPair;
  const request = await Pkcs10CertificateRequestGenerator.create({
    name: `CN=publisher-${installationId}`,
    keys: keyPair,
    signingAlgorithm: { name: "ECDSA", hash: "SHA-256" }
  });
  const csr = request.toString("pem");
  validateCsrPem(csr);

  const privateDer = await webcrypto.subtle.exportKey("pkcs8", keyPair.privateKey);
  const privateKey = toPem(Buffer.from(privateDer), PRIVATE_KEY_LABEL);
  validatePrivateKeyPem(privateKey);
  return { csr, privateKey };
}

function parseStoredIdentity(value: string, installationId: string): PublisherIdentity {
  if (Buffer.byteLength(value, "utf8") > MAX_METADATA_BYTES) {
    throw new Error("publisher_identity_metadata_too_large");
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(value) as unknown;
  } catch {
    throw new Error("publisher_identity_metadata_invalid");
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("publisher_identity_metadata_invalid");
  }
  const record = parsed as Partial<StoredPublisherIdentity>;
  if (
    record.version !== IDENTITY_VERSION ||
    record.installationId !== installationId ||
    typeof record.csr !== "string" ||
    typeof record.privateKey !== "string"
  ) {
    throw new Error("publisher_identity_metadata_invalid");
  }

  validateCsrPem(record.csr);
  validatePrivateKeyPem(record.privateKey);
  return { csr: record.csr, privateKey: record.privateKey };
}

function validateCsrPem(value: string): void {
  const body = decodePem(value, CSR_LABEL, MAX_CSR_BYTES);
  assertDerSequence(body, "publisher_csr_invalid");
}

function validatePrivateKeyPem(value: string): void {
  decodePem(value, PRIVATE_KEY_LABEL, MAX_PRIVATE_KEY_BYTES);
  try {
    const key = createPrivateKey({ key: value, format: "pem", type: "pkcs8" });
    if (key.asymmetricKeyType !== "ec" || key.asymmetricKeyDetails?.namedCurve !== "prime256v1") {
      throw new Error("wrong key algorithm");
    }
  } catch {
    throw new Error("publisher_private_key_invalid");
  }
}

function decodePem(value: string, label: string, maxBytes: number): Buffer {
  if (typeof value !== "string" || !value || Buffer.byteLength(value, "utf8") > maxBytes) {
    throw new Error(label === CSR_LABEL ? "publisher_csr_invalid" : "publisher_private_key_invalid");
  }
  const escaped = label.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
  const expression = new RegExp(`^-----BEGIN ${escaped}-----\\s*([A-Za-z0-9+/=\\r\\n]+?)\\s*-----END ${escaped}-----\\s*$`, "u");
  const match = expression.exec(value);
  if (!match?.[1]) {
    throw new Error(label === CSR_LABEL ? "publisher_csr_invalid" : "publisher_private_key_invalid");
  }
  const encoded = match[1].replace(/[\r\n\t ]/gu, "");
  if (!encoded || encoded.length % 4 !== 0 || !/^[A-Za-z0-9+/]+={0,2}$/u.test(encoded)) {
    throw new Error(label === CSR_LABEL ? "publisher_csr_invalid" : "publisher_private_key_invalid");
  }
  let decoded: Buffer;
  try {
    decoded = Buffer.from(encoded, "base64");
  } catch {
    throw new Error(label === CSR_LABEL ? "publisher_csr_invalid" : "publisher_private_key_invalid");
  }
  if (!decoded.length || decoded.toString("base64") !== encoded) {
    throw new Error(label === CSR_LABEL ? "publisher_csr_invalid" : "publisher_private_key_invalid");
  }
  return decoded;
}

function assertDerSequence(value: Buffer, errorCode: string): void {
  if (value.length < 2 || value[0] !== 0x30) throw new Error(errorCode);
  const firstLength = value[1];
  if (firstLength === undefined) throw new Error(errorCode);
  if ((firstLength & 0x80) === 0) {
    if (value.length !== firstLength + 2) throw new Error(errorCode);
    return;
  }
  const octets = firstLength & 0x7f;
  if (octets === 0 || octets > 4 || value.length < octets + 2) throw new Error(errorCode);
  let length = 0;
  for (let index = 0; index < octets; index += 1) length = length * 256 + (value[2 + index] ?? 0);
  if (length !== value.length - octets - 2) throw new Error(errorCode);
}

function toPem(value: Buffer, label: string): string {
  const encoded = value.toString("base64");
  const lines = encoded.match(/.{1,64}/gu) ?? [];
  return `-----BEGIN ${label}-----\n${lines.join("\n")}\n-----END ${label}-----\n`;
}

function isSecretStore(value: SecretStore | PublisherIdentityProviderOptions): value is SecretStore {
  return typeof (value as SecretStore).get === "function" && typeof (value as SecretStore).put === "function";
}
