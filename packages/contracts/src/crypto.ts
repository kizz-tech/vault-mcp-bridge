import {
  createHash,
  createHmac,
  sign,
  verify,
  type KeyObject,
  type KeyLike
} from "node:crypto";

export type ByteInput = string | Uint8Array;

function bytes(value: ByteInput): Buffer {
  return typeof value === "string" ? Buffer.from(value, "utf8") : Buffer.from(value);
}

/** Return a URL-safe, unpadded SHA-256 digest. */
export function sha256Base64Url(value: ByteInput): string {
  return createHash("sha256").update(bytes(value)).digest("base64url");
}

/** HMAC-SHA-256 helper used for opaque local document identifiers. */
export function hmacSha256Base64Url(key: ByteInput, value: ByteInput): string {
  return createHmac("sha256", bytes(key)).update(bytes(value)).digest("base64url");
}

export interface SignedRequestFields {
  method: string;
  path: string;
  timestamp: number | string;
  nonce: string;
  digest: string;
}

/**
 * The exact bytes covered by a publisher signature. Keep this deliberately
 * boring and line-oriented so other languages can implement it safely.
 */
export function canonicalSignedRequestPayload(fields: SignedRequestFields): string {
  const method = fields.method.trim().toUpperCase();
  const path = fields.path.trim();
  const nonce = fields.nonce.trim();
  const digest = fields.digest.trim();
  if (!method || !path.startsWith("/") || !nonce || !digest) {
    throw new TypeError("Invalid signed request fields");
  }
  if (/\r|\n/.test(method) || /\r|\n/.test(path) || /\r|\n/.test(nonce) || /\r|\n/.test(digest)) {
    throw new TypeError("Signed request fields may not contain newlines");
  }
  const timestamp = String(fields.timestamp).trim();
  if (!timestamp || /\r|\n/.test(timestamp)) {
    throw new TypeError("Invalid signed request timestamp");
  }
  return [method, path, timestamp, nonce, digest].join("\n");
}

function keyObject(key: KeyLike | string | Uint8Array): KeyLike {
  // KeyObject and PEM/JWK values are accepted by node:crypto directly. A
  // Uint8Array is treated as DER and is useful for raw key material supplied
  // by a local key store.
  return key as KeyLike;
}

/** Sign arbitrary bytes with an Ed25519 private key; result is base64url. */
export function signEd25519(payload: ByteInput, privateKey: KeyObject | string | Uint8Array): string {
  const signature = sign(null, bytes(payload), keyObject(privateKey));
  return signature.toString("base64url");
}

/** Verify an Ed25519 base64url signature. Invalid key/signature returns false. */
export function verifyEd25519(
  payload: ByteInput,
  signatureBase64Url: string,
  publicKey: KeyObject | string | Uint8Array
): boolean {
  try {
    return verify(
      null,
      bytes(payload),
      keyObject(publicKey),
      Buffer.from(signatureBase64Url, "base64url")
    );
  } catch {
    return false;
  }
}

export function signCanonicalRequest(
  fields: SignedRequestFields,
  privateKey: KeyObject | string | Uint8Array
): string {
  return signEd25519(canonicalSignedRequestPayload(fields), privateKey);
}

export function verifyCanonicalRequest(
  fields: SignedRequestFields,
  signatureBase64Url: string,
  publicKey: KeyObject | string | Uint8Array
): boolean {
  return verifyEd25519(canonicalSignedRequestPayload(fields), signatureBase64Url, publicKey);
}

/** A stable JSON representation for digesting protocol values. */
export function canonicalJson(value: unknown): string {
  if (value === null) return "null";
  if (typeof value === "string") return JSON.stringify(value);
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new TypeError("Canonical JSON accepts finite numbers only");
    return JSON.stringify(value);
  }
  if (typeof value === "bigint") return JSON.stringify(value.toString());
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([, entry]) => entry !== undefined)
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
    return `{${entries.map(([key, entry]) => `${JSON.stringify(key)}:${canonicalJson(entry)}`).join(",")}}`;
  }
  throw new TypeError(`Unsupported canonical JSON value: ${typeof value}`);
}
