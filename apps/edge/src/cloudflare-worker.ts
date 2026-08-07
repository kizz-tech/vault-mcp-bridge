export type PublisherWorkerSourceInput = {
  installationId: string;
  publisherHost: string;
  hiddenOriginHost: string;
  certificateFingerprint: string;
  attestationSecretBinding?: string;
  maxBodyBytes?: number;
};

export type McpWorkerSourceInput = {
  /** Installation identity is carried as a plain-text Worker binding. */
  installationId: string;
  /** Public MCP hostname on which this route is installed. */
  mcpHost: string;
  /** Exact edge introspection endpoint; this value is a plain-text binding. */
  introspectionUrl: string;
  mcpAttestationSecretBinding?: string;
  introspectionUrlBinding?: string;
  installationIdBinding?: string;
  maxBodyBytes?: number;
  maxHeaderBytes?: number;
  introspectionTimeoutMs?: number;
};

const HOST_RE = /^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/u;
const FINGERPRINT_RE = /^[A-Fa-f0-9:]{32,128}$/u;
const BINDING_RE = /^[A-Z][A-Z0-9_]{2,63}$/u;
const DEFAULT_MCP_BODY_BYTES = 3 * 1024 * 1024;
const DEFAULT_MCP_HEADER_BYTES = 64 * 1024;
const DEFAULT_INTROSPECTION_TIMEOUT_MS = 2_000;
const INTROSPECTION_RESPONSE_BYTES = 16 * 1024;

function validateWorkerBinding(value: string, field: string): string {
  if (!BINDING_RE.test(value)) throw new Error(`cloudflare ${field} binding is invalid`);
  return value;
}

function validateMcpSourceInput(input: McpWorkerSourceInput): {
  installationId: string;
  mcpHost: string;
  introspectionUrl: string;
  mcpAttestationSecretBinding: string;
  introspectionUrlBinding: string;
  installationIdBinding: string;
  maxBodyBytes: number;
  maxHeaderBytes: number;
  introspectionTimeoutMs: number;
} {
  if (!/^[A-Za-z0-9_-]{16,256}$/u.test(input.installationId)) throw new Error("cloudflare installation id is invalid");
  const mcpHost = input.mcpHost.toLowerCase();
  if (!HOST_RE.test(mcpHost)) throw new Error("cloudflare MCP worker hostname is invalid");
  let introspectionUrl: URL;
  try { introspectionUrl = new URL(input.introspectionUrl); } catch { throw new Error("cloudflare introspection URL is invalid"); }
  if (introspectionUrl.protocol !== "https:" || introspectionUrl.username || introspectionUrl.password || introspectionUrl.search || introspectionUrl.hash) {
    throw new Error("cloudflare introspection URL is invalid");
  }
  const expectedIntrospectionPath = `/v1/installations/${encodeURIComponent(input.installationId)}/oauth/introspect`;
  if (introspectionUrl.pathname !== expectedIntrospectionPath) throw new Error("cloudflare introspection URL is installation-mismatched");
  const mcpAttestationSecretBinding = validateWorkerBinding(input.mcpAttestationSecretBinding ?? "MCP_EDGE_ATTESTATION_SECRET", "MCP attestation secret");
  const introspectionUrlBinding = validateWorkerBinding(input.introspectionUrlBinding ?? "INTROSPECTION_URL", "introspection URL");
  const installationIdBinding = validateWorkerBinding(input.installationIdBinding ?? "INSTALLATION_ID", "installation id");
  if (new Set([mcpAttestationSecretBinding, introspectionUrlBinding, installationIdBinding]).size !== 3) throw new Error("cloudflare MCP worker bindings must be distinct");
  const maxBodyBytes = input.maxBodyBytes ?? DEFAULT_MCP_BODY_BYTES;
  if (!Number.isSafeInteger(maxBodyBytes) || maxBodyBytes < 1024 || maxBodyBytes > 16 * 1024 * 1024) throw new Error("cloudflare MCP worker body limit is invalid");
  const maxHeaderBytes = input.maxHeaderBytes ?? DEFAULT_MCP_HEADER_BYTES;
  if (!Number.isSafeInteger(maxHeaderBytes) || maxHeaderBytes < 1024 || maxHeaderBytes > 1024 * 1024) throw new Error("cloudflare MCP worker header limit is invalid");
  const introspectionTimeoutMs = input.introspectionTimeoutMs ?? DEFAULT_INTROSPECTION_TIMEOUT_MS;
  if (!Number.isSafeInteger(introspectionTimeoutMs) || introspectionTimeoutMs < 100 || introspectionTimeoutMs > 10_000) throw new Error("cloudflare introspection timeout is invalid");
  return {
    installationId: input.installationId,
    mcpHost,
    introspectionUrl: introspectionUrl.toString(),
    mcpAttestationSecretBinding,
    introspectionUrlBinding,
    installationIdBinding,
    maxBodyBytes,
    maxHeaderBytes,
    introspectionTimeoutMs,
  };
}

/**
 * Build the installation-scoped MCP policy Worker. The Worker performs a
 * fresh edge introspection decision before forwarding a POST /mcp request and
 * signs the exact request plus bearer-token digest for the tunnel origin.
 * Secret material is supplied only through a Worker secret binding.
 */
export function createMcpWorkerSource(input: McpWorkerSourceInput): string {
  const value = validateMcpSourceInput(input);
  return `const MCP_HOST = ${JSON.stringify(value.mcpHost)};
const MAX_BODY_BYTES = ${String(value.maxBodyBytes)};
const MAX_HEADER_BYTES = ${String(value.maxHeaderBytes)};
const INTROSPECTION_TIMEOUT_MS = ${String(value.introspectionTimeoutMs)};
const INTROSPECTION_RESPONSE_BYTES = ${String(INTROSPECTION_RESPONSE_BYTES)};
const MCP_ATTESTATION_SECRET = ${JSON.stringify(value.mcpAttestationSecretBinding)};
const INTROSPECTION_URL = ${JSON.stringify(value.introspectionUrlBinding)};
const INSTALLATION_ID = ${JSON.stringify(value.installationIdBinding)};
const ENCODER = new TextEncoder();
const RESERVED_HEADERS = ["x-vmb-mcp-edge-attestation", "x-vmb-mcp-edge-timestamp", "x-vmb-mcp-edge-nonce"];

function base64url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}

function deny(status, message, authenticate) {
  const headers = new Headers({ "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" });
  if (authenticate) headers.set("www-authenticate", authenticate);
  return new Response(message, { status, headers });
}

function stripReserved(headers) {
  for (const name of RESERVED_HEADERS) headers.delete(name);
}

function headerBytes(headers) {
  let total = 0;
  for (const [name, value] of headers) total += ENCODER.encode(name).byteLength + ENCODER.encode(value).byteLength;
  return total;
}

function bearerToken(headers) {
  const value = headers.get("authorization") || "";
  const match = /^Bearer\\s+([^\\s]+)$/iu.exec(value.trim());
  return match ? match[1] : null;
}

async function digestBase64url(value) {
  return base64url(new Uint8Array(await crypto.subtle.digest("SHA-256", ENCODER.encode(value))));
}

async function sign(secret, canonical) {
  const key = await crypto.subtle.importKey("raw", ENCODER.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return base64url(new Uint8Array(await crypto.subtle.sign("HMAC", key, ENCODER.encode(canonical))));
}

async function boundedJson(response) {
  const announced = Number(response.headers.get("content-length") || "0");
  if (Number.isFinite(announced) && announced > INTROSPECTION_RESPONSE_BYTES) throw new Error("introspection response too large");
  if (!response.body) return null;
  const reader = response.body.getReader();
  const chunks = [];
  let size = 0;
  try {
    while (true) {
      const part = await reader.read();
      if (part.done) break;
      size += part.value.byteLength;
      if (size > INTROSPECTION_RESPONSE_BYTES) throw new Error("introspection response too large");
      chunks.push(part.value);
    }
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return JSON.parse(new TextDecoder().decode(bytes));
}

function challenge() {
  return "Bearer realm=\\"mcp\\", resource_metadata=\\"https://" + MCP_HOST + "/.well-known/oauth-protected-resource/mcp\\", error=\\"invalid_token\\"";
}

async function introspect(token, env) {
  const secret = env[MCP_ATTESTATION_SECRET];
  const target = env[INTROSPECTION_URL];
  const installationId = env[INSTALLATION_ID];
  if (typeof secret !== "string" || secret.length < 32 || typeof target !== "string" || target.length === 0 || typeof installationId !== "string" || installationId.length === 0) return { kind: "error" };
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), INTROSPECTION_TIMEOUT_MS);
  try {
    const response = await fetch(target, {
      method: "POST",
      headers: { "authorization": "Bearer " + secret, "content-type": "application/json", "cache-control": "no-store" },
      body: JSON.stringify({ token }),
      cache: "no-store",
      redirect: "error",
      signal: controller.signal,
    });
    if (!response.ok) return { kind: "error" };
    const body = await boundedJson(response);
    return body && body.active === true ? { kind: "active" } : { kind: "inactive" };
  } catch {
    return { kind: "error" };
  } finally {
    clearTimeout(timer);
  }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.hostname.toLowerCase() !== MCP_HOST) return deny(404, "Not found");
    if (headerBytes(request.headers) > MAX_HEADER_BYTES) return deny(431, "Request headers too large");
    const headers = new Headers(request.headers);
    stripReserved(headers);
    const contentLength = request.headers.get("content-length");
    if (contentLength !== null) {
      const announced = Number(contentLength);
      if (!Number.isSafeInteger(announced) || announced < 0 || announced > MAX_BODY_BYTES) return deny(413, "Request too large");
    }
    const metadataPath = url.pathname === "/.well-known/oauth-protected-resource" || url.pathname === "/.well-known/oauth-protected-resource/mcp";
    if (metadataPath) {
      if (request.method.toUpperCase() !== "GET" || url.search) return deny(404, "Not found");
      return fetch(new Request(request, { headers }));
    }
    if (url.pathname !== "/mcp") return deny(404, "Not found");
    if (request.method.toUpperCase() !== "POST") return deny(405, "Method not allowed");
    let bodyBytes;
    try {
      bodyBytes = await request.clone().arrayBuffer();
    } catch {
      return deny(400, "Invalid request body");
    }
    if (bodyBytes.byteLength > MAX_BODY_BYTES) return deny(413, "Request too large");
    const token = bearerToken(request.headers);
    if (!token) return deny(401, "Bearer token required", challenge());
    const decision = await introspect(token, env);
    if (decision.kind === "error") return deny(503, "MCP edge unavailable");
    if (decision.kind !== "active") return deny(401, "Invalid bearer token", challenge());
    const timestamp = String(Math.floor(Date.now() / 1000));
    const nonce = base64url(crypto.getRandomValues(new Uint8Array(24)));
    const tokenDigest = await digestBase64url(token);
    const canonical = [request.method.toUpperCase(), url.pathname + url.search || "/", url.hostname.toLowerCase(), tokenDigest, timestamp, nonce].join("\\n");
    const secret = env[MCP_ATTESTATION_SECRET];
    let signature;
    try {
      signature = await sign(secret, canonical);
    } catch {
      return deny(503, "MCP edge unavailable");
    }
    headers.set("x-vmb-mcp-edge-attestation", signature);
    headers.set("x-vmb-mcp-edge-timestamp", timestamp);
    headers.set("x-vmb-mcp-edge-nonce", nonce);
    return fetch(new Request(request, { headers }));
  }
};
`;
}

/**
 * Build the installation-scoped Cloudflare Worker that terminates publisher
 * mTLS and binds the verified result to the exact request seen by the origin.
 * The generated source contains no secret: the HMAC key is a Worker secret
 * binding installed through the Cloudflare API.
 */
export function createPublisherWorkerSource(input: PublisherWorkerSourceInput): string {
  if (!/^[A-Za-z0-9_-]{16,256}$/u.test(input.installationId)) throw new Error("cloudflare installation id is invalid");
  const publisherHost = input.publisherHost.toLowerCase();
  const hiddenOriginHost = input.hiddenOriginHost.toLowerCase();
  if (!HOST_RE.test(publisherHost) || !HOST_RE.test(hiddenOriginHost) || publisherHost === hiddenOriginHost) {
    throw new Error("cloudflare worker hostname is invalid");
  }
  if (!FINGERPRINT_RE.test(input.certificateFingerprint)) throw new Error("cloudflare certificate fingerprint is invalid");
  const fingerprint = input.certificateFingerprint.replaceAll(":", "").toLowerCase();
  const binding = input.attestationSecretBinding ?? "EDGE_ATTESTATION_SECRET";
  if (!/^[A-Z][A-Z0-9_]{2,63}$/u.test(binding)) throw new Error("cloudflare worker binding is invalid");
  const maxBodyBytes = input.maxBodyBytes ?? 3 * 1024 * 1024;
  if (!Number.isSafeInteger(maxBodyBytes) || maxBodyBytes < 1024 || maxBodyBytes > 16 * 1024 * 1024) {
    throw new Error("cloudflare worker body limit is invalid");
  }

  return `const INSTALLATION_ID = ${JSON.stringify(input.installationId)};
const PUBLISHER_HOST = ${JSON.stringify(publisherHost)};
const HIDDEN_ORIGIN_HOST = ${JSON.stringify(hiddenOriginHost)};
const ALLOWED_FINGERPRINT = ${JSON.stringify(fingerprint)};
const MAX_BODY_BYTES = ${String(maxBodyBytes)};
const ENCODER = new TextEncoder();
const EDGE_HEADERS = ["x-vmb-edge-attestation", "x-vmb-edge-mtls-status", "x-vmb-edge-timestamp", "x-vmb-edge-nonce", "x-vmb-installation-id"];

function base64url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}

function fingerprint(value) {
  return String(value || "").replaceAll(":", "").toLowerCase();
}

function deny(status, message) {
  return new Response(message, { status, headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" } });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.hostname.toLowerCase() !== PUBLISHER_HOST) return deny(404, "Not found");
    const contentLength = Number(request.headers.get("content-length") || "0");
    if (!Number.isFinite(contentLength) || contentLength < 0 || contentLength > MAX_BODY_BYTES) return deny(413, "Request too large");

    const tls = request.cf && request.cf.tlsClientAuth;
    const verified = tls && tls.certVerified === "SUCCESS" && tls.certRevoked !== "1";
    if (!verified || fingerprint(tls.certFingerprintSHA256) !== ALLOWED_FINGERPRINT) return deny(403, "Client certificate required");
    if (!env.${binding}) return deny(503, "Publisher edge unavailable");

    const headers = new Headers(request.headers);
    for (const name of EDGE_HEADERS) headers.delete(name);
    const timestamp = String(Math.floor(Date.now() / 1000));
    const nonceBytes = crypto.getRandomValues(new Uint8Array(24));
    const nonce = base64url(nonceBytes);
    const exactUrl = url.pathname + url.search;
    const canonical = [request.method.toUpperCase(), exactUrl || "/", PUBLISHER_HOST, "verified", timestamp, nonce].join("\\n");
    const key = await crypto.subtle.importKey("raw", ENCODER.encode(env.${binding}), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    const signature = base64url(new Uint8Array(await crypto.subtle.sign("HMAC", key, ENCODER.encode(canonical))));
    headers.set("x-vmb-edge-attestation", signature);
    headers.set("x-vmb-edge-mtls-status", "verified");
    headers.set("x-vmb-edge-timestamp", timestamp);
    headers.set("x-vmb-edge-nonce", nonce);
    headers.set("x-vmb-installation-id", INSTALLATION_ID);

    const origin = new URL(request.url);
    origin.protocol = "https:";
    origin.hostname = HIDDEN_ORIGIN_HOST;
    origin.port = "";
    const init = { method: request.method, headers, redirect: "manual" };
    if (request.method !== "GET" && request.method !== "HEAD") init.body = request.body;
    return fetch(new Request(origin.toString(), init));
  }
};
`;
}
