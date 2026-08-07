import { request as httpRequest } from "node:http";
import { request as httpsRequest, type RequestOptions } from "node:https";
import type { IncomingHttpHeaders } from "node:http";

export const PUBLISHER_REQUEST_TIMEOUT_MS = 15_000;
export const PUBLISHER_MAX_REQUEST_BYTES = 16 * 1024 * 1024;
export const PUBLISHER_MAX_RESPONSE_BYTES = 2 * 1024 * 1024;
const MAX_CERTIFICATE_BYTES = 256 * 1024;

/** In-memory only. Implementations must load these from Keychain/safeStorage at call time. */
export interface PublisherTlsCredentials {
  certificate: string;
  privateKey: string;
  caCertificate?: string;
}

export interface PublisherTlsCredentialProvider {
  get(): Promise<PublisherTlsCredentials | undefined>;
}

export interface PublisherRequest {
  url: URL;
  method: string;
  headers?: Record<string, string>;
  body?: string;
  timeoutMs?: number;
}

export interface PublisherResponse {
  statusCode: number;
  headers: IncomingHttpHeaders | Record<string, string | string[] | undefined>;
  body: string;
}

/** Test seam; production uses the bounded Node http/https implementation below. */
export type PublisherRequestExecutor = (input: PublisherRequest & { tls?: PublisherTlsCredentials }) => Promise<PublisherResponse>;

function assertCredential(value: PublisherTlsCredentials): void {
  if (!value.certificate || !value.privateKey) throw new Error("publisher_mtls_credentials_invalid");
  if (Buffer.byteLength(value.certificate, "utf8") > MAX_CERTIFICATE_BYTES || Buffer.byteLength(value.privateKey, "utf8") > MAX_CERTIFICATE_BYTES || (value.caCertificate && Buffer.byteLength(value.caCertificate, "utf8") > MAX_CERTIFICATE_BYTES)) {
    throw new Error("publisher_mtls_credentials_too_large");
  }
}

function isLoopbackHost(host: string): boolean {
  const normalized = host.replace(/^\[/u, "").replace(/\]$/u, "").toLowerCase();
  return normalized === "localhost" || normalized === "127.0.0.1" || normalized === "::1";
}

function headerBytes(headers: Record<string, string> | undefined): number {
  return Object.entries(headers ?? {}).reduce((total, [key, value]) => total + Buffer.byteLength(key, "utf8") + Buffer.byteLength(value, "utf8"), 0);
}

function nodeRequest(input: PublisherRequest & { tls?: PublisherTlsCredentials }): Promise<PublisherResponse> {
  const { url } = input;
  const timeoutMs = Math.max(100, Math.min(input.timeoutMs ?? PUBLISHER_REQUEST_TIMEOUT_MS, PUBLISHER_REQUEST_TIMEOUT_MS));
  const body = input.body ?? "";
  if (Buffer.byteLength(body, "utf8") > PUBLISHER_MAX_REQUEST_BYTES) return Promise.reject(new Error("publisher request body is too large"));
  const headers: Record<string, string> = {
    ...(input.headers ?? {}),
    ...(body ? { "content-length": String(Buffer.byteLength(body, "utf8")) } : {})
  };
  const requestOptions: RequestOptions = {
    protocol: url.protocol,
    hostname: url.hostname,
    ...(url.port ? { port: Number(url.port) } : {}),
    path: `${url.pathname}${url.search}`,
    method: input.method,
    headers,
    timeout: timeoutMs,
    ...(url.protocol === "https:" ? {
      rejectUnauthorized: true,
      servername: url.hostname,
      ...(input.tls?.certificate ? { cert: input.tls.certificate } : {}),
      ...(input.tls?.privateKey ? { key: input.tls.privateKey } : {}),
      ...(input.tls?.caCertificate ? { ca: input.tls.caCertificate } : {})
    } : {})
  };
  const requestFunction = url.protocol === "https:" ? httpsRequest : httpRequest;
  return new Promise<PublisherResponse>((resolve, reject) => {
    let settled = false;
    const finish = (callback: () => void): void => {
      if (settled) return;
      settled = true;
      callback();
    };
    const request = requestFunction(requestOptions, (response) => {
      const contentLength = Number(response.headers["content-length"] ?? 0);
      if (Number.isFinite(contentLength) && contentLength > PUBLISHER_MAX_RESPONSE_BYTES) {
        response.resume();
        finish(() => reject(new Error("publisher response is too large")));
        return;
      }
      const chunks: Buffer[] = [];
      let bytes = 0;
      response.on("data", (chunk: Buffer | string) => {
        bytes += Buffer.byteLength(chunk);
        if (bytes > PUBLISHER_MAX_RESPONSE_BYTES) {
          response.destroy(new Error("publisher response is too large"));
          finish(() => reject(new Error("publisher response is too large")));
          return;
        }
        chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
      });
      response.on("end", () => finish(() => resolve({ statusCode: response.statusCode ?? 0, headers: response.headers, body: Buffer.concat(chunks).toString("utf8") })));
      response.on("error", (error) => finish(() => reject(error)));
    });
    request.setTimeout(timeoutMs, () => {
      request.destroy(new Error("publisher request timed out"));
    });
    request.on("error", (error) => finish(() => reject(error)));
    if (body) request.write(body);
    request.end();
  });
}

/**
 * HTTPS publisher transport with normal hostname verification, no redirects,
 * bounded request/response bodies, and a short timeout. The injected executor
 * is only a deterministic unit-test seam; it still receives ephemeral TLS
 * material and is never persisted by this package.
 */
export class NodeHttpsPublisherTransport {
  constructor(
    private readonly options: {
      credentialProvider?: PublisherTlsCredentialProvider;
      allowLoopbackHttp?: boolean;
      requireMtls?: boolean;
      executor?: PublisherRequestExecutor;
    } = {}
  ) {}

  async request(input: PublisherRequest): Promise<PublisherResponse> {
    if (input.body && Buffer.byteLength(input.body, "utf8") > PUBLISHER_MAX_REQUEST_BYTES) throw new Error("publisher request body is too large");
    if (headerBytes(input.headers) > PUBLISHER_MAX_REQUEST_BYTES) throw new Error("publisher request headers are too large");
    if (input.url.username || input.url.password) throw new Error("publisher URL credentials are forbidden");
    const https = input.url.protocol === "https:";
    const httpLoopback = input.url.protocol === "http:" && this.options.allowLoopbackHttp === true && isLoopbackHost(input.url.hostname);
    if (!https && !httpLoopback) throw new Error("publisher HTTPS is required");
    let tls: PublisherTlsCredentials | undefined;
    if (https && this.options.credentialProvider) {
      tls = await this.options.credentialProvider.get();
      if (tls) assertCredential(tls);
    }
    if (https && this.options.requireMtls === true && !tls) throw new Error("publisher_mtls_credentials_required");
    const response = await (this.options.executor ?? nodeRequest)({ ...input, ...(tls ? { tls } : {}) });
    const contentLengthHeader = response.headers["content-length"] ?? response.headers["Content-Length"];
    const contentLength = Array.isArray(contentLengthHeader) ? Number(contentLengthHeader[0] ?? 0) : Number(contentLengthHeader ?? 0);
    if ((Number.isFinite(contentLength) && contentLength > PUBLISHER_MAX_RESPONSE_BYTES) || Buffer.byteLength(response.body, "utf8") > PUBLISHER_MAX_RESPONSE_BYTES) throw new Error("publisher response is too large");
    if (response.statusCode >= 300 && response.statusCode < 400) throw new Error("publisher redirect refused");
    return response;
  }
}

export { assertCredential, isLoopbackHost, nodeRequest };
