import { createPublicKey, generateKeyPairSync } from 'node:crypto';
import { NodeHttpsPublisherTransport, type PublisherRequest, type PublisherResponse, type PublisherRequestExecutor, type PublisherTlsCredentialProvider } from '@vault-mcp-bridge/agent-core';
import { CONTRACT_VERSION, PairDeviceResponseSchema, PublisherStatusResponseSchema, UploadReceiptSchema, sha256Base64Url, signCanonicalRequest } from '@vault-mcp-bridge/contracts';
import { allowedRemoteUrl, nonce } from './security.js';
import type { PublisherStatus, RemoteClient, SnapshotPayload } from './types.js';

const REQUEST_TIMEOUT_MS = 15_000;
const MAX_RESPONSE_BYTES = 2 * 1024 * 1024;

export interface HttpRemoteClientOptions {
  credentialProvider?: PublisherTlsCredentialProvider;
  requestExecutor?: PublisherRequestExecutor;
  requireMtls?: boolean;
}

function bodyToString(value: unknown): string {
  return JSON.stringify(value);
}

async function fetchJson(url: URL, init: RequestInit, timeoutMs = REQUEST_TIMEOUT_MS): Promise<unknown> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url, { ...init, redirect: 'error', signal: controller.signal });
    const contentLength = Number(response.headers.get('content-length') || 0);
    if (contentLength > MAX_RESPONSE_BYTES) throw new Error('remote response is too large');
    const buffer = await response.arrayBuffer();
    if (buffer.byteLength > MAX_RESPONSE_BYTES) throw new Error('remote response is too large');
    const text = new TextDecoder().decode(buffer);
    let payload: unknown;
    try { payload = text ? JSON.parse(text) : {}; } catch { throw new Error('remote response was not JSON'); }
    if (!response.ok) throw new Error(`remote request failed (${response.status})`);
    return payload;
  } finally {
    clearTimeout(timer);
  }
}

function responseHeader(response: PublisherResponse, name: string): string | undefined {
  const value = response.headers[name.toLowerCase()] ?? response.headers[name];
  return Array.isArray(value) ? value[0] : typeof value === 'string' ? value : undefined;
}

async function transportJson(transport: NodeHttpsPublisherTransport, url: URL, init: RequestInit): Promise<unknown> {
  const headers = new Headers(init.headers);
  const request: PublisherRequest = {
    url,
    method: init.method || 'GET',
    headers: Object.fromEntries(headers.entries()),
    ...(typeof init.body === 'string' ? { body: init.body } : {})
  };
  const response = await transport.request(request);
  const contentLength = Number(responseHeader(response, 'content-length') || 0);
  if (contentLength > MAX_RESPONSE_BYTES || Buffer.byteLength(response.body, 'utf8') > MAX_RESPONSE_BYTES) throw new Error('remote response is too large');
  let payload: unknown;
  try { payload = response.body ? JSON.parse(response.body) : {}; } catch { throw new Error('remote response was not JSON'); }
  if (response.statusCode < 200 || response.statusCode >= 300) throw new Error(`remote request failed (${response.statusCode})`);
  return payload;
}

export function generateDeviceKeypair(): { privateKey: string; publicKey: string } {
  const keyPair = generateKeyPairSync('ed25519', { privateKeyEncoding: { format: 'pem', type: 'pkcs8' }, publicKeyEncoding: { format: 'pem', type: 'spki' } });
  const publicKey = createPublicKey(keyPair.publicKey).export({ format: 'der', type: 'spki' }).toString('base64url');
  return { privateKey: keyPair.privateKey, publicKey };
}

export class HttpRemoteClient implements RemoteClient {
  private readonly transport?: NodeHttpsPublisherTransport;

  constructor(private readonly allowLoopback = false, options: HttpRemoteClientOptions = {}) {
    if (options.credentialProvider || options.requestExecutor || options.requireMtls) {
      this.transport = new NodeHttpsPublisherTransport({
        ...(options.credentialProvider ? { credentialProvider: options.credentialProvider } : {}),
        ...(options.requestExecutor ? { executor: options.requestExecutor } : {}),
        allowLoopbackHttp: allowLoopback,
        requireMtls: options.requireMtls ?? Boolean(options.credentialProvider)
      });
    }
  }

  private requestJson(url: URL, init: RequestInit): Promise<unknown> {
    return this.transport ? transportJson(this.transport, url, init) : fetchJson(url, init);
  }

  async pair(input: { url: string; code: string; agentId: string; vaultId?: string; publicKey: string; label?: string }): Promise<{ deviceId: string; vaultId?: string; receipt?: unknown }> {
    const root = allowedRemoteUrl(input.url, this.allowLoopback);
    const url = new URL('/v1/pairing/consume', root);
    const body = bodyToString({ version: CONTRACT_VERSION, pairCode: input.code, agentId: input.agentId, publicKey: input.publicKey, ...(input.vaultId ? { vaultId: input.vaultId } : {}), ...(input.label ? { label: input.label } : {}) });
    const typed = PairDeviceResponseSchema.parse(await this.requestJson(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body }));
    return { deviceId: typed.deviceId, vaultId: typed.vaultId, receipt: typed };
  }

  async upload(input: { url: string; deviceId: string; vaultId: string; snapshot: SnapshotPayload; privateKey: string }): Promise<unknown> {
    const root = allowedRemoteUrl(input.url, this.allowLoopback);
    const url = new URL('/v1/snapshots', root);
    const timestamp = Math.floor(Date.now() / 1000);
    const requestNonce = nonce();
    const snapshot = input.snapshot.snapshot as { digest?: string };
    if (!snapshot.digest) throw new Error('snapshot digest is required before upload');
    const signature = signCanonicalRequest({ method: 'POST', path: url.pathname, timestamp, nonce: requestNonce, digest: snapshot.digest }, input.privateKey);
    const body = bodyToString({ deviceId: input.deviceId, vaultId: input.vaultId, timestamp, nonce: requestNonce, signature, snapshot: input.snapshot.snapshot });
    return UploadReceiptSchema.parse(await this.requestJson(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body }));
  }

  async status(input: { url: string; deviceId: string; vaultId: string; privateKey: string }): Promise<PublisherStatus> {
    const root = allowedRemoteUrl(input.url, this.allowLoopback);
    const url = new URL('/v1/status', root);
    url.searchParams.set('vaultId', input.vaultId);
    const timestamp = Math.floor(Date.now() / 1000);
    const requestNonce = nonce();
    const signature = signCanonicalRequest({ method: 'GET', path: url.pathname, timestamp, nonce: requestNonce, digest: sha256Base64Url(input.vaultId) }, input.privateKey);
    const value = PublisherStatusResponseSchema.parse(await this.requestJson(url, {
      method: 'GET',
      headers: {
        accept: 'application/json',
        'x-bridge-device-id': input.deviceId,
        'x-bridge-vault-id': input.vaultId,
        'x-bridge-timestamp': String(timestamp),
        'x-bridge-nonce': requestNonce,
        'x-bridge-signature': signature,
      }
    }));
    const activatedAt = value.active?.activatedAt;
    return {
      ok: true,
      checkedAt: new Date().toISOString(),
      ...(value.vaultId ? { vaultId: value.vaultId } : {}),
      ...(typeof value.active?.generation === 'number' ? { generation: value.active.generation } : {}),
      ...(value.active?.snapshotId ? { snapshotId: value.active.snapshotId } : {}),
      ...(typeof activatedAt === 'number' ? { freshnessSeconds: Math.max(0, timestamp - activatedAt) } : {}),
    };
  }
}

export { fetchJson, REQUEST_TIMEOUT_MS, MAX_RESPONSE_BYTES };
