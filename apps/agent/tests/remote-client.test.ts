import { createPublicKey } from 'node:crypto';
import { describe, expect, it, vi } from 'vitest';
import type { PublisherRequestExecutor, PublisherTlsCredentialProvider } from '@vault-mcp-bridge/agent-core';
import { sha256Base64Url, verifyCanonicalRequest } from '@vault-mcp-bridge/contracts';
import { generateDeviceKeypair, HttpRemoteClient } from '../src/remote-client.js';

describe('remote client protocol envelope', () => {
  it('uses pairing consume, DER public keys, and the signed snapshot envelope', async () => {
    const requests: Array<{ url: string; init: RequestInit }> = [];
    const originalFetch = globalThis.fetch;
    globalThis.fetch = vi.fn(async (input: URL | RequestInfo, init: RequestInit = {}) => {
      requests.push({ url: String(input), init });
      const path = new URL(String(input)).pathname;
      const response = path === '/v1/pairing/consume'
        ? { version: 1, deviceId: 'device_test_opaque_id', vaultId: 'vault_test_opaque_id', serverUrl: 'https://bridge.example', expiresAt: new Date(Date.now() + 60_000).toISOString() }
        : { version: 1, accepted: true, idempotent: false, generation: 1, vaultId: 'vault_test_opaque_id', documentCount: 0, digest: sha256Base64Url('synthetic'), receivedAt: new Date().toISOString(), snapshotId: '32f9f08e-6c2c-4b42-9a0c-cc1d1c3cf7b2' };
      return new Response(JSON.stringify(response), { status: 202, headers: { 'content-type': 'application/json' } });
    });
    try {
      const keys = generateDeviceKeypair();
      const publicDer = Buffer.from(keys.publicKey, 'base64url');
      expect(publicDer.length).toBeGreaterThanOrEqual(32);
      expect(createPublicKey({ key: publicDer, format: 'der', type: 'spki' }).asymmetricKeyType).toBe('ed25519');
      const client = new HttpRemoteClient();
      await client.pair({ url: 'https://bridge.example', code: 'PAIR-1234', agentId: 'agent-test-opaque-id', publicKey: keys.publicKey, vaultId: 'vault-test' });
      expect(requests[0]?.url).toBe('https://bridge.example/v1/pairing/consume');
      const pairBody = JSON.parse(String(requests[0]?.init.body)) as Record<string, unknown>;
      expect(pairBody).toMatchObject({ version: 1, pairCode: 'PAIR-1234', agentId: 'agent-test-opaque-id', publicKey: keys.publicKey, vaultId: 'vault-test' });
      expect(pairBody).not.toHaveProperty('vaultRoot');

      const snapshot = {
        version: 1,
        snapshotId: '32f9f08e-6c2c-4b42-9a0c-cc1d1c3cf7b2',
        vaultId: 'vault-test',
        generation: 1,
        createdAt: new Date().toISOString(),
        documents: [],
        digest: 'synthetic-digest'
      };
      // The fake response path is enough to inspect request shape; the digest is
      // deliberately a protocol-looking fixture rather than real vault content.
      await client.upload({ url: 'https://bridge.example', deviceId: 'agent-test-opaque-id', vaultId: 'vault-test', snapshot: { snapshot, body: JSON.stringify(snapshot), snapshotId: snapshot.snapshotId, generation: 1 }, privateKey: keys.privateKey });
      const upload = requests[1];
      expect(upload?.url).toBe('https://bridge.example/v1/snapshots');
      const uploadBody = JSON.parse(String(upload?.init.body)) as Record<string, unknown>;
      expect(uploadBody).toMatchObject({ deviceId: 'agent-test-opaque-id', vaultId: 'vault-test', snapshot });
      expect(uploadBody).toHaveProperty('timestamp');
      expect(uploadBody).toHaveProperty('nonce');
      expect(uploadBody).toHaveProperty('signature');
      expect(uploadBody).not.toHaveProperty('vaultRoot');
      expect(upload?.init.headers).not.toHaveProperty('x-bridge-signature');
      const verified = verifyCanonicalRequest({ method: 'POST', path: '/v1/snapshots', timestamp: uploadBody.timestamp as number, nonce: uploadBody.nonce as string, digest: snapshot.digest }, uploadBody.signature as string, createPublicKey({ key: publicDer, format: 'der', type: 'spki' }));
      expect(verified).toBe(true);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('uses the status query endpoint and rejects cross-origin redirects', async () => {
    const originalFetch = globalThis.fetch;
    const keys = generateDeviceKeypair();
    const publicKey = createPublicKey({ key: Buffer.from(keys.publicKey, 'base64url'), format: 'der', type: 'spki' });
    globalThis.fetch = vi.fn(async (input: URL | RequestInfo, init?: RequestInit) => {
      expect(String(input)).toBe('https://bridge.example/v1/status?vaultId=vault_test_opaque_id');
      expect(init?.redirect).toBe('error');
      const headers = new Headers(init?.headers);
      expect(headers.get('x-bridge-device-id')).toBe('agent-test-opaque-id');
      expect(headers.get('x-bridge-vault-id')).toBe('vault_test_opaque_id');
      const timestamp = Number(headers.get('x-bridge-timestamp'));
      const requestNonce = headers.get('x-bridge-nonce') || '';
      const signature = headers.get('x-bridge-signature') || '';
      expect(verifyCanonicalRequest({ method: 'GET', path: '/v1/status', timestamp, nonce: requestNonce, digest: sha256Base64Url('vault_test_opaque_id') }, signature, publicKey)).toBe(true);
      return new Response(JSON.stringify({ vaultId: 'vault_test_opaque_id', active: null, documentCount: 0 }), { status: 200 });
    });
    try {
      const status = await new HttpRemoteClient().status({ url: 'https://bridge.example', deviceId: 'agent-test-opaque-id', vaultId: 'vault_test_opaque_id', privateKey: keys.privateKey });
      expect(status.ok).toBe(true);
      expect(status.vaultId).toBe('vault_test_opaque_id');
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('uses an injected mTLS transport without exposing credentials in request URLs', async () => {
    const keys = generateDeviceKeypair();
    const calls: Array<{ path: string; hasTls: boolean }> = [];
    const provider: PublisherTlsCredentialProvider = {
      async get() {
        return { certificate: '-----BEGIN CERTIFICATE-----synthetic-----END CERTIFICATE-----', privateKey: '-----BEGIN PRIVATE KEY-----synthetic-----END PRIVATE KEY-----' };
      }
    };
    const executor: PublisherRequestExecutor = async (input) => {
      calls.push({ path: input.url.pathname, hasTls: Boolean(input.tls?.certificate && input.tls.privateKey) });
      return { statusCode: 200, headers: {}, body: JSON.stringify({ vaultId: 'vault_test_opaque_id', active: null, documentCount: 0 }) };
    };
    const client = new HttpRemoteClient(false, { credentialProvider: provider, requestExecutor: executor, requireMtls: true });
    const status = await client.status({ url: 'https://bridge.example', deviceId: 'agent-test-opaque-id', vaultId: 'vault_test_opaque_id', privateKey: keys.privateKey });
    expect(status.ok).toBe(true);
    expect(calls).toEqual([{ path: '/v1/status', hasTls: true }]);
  });
});
