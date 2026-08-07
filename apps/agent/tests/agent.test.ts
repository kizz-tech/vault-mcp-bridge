import { mkdir, mkdtemp, readFile, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it, beforeEach, afterEach } from 'vitest';
import { normalizeVaultId } from '@vault-mcp-bridge/contracts';
import { createAgentApp, toPreview } from '../src/app.js';
import { MAX_PENDING_REVOCATIONS } from '../src/config.js';
import { FileCredentialStore } from '../src/credentials.js';
import type { PublisherStatus, RemoteClient, ScanIssueReason, ScanOptions, ScanResult, VaultScanner } from '../src/types.js';

const csrf = (app: Awaited<ReturnType<typeof createAgentApp>>) => app.agentState.csrfToken;

class FakeScanner implements VaultScanner {
  incomplete = false;
  incompleteReason: ScanIssueReason = 'unstable';
  benignWarning = false;
  async scan(_root: string, _options: ScanOptions) {
    return {
      files: [{ relativePath: 'notes/hello.md', bytes: 12, content: '# Hello\n', contentType: 'markdown' }],
      excluded: [{ path: '.obsidian/workspace.json', reason: 'hidden' }, { path: 'secret.txt', reason: 'unsupported-file' }],
      hidden: 1,
      symlinks: 0,
      errors: this.incomplete ? [{ path: 'notes/hello.md', reason: this.incompleteReason, message: `synthetic scan issue: ${this.incompleteReason}` }] : [],
      ...(this.benignWarning ? { warnings: [{ path: 'notes/hello.md', message: 'Malformed frontmatter: YAML parse error' }] } : {}),
      bytes: 12,
    } satisfies ScanResult;
  }
}

class FakeRemote implements RemoteClient {
  pairCalls: Array<Record<string, unknown>> = [];
  uploadCalls: Array<{ input: Parameters<RemoteClient['upload']>[0]; body: string }> = [];
  statusCalls = 0;
  pairGate?: { promise: Promise<void> };
  statusGate?: { promise: Promise<PublisherStatus>; resolve: (value: PublisherStatus) => void };
  mismatchReceipt = false;
  pairCount = 0;
  async pair(input: Parameters<RemoteClient['pair']>[0]) {
    this.pairCalls.push(input);
    this.pairCount += 1;
    if (this.pairGate) await this.pairGate.promise;
    return { deviceId: `device-test-${this.pairCount}`, vaultId: input.vaultId || 'vault-test' };
  }
  async upload(input: Parameters<RemoteClient['upload']>[0]) {
    const snapshot = input.snapshot.snapshot as { digest: string; documents: unknown[] };
    const body = JSON.stringify({ vaultId: input.vaultId, snapshot });
    this.uploadCalls.push({ input, body });
    return { version: 1, accepted: true, idempotent: false, snapshotId: input.snapshot.snapshotId, vaultId: input.vaultId, generation: input.snapshot.generation, digest: this.mismatchReceipt ? 'wrong-digest' : snapshot.digest, documentCount: snapshot.documents.length, receivedAt: new Date().toISOString() };
  }
  async status() {
    this.statusCalls += 1;
    if (this.statusGate) return this.statusGate.promise;
    return { ok: true, checkedAt: new Date().toISOString(), vaultId: normalizeVaultId('vault-test'), freshnessSeconds: 3 };
  }
}

function deferred<T>(): { promise: Promise<T>; resolve: (value: T) => void } {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((resolver) => { resolve = resolver; });
  return { promise, resolve };
}

async function appFixture() {
  const dataDir = await mkdtemp(join(tmpdir(), 'vault-mcp-agent-'));
  const vaultRoot = await mkdtemp(join(tmpdir(), 'vault-mcp-fixture-'));
  await mkdir(join(vaultRoot, 'notes'), { recursive: true });
  await writeFile(join(vaultRoot, 'notes', 'hello.md'), '# Hello\n', 'utf8');
  await mkdir(join(vaultRoot, '.obsidian'), { recursive: true });
  await writeFile(join(vaultRoot, '.obsidian', 'workspace.json'), '{"secret":true}', 'utf8');
  const remote = new FakeRemote();
  const scanner = new FakeScanner();
  const app = await createAgentApp({ dataDir, scanVault: scanner, remoteClient: remote, allowLoopbackRemoteHttp: true });
  await app.ready();
  return { app, remote, scanner, dataDir, vaultRoot };
}

async function readyForSync(fixture: Awaited<ReturnType<typeof appFixture>>) {
  const headers = { host: '127.0.0.1:3210', 'x-bridge-csrf': csrf(fixture.app) };
  expect((await fixture.app.inject({ method: 'POST', url: '/api/config', headers, payload: { vaultRoot: fixture.vaultRoot, vaultId: 'vault-test', remoteServerUrl: 'https://bridge.example' } })).statusCode).toBe(200);
  expect((await fixture.app.inject({ method: 'POST', url: '/api/device/generate', headers, payload: {} })).statusCode).toBe(200);
  expect((await fixture.app.inject({ method: 'POST', url: '/api/pair', headers, payload: { code: 'PAIR-123' } })).statusCode).toBe(200);
  expect((await fixture.app.inject({ method: 'POST', url: '/api/preview', headers, payload: {} })).statusCode).toBe(200);
  return headers;
}

describe('local agent security and read-only flow', () => {
  let fixture: Awaited<ReturnType<typeof appFixture>>;
  beforeEach(async () => { fixture = await appFixture(); });
  afterEach(async () => { await fixture.app.close(); });

  it('serves a dashboard and bootstrap without exposing the private key', async () => {
    const page = await fixture.app.inject({ method: 'GET', url: '/', headers: { host: '127.0.0.1:3210' } });
    expect(page.statusCode).toBe(200);
    expect(page.body).toContain('READ ONLY');
    expect(page.headers['content-security-policy']).toContain("default-src 'self'");
    const response = await fixture.app.inject({ method: 'GET', url: '/api/bootstrap', headers: { host: '127.0.0.1:3210' } });
    expect(response.statusCode).toBe(200);
    expect(response.json()).not.toHaveProperty('privateKey');
    expect(response.json().config).toMatchObject({ syncIntervalMinutes: 0 });
  });

  it('requires loopback host, same origin, and a per-process CSRF token for writes', async () => {
    const noCsrf = await fixture.app.inject({ method: 'POST', url: '/api/config', headers: { host: '127.0.0.1:3210' }, payload: { vaultId: 'vault-test' } });
    expect(noCsrf.statusCode).toBe(403);
    const wrongOrigin = await fixture.app.inject({ method: 'POST', url: '/api/config', headers: { host: '127.0.0.1:3210', origin: 'https://evil.invalid', 'x-bridge-csrf': csrf(fixture.app) }, payload: { vaultId: 'vault-test' } });
    expect(wrongOrigin.statusCode).toBe(403);
    const external = await fixture.app.inject({ method: 'POST', url: '/api/config', headers: { host: '203.0.113.4:3210', 'x-bridge-csrf': csrf(fixture.app) }, payload: { vaultId: 'vault-test' } });
    expect(external.statusCode).toBe(403);
  });

  it('validates remote URL as HTTPS except explicit loopback development', async () => {
    const response = await fixture.app.inject({ method: 'POST', url: '/api/config', headers: { host: 'localhost:3210', 'x-bridge-csrf': csrf(fixture.app) }, payload: { remoteServerUrl: 'http://remote.invalid' } });
    expect(response.statusCode).toBe(400);
    const allowed = await fixture.app.inject({ method: 'POST', url: '/api/config', headers: { host: 'localhost:3210', 'x-bridge-csrf': csrf(fixture.app) }, payload: { remoteServerUrl: 'http://127.0.0.1:9999' } });
    expect(allowed.statusCode).toBe(200);
  });

  it('drops unknown credential-like config fields instead of persisting or returning them', async () => {
    const response = await fixture.app.inject({ method: 'POST', url: '/api/config', headers: { host: 'localhost:3210', 'x-bridge-csrf': csrf(fixture.app) }, payload: { vaultId: 'vault-test', privateKey: 'TEST_PRIVATE_KEY_VALUE', token: 'TEST_TOKEN_VALUE' } });
    expect(response.statusCode).toBe(200);
    expect(response.body).not.toContain('TEST_PRIVATE_KEY_VALUE');
    const persisted = await readFile(join(fixture.dataDir, 'config.json'), 'utf8');
    expect(persisted).not.toContain('TEST_PRIVATE_KEY_VALUE');
    expect(persisted).not.toContain('synthetic-token');
  });

  it('schedules outbound sync only when an explicit interval is configured', async () => {
    const headers = { host: 'localhost:3210', 'x-bridge-csrf': csrf(fixture.app) };
    const enabled = await fixture.app.inject({ method: 'POST', url: '/api/config', headers, payload: { syncIntervalMinutes: 1 } });
    expect(enabled.statusCode).toBe(200);
    expect(fixture.app.agentState.syncTimer).toBeDefined();
    const disabled = await fixture.app.inject({ method: 'POST', url: '/api/config', headers, payload: { syncIntervalMinutes: 0 } });
    expect(disabled.statusCode).toBe(200);
    expect(fixture.app.agentState.syncTimer).toBeUndefined();
  });

  it('previews a synthetic vault and returns only bounded exclusion metadata', async () => {
    const response = await fixture.app.inject({ method: 'POST', url: '/api/preview', headers: { host: '127.0.0.1:3210', 'x-bridge-csrf': csrf(fixture.app) }, payload: { vaultRoot: fixture.vaultRoot, vaultId: 'vault-test' } });
    expect(response.statusCode).toBe(200);
    const result = response.json().preview;
    expect(result.documents).toBe(1);
    expect(result.hidden).toBe(1);
    expect(JSON.stringify(result)).not.toContain(fixture.vaultRoot);
    expect(JSON.stringify(result)).not.toContain('# Hello');
  });

  it('generates a file credential with restrictive permissions but never returns the private key', async () => {
    const response = await fixture.app.inject({ method: 'POST', url: '/api/device/generate', headers: { host: '127.0.0.1:3210', 'x-bridge-csrf': csrf(fixture.app) }, payload: {} });
    expect(response.statusCode).toBe(200);
    expect(response.json()).not.toHaveProperty('privateKey');
    const credentials = await stat(join(fixture.dataDir, 'credentials.json'));
    expect(credentials.mode & 0o777).toBe(0o600);
    const raw = await readFile(join(fixture.dataDir, 'credentials.json'), 'utf8');
    expect(raw).toContain('privateKey');
    const bootstrap = await fixture.app.inject({ method: 'GET', url: '/api/bootstrap', headers: { host: '127.0.0.1:3210' } });
    expect(bootstrap.body).not.toContain(raw.match(/-----BEGIN PRIVATE KEY-----[\s\S]+?-----END PRIVATE KEY-----/)?.[0] || 'unavailable-key');
    const accidentalRotation = await fixture.app.inject({ method: 'POST', url: '/api/device/generate', headers: { host: '127.0.0.1:3210', 'x-bridge-csrf': csrf(fixture.app) }, payload: {} });
    expect(accidentalRotation.statusCode).toBe(409);
  });

  it('pairs and uploads without sending the local vault root', async () => {
    const headers = { host: '127.0.0.1:3210', 'x-bridge-csrf': csrf(fixture.app) };
    await fixture.app.inject({ method: 'POST', url: '/api/config', headers, payload: { vaultRoot: fixture.vaultRoot, vaultId: 'vault-test', remoteServerUrl: 'https://bridge.example' } });
    await fixture.app.inject({ method: 'POST', url: '/api/device/generate', headers, payload: {} });
    const pair = await fixture.app.inject({ method: 'POST', url: '/api/pair', headers, payload: { code: 'PAIR-123' } });
    expect(pair.statusCode).toBe(200);
    expect(JSON.stringify(fixture.remote.pairCalls[0])).not.toContain(fixture.vaultRoot);
    const preview = await fixture.app.inject({ method: 'POST', url: '/api/preview', headers, payload: {} });
    expect(preview.statusCode).toBe(200);
    const uploadBeforePreview = await fixture.app.inject({ method: 'POST', url: '/api/sync', headers, payload: {} });
    expect(uploadBeforePreview.statusCode).toBe(200);
    expect(fixture.remote.uploadCalls).toHaveLength(1);
    expect(fixture.remote.uploadCalls[0]?.body).not.toContain(fixture.vaultRoot);
    expect(fixture.remote.uploadCalls[0]?.body).not.toContain('privateKey');
  });

  it('serializes pairing with rotation and config until the remote response commits', async () => {
    const headers = { host: '127.0.0.1:3210', 'x-bridge-csrf': csrf(fixture.app) };
    await fixture.app.inject({ method: 'POST', url: '/api/config', headers, payload: { vaultRoot: fixture.vaultRoot, vaultId: 'vault-test', remoteServerUrl: 'https://bridge.example' } });
    await fixture.app.inject({ method: 'POST', url: '/api/device/generate', headers, payload: {} });
    const localPublicKey = fixture.app.agentState.deviceIdentity?.publicKey;
    const gate = deferred<void>();
    fixture.remote.pairGate = gate;
    const pairPromise = fixture.app.inject({ method: 'POST', url: '/api/pair', headers, payload: { code: 'PAIR-DEFERRED' } });
    for (let attempt = 0; attempt < 20 && fixture.app.agentState.controlOperation?.kind !== 'pair'; attempt += 1) await new Promise<void>((resolve) => setImmediate(resolve));
    expect(fixture.app.agentState.controlOperation?.kind).toBe('pair');
    const rotate = await fixture.app.inject({ method: 'POST', url: '/api/device/generate', headers, payload: { rotate: true } });
    const config = await fixture.app.inject({ method: 'POST', url: '/api/config', headers, payload: { label: 'must-not-commit-during-pair' } });
    expect(rotate.statusCode).toBe(409);
    expect(rotate.json().error).toBe('operation_in_progress');
    expect(config.statusCode).toBe(409);
    expect(config.json().error).toBe('operation_in_progress');
    gate.resolve();
    const paired = await pairPromise;
    expect(paired.statusCode).toBe(200);
    expect(fixture.remote.pairCalls[0]?.publicKey).toBe(localPublicKey);
    expect(fixture.app.agentState.deviceIdentity?.publicKey).toBe(localPublicKey);
    expect(fixture.app.agentState.pairing.publicKey).toBe(localPublicKey);
    expect(fixture.app.agentState.pairing.deviceId).toBe('device-test-1');
    expect(fixture.app.agentState.config.label).not.toBe('must-not-commit-during-pair');
    expect(fixture.app.agentState.controlOperation).toBeUndefined();
  });

  it('captures an immutable sync context and rejects concurrent mutations', async () => {
    const headers = await readyForSync(fixture);
    const gate = deferred<PublisherStatus>();
    fixture.remote.statusGate = gate;
    const syncPromise = fixture.app.inject({ method: 'POST', url: '/api/sync', headers, payload: {} });
    for (let attempt = 0; attempt < 20 && !fixture.app.agentState.syncInFlight; attempt += 1) await new Promise<void>((resolve) => setImmediate(resolve));
    expect(fixture.app.agentState.syncInFlight).toBe(true);
    const config = await fixture.app.inject({ method: 'POST', url: '/api/config', headers, payload: { include: ['**/*.md'] } });
    const preview = await fixture.app.inject({ method: 'POST', url: '/api/preview', headers, payload: {} });
    const pair = await fixture.app.inject({ method: 'POST', url: '/api/pair', headers, payload: { code: 'PAIR-456' } });
    const identity = await fixture.app.inject({ method: 'POST', url: '/api/device/generate', headers, payload: { rotate: true } });
    expect(config.statusCode).toBe(409);
    expect(preview.statusCode).toBe(409);
    expect(pair.statusCode).toBe(409);
    expect(identity.statusCode).toBe(409);
    gate.resolve({ ok: true, checkedAt: new Date().toISOString(), vaultId: normalizeVaultId('vault-test'), freshnessSeconds: 3 });
    const sync = await syncPromise;
    expect(sync.statusCode).toBe(200);
    expect(fixture.app.agentState.syncInFlight).toBe(false);
  });

  it('invalidates the preview digest when export policy changes and blocks sync until re-preview', async () => {
    const headers = await readyForSync(fixture);
    const before = await fixture.app.inject({ method: 'GET', url: '/api/status', headers: { host: '127.0.0.1:3210' } });
    expect(before.json().status.previewValid).toBe(true);
    const changed = await fixture.app.inject({ method: 'POST', url: '/api/config', headers, payload: { exclude: ['private/**'] } });
    expect(changed.statusCode).toBe(200);
    expect(changed.json().status.previewValid).toBe(false);
    const blocked = await fixture.app.inject({ method: 'POST', url: '/api/sync', headers, payload: {} });
    expect(blocked.statusCode).toBe(400);
    expect(blocked.json().error).toBe('preview_required');
    const refreshed = await fixture.app.inject({ method: 'POST', url: '/api/preview', headers, payload: {} });
    expect(refreshed.statusCode).toBe(200);
    const after = await fixture.app.inject({ method: 'GET', url: '/api/status', headers: { host: '127.0.0.1:3210' } });
    expect(after.json().status.previewValid).toBe(true);
  });

  it('rejects an upload receipt that does not match the immutable snapshot', async () => {
    const headers = await readyForSync(fixture);
    fixture.remote.mismatchReceipt = true;
    const response = await fixture.app.inject({ method: 'POST', url: '/api/sync', headers, payload: {} });
    expect(response.statusCode).toBe(502);
    expect(response.json().error).toBe('receipt_mismatch');
    expect(fixture.app.agentState.runtime.lastReceipt).toBeUndefined();
  });

  it('shows benign parse warnings but fails closed on a transient incomplete scan', async () => {
    const headers = await readyForSync(fixture);
    fixture.scanner.benignWarning = true;
    const benign = await fixture.app.inject({ method: 'POST', url: '/api/preview', headers, payload: {} });
    expect(benign.statusCode).toBe(200);
    expect(benign.json().preview.incomplete).toBe(false);
    expect(benign.json().preview.warnings).toHaveLength(1);
    const first = await fixture.app.inject({ method: 'POST', url: '/api/sync', headers, payload: {} });
    expect(first.statusCode).toBe(200);
    const lastGoodReceipt = fixture.app.agentState.runtime.lastReceipt;
    fixture.scanner.incomplete = true;
    const failed = await fixture.app.inject({ method: 'POST', url: '/api/sync', headers, payload: {} });
    expect(failed.statusCode).toBe(409);
    expect(failed.json().error).toBe('scan_incomplete');
    expect(fixture.remote.uploadCalls).toHaveLength(1);
    expect(fixture.app.agentState.runtime.lastReceipt).toEqual(lastGoodReceipt);
    expect(fixture.app.agentState.runtime.lastPreview?.incomplete).toBe(true);
    expect((await fixture.app.inject({ method: 'GET', url: '/api/status', headers: { host: '127.0.0.1:3210' } })).json().status.previewValid).toBe(false);
  });

  it.each(['file-limit', 'file-too-large', 'total-bytes-limit'] as const)('does not upload when the scanner reports %s', async (reason) => {
    const headers = await readyForSync(fixture);
    fixture.scanner.incomplete = true;
    fixture.scanner.incompleteReason = reason;
    const failed = await fixture.app.inject({ method: 'POST', url: '/api/sync', headers, payload: {} });
    expect(failed.statusCode).toBe(409);
    expect(failed.json().error).toBe('scan_incomplete');
    expect(fixture.remote.uploadCalls).toHaveLength(0);
    expect(fixture.app.agentState.runtime.lastPreview?.incomplete).toBe(true);
    fixture.scanner.incomplete = false;
    const policyOnlyPreview = await fixture.app.inject({ method: 'POST', url: '/api/preview', headers, payload: {} });
    expect(policyOnlyPreview.statusCode).toBe(200);
    const policyOnlySync = await fixture.app.inject({ method: 'POST', url: '/api/sync', headers, payload: {} });
    expect(policyOnlySync.statusCode).toBe(200);
    expect(fixture.remote.uploadCalls).toHaveLength(1);
  });

  it('preserves the old device id as a pending revocation during rotation', async () => {
    const headers = await readyForSync(fixture);
    const oldDeviceId = fixture.app.agentState.pairing.deviceId;
    const response = await fixture.app.inject({ method: 'POST', url: '/api/device/generate', headers, payload: { rotate: true } });
    expect(response.statusCode).toBe(200);
    const status = await fixture.app.inject({ method: 'GET', url: '/api/status', headers: { host: '127.0.0.1:3210' } });
    expect(status.json().status.pendingRevocations[0].deviceId).toBe(oldDeviceId);
    expect(status.json().status.pairingConfigured).toBe(false);
    expect(status.json().status.previewValid).toBe(false);
  });

  it('retains every old device id across repeated rotations', async () => {
    const headers = await readyForSync(fixture);
    const firstDeviceId = fixture.app.agentState.pairing.deviceId;
    expect((await fixture.app.inject({ method: 'POST', url: '/api/device/generate', headers, payload: { rotate: true } })).statusCode).toBe(200);
    expect((await fixture.app.inject({ method: 'POST', url: '/api/pair', headers, payload: { code: 'PAIR-456' } })).statusCode).toBe(200);
    const secondDeviceId = fixture.app.agentState.pairing.deviceId;
    expect(secondDeviceId).not.toBe(firstDeviceId);
    expect((await fixture.app.inject({ method: 'POST', url: '/api/device/generate', headers, payload: { rotate: true } })).statusCode).toBe(200);
    const status = await fixture.app.inject({ method: 'GET', url: '/api/status', headers: { host: '127.0.0.1:3210' } });
    const pendingIds = status.json().status.pendingRevocations.map((record: { deviceId: string }) => record.deviceId);
    expect(pendingIds).toEqual([secondDeviceId, firstDeviceId]);
  });

  it('rejects rotation at pending revocation capacity before replacing credentials', async () => {
    const headers = await readyForSync(fixture);
    const beforeIdentity = fixture.app.agentState.deviceIdentity;
    const beforePrivateKey = await fixture.app.agentState.credentialStore.getPrivateKey();
    const beforeDeviceId = fixture.app.agentState.pairing.deviceId;
    const pendingRevocations = Array.from({ length: MAX_PENDING_REVOCATIONS }, (_, index) => ({
      deviceId: `synthetic-old-device-${index}`,
      agentId: `synthetic-old-agent-${index}`,
      publicKey: `synthetic-old-public-key-${index}`,
      createdAt: new Date(index).toISOString(),
      status: 'pending' as const,
    }));
    fixture.app.agentState.runtime.pendingRevocations = pendingRevocations;
    const response = await fixture.app.inject({ method: 'POST', url: '/api/device/generate', headers, payload: { rotate: true } });
    expect(response.statusCode).toBe(409);
    expect(response.json().error).toBe('pending_revocations_limit');
    expect(fixture.app.agentState.deviceIdentity).toEqual(beforeIdentity);
    expect(await fixture.app.agentState.credentialStore.getPrivateKey()).toBe(beforePrivateKey);
    expect(fixture.app.agentState.pairing.deviceId).toBe(beforeDeviceId);
    expect(fixture.app.agentState.runtime.pendingRevocations).toEqual(pendingRevocations);
  });

  it('deduplicates an already-pending current device at capacity without evicting another record', async () => {
    const headers = await readyForSync(fixture);
    const currentDeviceId = fixture.app.agentState.pairing.deviceId!;
    const currentAgentId = fixture.app.agentState.config.agentId!;
    const currentPublicKey = fixture.app.agentState.deviceIdentity!.publicKey;
    const currentRecord = { deviceId: currentDeviceId, agentId: currentAgentId, publicKey: currentPublicKey, createdAt: new Date(0).toISOString(), status: 'pending' as const };
    const pendingRevocations = [
      currentRecord,
      ...Array.from({ length: MAX_PENDING_REVOCATIONS - 1 }, (_, index) => ({
        deviceId: `synthetic-old-device-${index}`,
        agentId: `synthetic-old-agent-${index}`,
        publicKey: `synthetic-old-public-key-${index}`,
        createdAt: new Date(index + 1).toISOString(),
        status: 'pending' as const,
      })),
    ];
    fixture.app.agentState.runtime.pendingRevocations = [...pendingRevocations, currentRecord];
    const response = await fixture.app.inject({ method: 'POST', url: '/api/device/generate', headers, payload: { rotate: true } });
    expect(response.statusCode).toBe(200);
    expect(fixture.app.agentState.runtime.pendingRevocations).toHaveLength(MAX_PENDING_REVOCATIONS);
    expect(fixture.app.agentState.runtime.pendingRevocations?.filter((record) => record.deviceId === currentDeviceId)).toHaveLength(1);
    expect(fixture.app.agentState.runtime.pendingRevocations?.map((record) => record.deviceId)).toContain(currentDeviceId);
  });

  it('rejects unsafe wildcard paths from static routes', async () => {
    const response = await fixture.app.inject({ method: 'GET', url: '/../../etc/passwd', headers: { host: 'localhost:3210' } });
    expect(response.statusCode).toBe(404);
  });
});

describe('file credential seam', () => {
  it('stores private material outside the vault and keeps mode 0600', async () => {
    const dataDir = await mkdtemp(join(tmpdir(), 'vault-mcp-credentials-'));
    const store = new FileCredentialStore(dataDir);
    await store.savePrivateKey('synthetic-private-key');
    expect(await store.getPrivateKey()).toBe('synthetic-private-key');
    const file = await stat(join(dataDir, 'credentials.json'));
    expect(file.mode & 0o777).toBe(0o600);
  });

  it('persists the opaque-id HMAC key across identity updates and restarts', async () => {
    const dataDir = await mkdtemp(join(tmpdir(), 'vault-mcp-id-key-'));
    const first = new FileCredentialStore(dataDir);
    const idKey = await first.getOrCreateIdKey();
    await first.saveIdentity('synthetic-private-key', 'synthetic-public-key', new Date(0).toISOString());

    const restarted = new FileCredentialStore(dataDir);
    expect(await restarted.getOrCreateIdKey()).toBe(idKey);
    await restarted.deletePrivateKey();
    expect(await restarted.getOrCreateIdKey()).toBe(idKey);
    expect(await restarted.getPrivateKey()).toBeUndefined();
  });

  it('migrates the legacy single pending revocation record into the bounded array', async () => {
    const dataDir = await mkdtemp(join(tmpdir(), 'vault-mcp-legacy-revocation-'));
    await writeFile(join(dataDir, 'runtime.json'), JSON.stringify({
      startedAt: new Date(0).toISOString(),
      pendingRevocation: { deviceId: 'legacy-device-id', agentId: 'legacy-agent-id', publicKey: 'legacy-public-key', createdAt: new Date(0).toISOString(), status: 'pending' }
    }), 'utf8');
    const app = await createAgentApp({ dataDir, scanVault: new FakeScanner(), remoteClient: new FakeRemote(), allowLoopbackRemoteHttp: true });
    await app.ready();
    const status = await app.inject({ method: 'GET', url: '/api/status', headers: { host: '127.0.0.1:3210' } });
    expect(status.json().status.pendingRevocations).toEqual([{ deviceId: 'legacy-device-id', agentId: 'legacy-agent-id', createdAt: new Date(0).toISOString(), status: 'pending' }]);
    const migrated = JSON.parse(await readFile(join(dataDir, 'runtime.json'), 'utf8')) as Record<string, unknown>;
    expect(migrated).not.toHaveProperty('pendingRevocation');
    expect(migrated.pendingRevocations).toHaveLength(1);
    await app.close();
  });
});

describe('preview bounds', () => {
  it('reports totals and explicit omitted counts when local lists are capped', () => {
    const scan: ScanResult = {
      files: Array.from({ length: 205 }, (_, index) => ({ relativePath: `notes/${index}.md`, bytes: 1, content: 'x', contentType: 'markdown' as const })),
      excluded: Array.from({ length: 207 }, (_, index) => ({ path: `.hidden/${index}`, reason: 'hidden' })),
      hidden: 207,
      symlinks: 0,
      errors: [],
      bytes: 205,
    };
    const preview = toPreview(scan, 'synthetic-policy-digest');
    expect(preview.included).toHaveLength(200);
    expect(preview.includedTotal).toBe(205);
    expect(preview.includedOmitted).toBe(5);
    expect(preview.exclusions).toHaveLength(200);
    expect(preview.excludedTotal).toBe(207);
    expect(preview.excludedOmitted).toBe(7);
  });
});
