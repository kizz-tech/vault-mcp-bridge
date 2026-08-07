import { randomBytes, randomUUID } from 'node:crypto';
import { existsSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { join, resolve } from 'node:path';
import Fastify, { type FastifyInstance, type FastifyReply, type FastifyRequest } from 'fastify';
import { CONTRACT_VERSION, computeSnapshotDigest, normalizeVaultId, sha256Base64Url } from '@vault-mcp-bridge/contracts';
import { loadConfig, loadRuntime, resolveDataDir, saveConfig, saveRuntime, validateConfig, MAX_PENDING_REVOCATIONS } from './config.js';
import { FileCredentialStore } from './credentials.js';
import { generateDeviceKeypair, HttpRemoteClient } from './remote-client.js';
import { DefaultVaultScanner } from './scanner.js';
import { allowedRemoteUrl, isLoopbackHost, newCsrfToken, safeEqual } from './security.js';
import type { AgentConfig, AgentDeps, CredentialStore, DeviceIdentity, PairingState, PendingRevocation, PreviewResult, PublicStatus, PublisherStatus, RuntimeState, ScanIssue, ScanOptions, ScanResult, SnapshotPayload } from './types.js';

export interface CreateAgentAppOptions extends AgentDeps {
  dataDir?: string;
  staticDir?: string;
  unsafeDevelopmentHost?: boolean;
  allowLoopbackRemoteHttp?: boolean;
  logger?: boolean;
}

export interface AgentApp extends FastifyInstance {
  agentState: AgentState;
}

export interface AgentState {
  dataDir: string;
  csrfToken: string;
  unsafeDevelopmentHost: boolean;
  allowLoopbackRemoteHttp: boolean;
  config: AgentConfig;
  runtime: RuntimeState;
  pairing: PairingState;
  credentialStore: CredentialStore;
  deviceIdentity?: DeviceIdentity;
  scanner: NonNullable<AgentDeps['scanVault']>;
  remoteClient: NonNullable<AgentDeps['remoteClient']>;
  now: () => Date;
  syncInFlight: boolean;
  controlOperation?: { kind: ControlOperationKind };
  syncTimer?: NodeJS.Timeout;
}

type ControlOperationKind = 'config' | 'preview' | 'device-generate' | 'pair' | 'sync' | 'publisher-status';

interface SyncContext {
  vaultRoot: string;
  remoteServerUrl: string;
  vaultId: string;
  include: string[];
  exclude: string[];
  agentId: string;
  deviceId: string;
  policyDigest: string;
}

const WRITE_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);
const WRITE_PATHS = new Set(['/api/config', '/api/preview', '/api/device/generate', '/api/pair', '/api/sync', '/api/publisher/status']);
const CONTROL_OPERATION_PATHS = new Set(['/api/config', '/api/preview', '/api/device/generate', '/api/pair', '/api/sync', '/api/publisher/status']);
const MAX_JSON_BYTES = 128 * 1024;
const CONFIG_KEYS: Array<keyof AgentConfig> = ['vaultRoot', 'include', 'exclude', 'remoteServerUrl', 'vaultId', 'syncIntervalMinutes', 'label'];

function requestPath(request: FastifyRequest): string {
  return request.url.split('?')[0] || '/';
}

function bodyObject(request: FastifyRequest): Record<string, unknown> {
  if (!request.body || typeof request.body !== 'object' || Array.isArray(request.body)) return {};
  return request.body as Record<string, unknown>;
}

function configWithPatch(base: AgentConfig, body: Record<string, unknown>): AgentConfig {
  const next: AgentConfig = { ...base };
  for (const key of CONFIG_KEYS) {
    if (Object.prototype.hasOwnProperty.call(body, key)) {
      (next as Record<string, unknown>)[key] = body[key];
    }
  }
  return next;
}

function scanOptions(config: AgentConfig): ScanOptions {
  return {
    ...(config.include ? { include: config.include } : {}),
    ...(config.exclude ? { exclude: config.exclude } : {}),
    ...(config.vaultId ? { vaultId: protocolVaultId(config.vaultId) } : {}),
  };
}

function policyDigest(config: AgentConfig): string {
  return sha256Base64Url(JSON.stringify({
    vaultRoot: config.vaultRoot || '',
    remoteServerUrl: config.remoteServerUrl || '',
    vaultId: config.vaultId ? protocolVaultId(config.vaultId) : '',
    include: [...(config.include || [])],
    exclude: [...(config.exclude || [])],
  }));
}

function captureSyncContext(state: AgentState): SyncContext {
  if (!state.config.vaultRoot || !state.config.remoteServerUrl || !state.config.vaultId) throw new Error('vault_remote_and_id_required');
  if (!state.deviceIdentity || !state.config.agentId || !state.pairing.deviceId) throw new Error('device_identity_required');
  const contextBase = {
    vaultRoot: state.config.vaultRoot,
    remoteServerUrl: state.config.remoteServerUrl,
    vaultId: state.config.vaultId,
    include: [...(state.config.include || [])],
    exclude: [...(state.config.exclude || [])],
    agentId: state.config.agentId,
    deviceId: state.pairing.deviceId,
  };
  return { ...contextBase, policyDigest: policyDigest(state.config) };
}

function previewMatchesContext(state: AgentState, context: SyncContext): boolean {
  return Boolean(state.runtime.lastPreview && !state.runtime.lastPreview.incomplete && state.runtime.lastPreview.policyDigest === context.policyDigest);
}

function acquireControlOperation(state: AgentState, kind: ControlOperationKind): boolean {
  if (state.controlOperation) return false;
  state.controlOperation = { kind };
  return true;
}

function releaseControlOperation(state: AgentState, kind: ControlOperationKind): void {
  if (state.controlOperation?.kind === kind) delete state.controlOperation;
}

function rejectControlOperation(state: AgentState, request: FastifyRequest, reply: FastifyReply): boolean {
  const path = requestPath(request);
  if (!CONTROL_OPERATION_PATHS.has(path)) return false;
  const operation = state.controlOperation;
  if (!operation && !state.syncInFlight) return false;
  const error = path === '/api/sync' && (operation?.kind === 'sync' || state.syncInFlight)
    ? 'sync_already_running'
    : 'operation_in_progress';
  void reply.code(409).send({ error });
  return true;
}

function receiptMatches(receipt: unknown, payload: SnapshotPayload, vaultId: string): boolean {
  if (!receipt || typeof receipt !== 'object') return false;
  const candidate = receipt as Record<string, unknown>;
  const snapshot = payload.snapshot as Record<string, unknown>;
  return candidate.accepted === true
    && candidate.snapshotId === payload.snapshotId
    && candidate.vaultId === vaultId
    && candidate.generation === payload.generation
    && candidate.digest === snapshot.digest;
}

function scanIsIncomplete(scan: ScanResult): boolean {
  return scan.errors.length > 0;
}

function safeErrorMessage(error: unknown): string {
  const raw = error instanceof Error ? error.message : String(error);
  return raw
    .replace(/(?:[A-Za-z]:)?[\\/](?:Users|home|private|tmp)[\\/][^\s"']+/gi, '[local path]')
    .replace(/(?:pairing code|x-bridge-signature|private key)\s*[:=]\s*[^\s,;]+/gi, '$1=[redacted]')
    .slice(0, 400);
}

function publicIdentity(identity?: DeviceIdentity): Pick<DeviceIdentity, 'publicKey' | 'keyAlgorithm' | 'createdAt'> | undefined {
  return identity ? { publicKey: identity.publicKey, keyAlgorithm: identity.keyAlgorithm, createdAt: identity.createdAt } : undefined;
}

function publicStatus(state: AgentState): PublicStatus {
  const currentPolicyDigest = policyDigest(state.config);
  const previewValid = Boolean(state.runtime.lastPreview && !state.runtime.lastPreview.incomplete && state.runtime.lastPreview.policyDigest === currentPolicyDigest);
  const pendingRevocations = state.runtime.pendingRevocations?.length
    ? state.runtime.pendingRevocations
    : state.runtime.pendingRevocation
      ? [state.runtime.pendingRevocation]
      : [];
  return {
    readOnly: true,
    configured: Boolean(state.config.vaultRoot && state.config.remoteServerUrl && state.config.vaultId),
    vaultConfigured: Boolean(state.config.vaultRoot),
    remoteConfigured: Boolean(state.config.remoteServerUrl),
    pairingConfigured: state.pairing.paired,
    credentialStore: state.credentialStore.kind,
    dataDir: state.dataDir,
    ...(state.config.vaultId ? { vaultId: state.config.vaultId } : {}),
    vaultRootConfigured: Boolean(state.config.vaultRoot),
    ...(state.runtime.lastScanAt ? { lastScanAt: state.runtime.lastScanAt } : {}),
    ...(state.runtime.lastUploadAt ? { lastUploadAt: state.runtime.lastUploadAt } : {}),
    ...(state.runtime.lastReceipt ? { lastReceipt: state.runtime.lastReceipt } : {}),
    ...(state.runtime.lastPreview ? { lastPreview: state.runtime.lastPreview } : {}),
    ...(state.runtime.lastPublisherStatus ? { lastPublisherStatus: state.runtime.lastPublisherStatus } : {}),
    ...(state.runtime.lastError ? { lastError: state.runtime.lastError } : {}),
    intervalSyncEnabled: Number(state.config.syncIntervalMinutes || 0) > 0,
    previewValid,
    ...(pendingRevocations.length ? { pendingRevocations: pendingRevocations.slice(0, MAX_PENDING_REVOCATIONS).map((record) => ({ deviceId: record.deviceId, agentId: record.agentId, createdAt: record.createdAt, status: record.status })) } : {}),
  };
}

function dashboardConfig(config: AgentConfig): AgentConfig {
  return {
    ...(config.vaultRoot ? { vaultRoot: config.vaultRoot } : {}),
    ...(config.remoteServerUrl ? { remoteServerUrl: config.remoteServerUrl } : {}),
    ...(config.vaultId ? { vaultId: config.vaultId } : {}),
    ...(config.include ? { include: [...config.include] } : {}),
    ...(config.exclude ? { exclude: [...config.exclude] } : {}),
    ...(config.syncIntervalMinutes !== undefined ? { syncIntervalMinutes: config.syncIntervalMinutes } : {}),
    ...(config.label ? { label: config.label } : {}),
  };
}

function expectedOrigin(request: FastifyRequest): string | undefined {
  const host = request.headers.host;
  if (!host) return undefined;
  const protocol = (request.headers['x-forwarded-proto'] || 'http').toString().split(',')[0]?.trim() || 'http';
  return `${protocol}://${host}`;
}

function originAllowed(request: FastifyRequest): boolean {
  const origin = request.headers.origin;
  if (!origin) return true;
  const expected = expectedOrigin(request);
  return Boolean(expected && origin === expected);
}

async function readStaticFile(staticDir: string, pathName: string): Promise<{ body: Buffer; contentType: string } | undefined> {
  const relative = pathName === '/' ? 'index.html' : pathName.replace(/^\/+/, '');
  if (!relative || relative.includes('..') || relative.includes('\\') || relative.length > 160) return undefined;
  const path = join(staticDir, relative);
  const contentType = relative.endsWith('.html') ? 'text/html; charset=utf-8' : relative.endsWith('.css') ? 'text/css; charset=utf-8' : relative.endsWith('.js') ? 'text/javascript; charset=utf-8' : 'application/octet-stream';
  try { return { body: await readFile(path), contentType }; } catch { return undefined; }
}

function defaultStaticDir(): string {
  const candidates = [
    join(process.cwd(), 'public'),
    fileURLToPath(new URL('../public/', import.meta.url)),
    fileURLToPath(new URL('../../public/', import.meta.url))
  ];
  return candidates.find((candidate) => existsSync(join(candidate, 'index.html'))) || candidates[0]!;
}

function toPreview(scan: ScanResult, digest = ''): PreviewResult {
  const includedTotal = scan.files.length;
  const excludedTotal = scan.excluded.length;
  const incompleteErrors: ScanIssue[] = scan.errors.slice(0, 100);
  return {
    files: scan.files.length,
    documents: scan.files.length,
    bytes: scan.bytes,
    excluded: scan.excluded.length,
    exclusions: scan.excluded.slice(0, 200),
    hidden: scan.hidden,
    symlinks: scan.symlinks,
    errors: incompleteErrors,
    included: scan.files.slice(0, 200).map((file) => ({ path: file.relativePath, bytes: file.bytes })),
    policyDigest: digest,
    includedTotal,
    includedOmitted: Math.max(0, includedTotal - 200),
    excludedTotal,
    excludedOmitted: Math.max(0, excludedTotal - 200),
    incomplete: scanIsIncomplete(scan),
    incompleteErrors,
    warnings: (scan.warnings || []).slice(0, 100),
  };
}

function fallbackSnapshot(scan: ScanResult, vaultId: string, generation: number, createdAt: string): SnapshotPayload {
  const documents = scan.files.map((file) => ({
    id: file.id ?? sha256Base64Url(`vault-document:v1:${file.relativePath}`),
    title: file.title ?? (file.relativePath.split('/').pop()?.replace(/\.md$/i, '') || 'Untitled'),
    mediaType: file.contentType === 'markdown' ? 'text/markdown' as const : file.contentType === 'canvas' ? 'application/vnd.obsidian.canvas+json' as const : 'application/vnd.obsidian.base+yaml' as const,
    text: file.content,
    sourceHash: file.sha256 || sha256Base64Url(file.content),
    modifiedAt: file.modifiedAt ?? createdAt,
    ...(file.metadata ? { metadata: file.metadata } : {}),
  }));
  const snapshotId = randomUUID();
  const base = { version: CONTRACT_VERSION, snapshotId, vaultId, generation, createdAt, documents };
  const snapshot = { ...base, digest: computeSnapshotDigest(base) };
  return { snapshot, body: JSON.stringify(snapshot), snapshotId, generation };
}

function protocolVaultId(value: string): string {
  return normalizeVaultId(value);
}

async function makeSnapshot(scan: ScanResult, vaultId: string, generation: number, createdAt: string): Promise<SnapshotPayload> {
  const safeVaultId = protocolVaultId(vaultId);
  return fallbackSnapshot(scan, safeVaultId, generation, createdAt);
}

async function persist(state: AgentState): Promise<void> {
  await saveConfig(state.dataDir, state.config);
  await saveRuntime(state.dataDir, state.runtime);
}

async function performSync(state: AgentState): Promise<{ receipt: unknown; preview: PreviewResult; snapshotId: string }> {
  if (state.syncInFlight) throw new Error('sync_already_running');
  if (!acquireControlOperation(state, 'sync')) throw new Error('operation_in_progress');
  state.syncInFlight = true;
  try {
    const context = captureSyncContext(state);
    if (!previewMatchesContext(state, context)) throw new Error('preview_required');
    const privateKey = await state.credentialStore.getPrivateKey();
    if (!privateKey) throw new Error('device_identity_required');
    const protocolId = protocolVaultId(context.vaultId);
    const publisherStatus = await state.remoteClient.status({ url: context.remoteServerUrl, deviceId: context.deviceId, vaultId: protocolId, privateKey });
    state.runtime.lastPublisherStatus = publisherStatus;
    if (publisherStatus.vaultId && publisherStatus.vaultId !== protocolId) throw new Error('publisher_status_mismatch');
    const scan = await state.scanner.scan(resolve(context.vaultRoot), { include: [...context.include], exclude: [...context.exclude], vaultId: protocolId });
    const preview = toPreview(scan, context.policyDigest);
    state.runtime.lastPreview = preview;
    state.runtime.lastScanAt = state.now().toISOString();
    if (scanIsIncomplete(scan)) throw new Error('scan_incomplete');
    if (policyDigest(state.config) !== context.policyDigest) throw new Error('sync_context_changed');
    const lastReceipt = state.runtime.lastReceipt as { generation?: number; vaultId?: string } | undefined;
    const previousGeneration = Math.max(Number(lastReceipt?.vaultId === protocolId ? lastReceipt.generation || 0 : 0), publisherStatus.generation ?? 0);
    const payload = await makeSnapshot(scan, protocolId, previousGeneration + 1, state.now().toISOString());
    const receipt = await state.remoteClient.upload({ url: context.remoteServerUrl, deviceId: context.deviceId, vaultId: protocolId, snapshot: payload, privateKey });
    if (!receiptMatches(receipt, payload, protocolId)) throw new Error('receipt_mismatch');
    state.runtime.lastUploadAt = state.now().toISOString();
    state.runtime.lastReceipt = receipt;
    delete state.runtime.lastError;
    await persist(state);
    return { receipt, preview, snapshotId: payload.snapshotId };
  } catch (error) {
    state.runtime.lastError = safeErrorMessage(error);
    await saveRuntime(state.dataDir, state.runtime).catch(() => undefined);
    throw error;
  } finally {
    state.syncInFlight = false;
    releaseControlOperation(state, 'sync');
  }
}

function scheduleSync(state: AgentState): void {
  if (state.syncTimer) clearInterval(state.syncTimer);
  delete state.syncTimer;
  const minutes = Number(state.config.syncIntervalMinutes || 0);
  if (minutes <= 0) return;
  const timer = setInterval(() => {
    void performSync(state).catch(() => undefined);
  }, minutes * 60_000);
  timer.unref();
  state.syncTimer = timer;
}

function requireCsrf(state: AgentState, request: FastifyRequest, reply: FastifyReply): boolean {
  if (!safeEqual(request.headers['x-bridge-csrf']?.toString(), state.csrfToken)) {
    void reply.code(403).send({ error: 'csrf_required' });
    return false;
  }
  return true;
}

export async function createAgentApp(options: CreateAgentAppOptions = {}): Promise<AgentApp> {
  const dataDir = resolveDataDir(options.dataDir);
  const now = options.now ?? (() => new Date());
  const config = await loadConfig(dataDir);
  const runtime = await loadRuntime(dataDir, now());
  const credentialStore = options.credentials ?? new FileCredentialStore(dataDir);
  const fileStore = credentialStore instanceof FileCredentialStore ? credentialStore : undefined;
  const deviceIdentity = fileStore ? await fileStore.identity() : undefined;
  const pairing = ((runtime as RuntimeState & { pairing?: PairingState }).pairing || { paired: false }) as PairingState;
  const idKey = await credentialStore.getOrCreateIdKey?.() ?? randomBytes(32).toString('base64url');
  const state: AgentState = {
    dataDir,
    csrfToken: newCsrfToken(),
    unsafeDevelopmentHost: options.unsafeDevelopmentHost ?? process.env.BRIDGE_UNSAFE_DEV === '1',
    allowLoopbackRemoteHttp: options.allowLoopbackRemoteHttp ?? process.env.BRIDGE_ALLOW_LOOPBACK_HTTP === '1',
    config,
    runtime,
    pairing,
    credentialStore,
    ...(deviceIdentity ? { deviceIdentity } : {}),
    scanner: options.scanVault ?? new DefaultVaultScanner(idKey),
    remoteClient: options.remoteClient ?? new HttpRemoteClient(options.allowLoopbackRemoteHttp ?? process.env.BRIDGE_ALLOW_LOOPBACK_HTTP === '1'),
    now,
    syncInFlight: false,
  };
  const app = Fastify({ logger: options.logger ?? false, bodyLimit: MAX_JSON_BYTES }) as unknown as AgentApp;
  app.decorate('agentState', state);

  app.addHook('onSend', async (_request, reply, payload) => {
    reply
      .header('cache-control', 'no-store')
      .header('content-security-policy', "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
      .header('cross-origin-opener-policy', 'same-origin')
      .header('permissions-policy', 'camera=(), microphone=(), geolocation=()')
      .header('referrer-policy', 'no-referrer')
      .header('x-content-type-options', 'nosniff')
      .header('x-frame-options', 'DENY');
    return payload;
  });

  app.addHook('onRequest', async (request, reply) => {
    const path = requestPath(request);
    const host = request.headers.host;
    if (!state.unsafeDevelopmentHost && !isLoopbackHost(host)) {
      await reply.code(403).send({ error: 'loopback_only' });
      return;
    }
    if (!originAllowed(request)) {
      await reply.code(403).send({ error: 'origin_not_allowed' });
      return;
    }
    if (WRITE_METHODS.has(request.method) && WRITE_PATHS.has(path) && !requireCsrf(state, request, reply)) return;
    if (WRITE_METHODS.has(request.method) && rejectControlOperation(state, request, reply)) return;
  });

  app.get('/api/bootstrap', async () => ({ csrfToken: state.csrfToken, status: publicStatus(state), config: dashboardConfig(state.config), identity: publicIdentity(state.deviceIdentity) }));
  app.get('/api/status', async () => ({ status: publicStatus(state), identity: publicIdentity(state.deviceIdentity) }));

  app.post('/api/config', async (request, reply) => {
    if (!acquireControlOperation(state, 'config')) return reply.code(409).send({ error: 'operation_in_progress' });
    try {
      const candidate = configWithPatch(state.config, bodyObject(request));
      const checked = validateConfig(candidate);
      if (!checked.ok) return reply.code(400).send({ error: checked.error });
      if (checked.config.remoteServerUrl) {
        try { allowedRemoteUrl(checked.config.remoteServerUrl, state.allowLoopbackRemoteHttp); } catch (error) { return reply.code(400).send({ error: safeErrorMessage(error) }); }
      }
      const oldPolicyDigest = policyDigest(state.config);
      state.config = checked.config;
      if (oldPolicyDigest !== policyDigest(state.config)) delete state.runtime.lastPreview;
      await persist(state);
      scheduleSync(state);
      return { status: publicStatus(state) };
    } finally {
      releaseControlOperation(state, 'config');
    }
  });

  app.post('/api/preview', async (request, reply) => {
    if (!acquireControlOperation(state, 'preview')) return reply.code(409).send({ error: 'operation_in_progress' });
    try {
      const body = bodyObject(request);
      const candidate = configWithPatch(state.config, body);
      const checked = validateConfig(candidate);
      if (!checked.ok) return reply.code(400).send({ error: checked.error });
      if (!checked.config.vaultRoot) return reply.code(400).send({ error: 'vaultRoot_required' });
      state.config = checked.config;
      const digest = policyDigest(state.config);
      try {
        const scan = await state.scanner.scan(resolve(checked.config.vaultRoot), scanOptions(checked.config));
        const preview = toPreview(scan, digest);
        state.runtime.lastPreview = preview;
        state.runtime.lastScanAt = now().toISOString();
        delete state.runtime.lastError;
        await persist(state);
        return { preview };
      } catch (error) {
        delete state.runtime.lastPreview;
        state.runtime.lastError = safeErrorMessage(error);
        await persist(state);
        return reply.code(400).send({ error: state.runtime.lastError });
      }
    } finally {
      releaseControlOperation(state, 'preview');
    }
  });

  app.post('/api/device/generate', async (request, reply) => {
    if (!acquireControlOperation(state, 'device-generate')) return reply.code(409).send({ error: 'operation_in_progress' });
    try {
      const rotate = bodyObject(request).rotate === true;
      if (state.deviceIdentity && !rotate) return reply.code(409).send({ error: 'device_identity_exists' });
      if (rotate && state.deviceIdentity && state.pairing.deviceId && state.config.agentId) {
        const pendingRevocation: PendingRevocation = {
          deviceId: state.pairing.deviceId,
          agentId: state.config.agentId,
          publicKey: state.deviceIdentity.publicKey,
          createdAt: now().toISOString(),
          status: 'pending',
        };
        const records = [
          ...(state.runtime.pendingRevocations || []),
          ...(state.runtime.pendingRevocation ? [state.runtime.pendingRevocation] : []),
        ];
        const deduplicated = new Map<string, PendingRevocation>();
        for (const record of records) {
          if (!deduplicated.has(record.deviceId)) deduplicated.set(record.deviceId, record);
        }
        const existing = [...deduplicated.values()];
        const alreadyPending = existing.some((record) => record.deviceId === pendingRevocation.deviceId);
        if (existing.length > MAX_PENDING_REVOCATIONS || (existing.length >= MAX_PENDING_REVOCATIONS && !alreadyPending)) {
          return reply.code(409).send({ error: 'pending_revocations_limit' });
        }
        state.runtime.pendingRevocations = [pendingRevocation, ...existing.filter((record) => record.deviceId !== pendingRevocation.deviceId)];
        delete state.runtime.pendingRevocation;
        await saveRuntime(state.dataDir, state.runtime);
      }
      const keys = generateDeviceKeypair();
      const createdAt = now().toISOString();
      if (!fileStore) return reply.code(503).send({ error: 'keychain_adapter_required' });
      await fileStore.saveIdentity(keys.privateKey, keys.publicKey, createdAt);
      state.deviceIdentity = { publicKey: keys.publicKey, keyAlgorithm: 'ed25519', createdAt };
      state.config.agentId = sha256Base64Url(keys.publicKey).slice(0, 32);
      state.pairing = { paired: false };
      state.runtime = { ...state.runtime, pairing: state.pairing } as RuntimeState;
      if (rotate) delete state.runtime.lastPreview;
      delete state.runtime.lastError;
      await persist(state);
      return { identity: publicIdentity(state.deviceIdentity), credentialStore: state.credentialStore.kind };
    } finally {
      releaseControlOperation(state, 'device-generate');
    }
  });

  app.post('/api/pair', async (request, reply) => {
    if (!acquireControlOperation(state, 'pair')) return reply.code(409).send({ error: 'operation_in_progress' });
    try {
      const body = bodyObject(request);
      const code = typeof body.code === 'string' ? body.code.trim() : '';
      if (!code || code.length > 128) return reply.code(400).send({ error: 'pairing_code_required' });
      if (!state.config.remoteServerUrl) return reply.code(400).send({ error: 'remoteServerUrl_required' });
      if (!state.deviceIdentity || !state.config.agentId) return reply.code(400).send({ error: 'device_identity_required' });
      try {
        const response = await state.remoteClient.pair({ url: state.config.remoteServerUrl, code, agentId: state.config.agentId, ...(state.config.vaultId ? { vaultId: protocolVaultId(state.config.vaultId) } : {}), publicKey: state.deviceIdentity.publicKey, ...(state.config.label ? { label: state.config.label } : {}) });
        state.pairing = { paired: true, deviceId: response.deviceId, publicKey: state.deviceIdentity.publicKey, pairedAt: now().toISOString() };
        if (response.vaultId) state.config.vaultId = response.vaultId;
        state.runtime = { ...state.runtime, pairing: state.pairing } as RuntimeState;
        delete state.runtime.lastError;
        await persist(state);
        return { pairing: state.pairing, receipt: response.receipt };
      } catch (error) {
        state.runtime.lastError = safeErrorMessage(error);
        await saveRuntime(state.dataDir, state.runtime);
        return reply.code(502).send({ error: state.runtime.lastError });
      }
    } finally {
      releaseControlOperation(state, 'pair');
    }
  });

  app.post('/api/sync', async (_request, reply) => {
    try {
      return await performSync(state);
    } catch (error) {
      const message = safeErrorMessage(error);
      const statusCode = message === 'sync_already_running' || message === 'operation_in_progress' || message === 'scan_incomplete' ? 409 : message.endsWith('_required') ? 400 : 502;
      return reply.code(statusCode).send({ error: message });
    }
  });

  app.post('/api/publisher/status', async (_request, reply) => {
    if (!acquireControlOperation(state, 'publisher-status')) return reply.code(409).send({ error: 'operation_in_progress' });
    try {
      if (!state.config.remoteServerUrl || !state.config.vaultId) return reply.code(400).send({ error: 'remote_and_id_required' });
      if (!state.pairing.deviceId) return reply.code(400).send({ error: 'device_identity_required' });
      const privateKey = await state.credentialStore.getPrivateKey();
      if (!privateKey) return reply.code(400).send({ error: 'device_identity_required' });
      try {
        const status = await state.remoteClient.status({ url: state.config.remoteServerUrl, deviceId: state.pairing.deviceId, vaultId: protocolVaultId(state.config.vaultId), privateKey });
        state.runtime.lastPublisherStatus = status;
        delete state.runtime.lastError;
        await saveRuntime(state.dataDir, state.runtime);
        return { status };
      } catch (error) {
        const status: PublisherStatus = { ok: false, checkedAt: now().toISOString(), message: safeErrorMessage(error) };
        state.runtime.lastPublisherStatus = status;
        if (status.message) state.runtime.lastError = status.message;
        await saveRuntime(state.dataDir, state.runtime);
        return reply.code(502).send({ status, error: status.message });
      }
    } finally {
      releaseControlOperation(state, 'publisher-status');
    }
  });

  const staticDir = options.staticDir || defaultStaticDir();
  app.get('/*', async (request, reply) => {
    const result = await readStaticFile(staticDir, requestPath(request));
    if (!result) return reply.code(404).send({ error: 'not_found' });
    return reply.header('content-type', result.contentType).send(result.body);
  });

  app.addHook('onClose', async () => {
    if (state.syncTimer) clearInterval(state.syncTimer);
    delete state.syncTimer;
  });
  scheduleSync(state);

  return app;
}

export { dashboardConfig, fallbackSnapshot, makeSnapshot, performSync, publicStatus, safeErrorMessage, scheduleSync, toPreview };
