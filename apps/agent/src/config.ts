import { mkdir, open, readFile, rename, chmod, unlink } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import type { AgentConfig, RuntimeState } from './types.js';
import type { PendingRevocation } from './types.js';

const DEFAULT_CONFIG: AgentConfig = {
  include: ['**/*.md', '**/*.canvas', '**/*.base'],
  exclude: ['.obsidian/**', '**/.obsidian/**', '**/.git/**', '**/.*', '**/node_modules/**'],
  syncIntervalMinutes: 0,
};
const DEFAULT_INCLUDE = ['**/*.md'];
const DEFAULT_EXCLUDE = ['.obsidian/**', '**/.obsidian/**', '**/.git/**', '**/.*', '**/node_modules/**'];
export const MAX_PENDING_REVOCATIONS = 32;

export const configPaths = (dataDir: string) => ({
  config: join(dataDir, 'config.json'),
  runtime: join(dataDir, 'runtime.json'),
  credentials: join(dataDir, 'credentials.json'),
  locks: join(dataDir, 'locks'),
});

export function resolveDataDir(input?: string): string {
  return input?.trim() || process.env.BRIDGE_DATA_DIR?.trim() || join(process.env.XDG_STATE_HOME || join(process.env.HOME || '/tmp', '.local', 'state'), 'vault-mcp-bridge');
}

async function ensureDataDir(dataDir: string): Promise<void> {
  await mkdir(dataDir, { recursive: true, mode: 0o700 });
  try {
    await chmod(dataDir, 0o700);
  } catch {
    // Windows and some mounted filesystems don't support chmod; file writes still use mode 0600.
  }
}

async function readJson<T>(path: string, fallback: T): Promise<T> {
  try {
    const raw = await readFile(path, 'utf8');
    return JSON.parse(raw) as T;
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code === 'ENOENT') return fallback;
    throw error;
  }
}

export async function loadConfig(dataDir: string): Promise<AgentConfig> {
  await ensureDataDir(dataDir);
  const loaded = await readJson<AgentConfig>(configPaths(dataDir).config, {});
  const config: AgentConfig = { ...DEFAULT_CONFIG, ...loaded };
  if (!config.include) config.include = [...DEFAULT_INCLUDE];
  if (!config.exclude) config.exclude = [...DEFAULT_EXCLUDE];
  if (config.syncIntervalMinutes === undefined) config.syncIntervalMinutes = 0;
  return config;
}

export async function loadRuntime(dataDir: string, now = new Date()): Promise<RuntimeState> {
  await ensureDataDir(dataDir);
  const runtime = await readJson<RuntimeState>(configPaths(dataDir).runtime, { startedAt: now.toISOString() });
  const legacy = runtime.pendingRevocation;
  const records = [...(runtime.pendingRevocations || []), ...(legacy ? [legacy] : [])];
  const deduplicated = new Map<string, PendingRevocation>();
  for (const record of records) {
    if (!record || typeof record.deviceId !== 'string' || typeof record.agentId !== 'string' || typeof record.publicKey !== 'string' || typeof record.createdAt !== 'string') continue;
    if (!deduplicated.has(record.deviceId)) deduplicated.set(record.deviceId, { ...record, status: 'pending' });
  }
  const pendingRevocations = [...deduplicated.values()].slice(0, MAX_PENDING_REVOCATIONS);
  const normalized: RuntimeState = { ...runtime, ...(pendingRevocations.length ? { pendingRevocations } : {}) };
  delete normalized.pendingRevocation;
  if (legacy || runtime.pendingRevocations?.length !== pendingRevocations.length) await atomicWriteJson(configPaths(dataDir).runtime, normalized);
  return normalized;
}

export async function atomicWriteJson(path: string, value: unknown): Promise<void> {
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  const tempPath = `${path}.${process.pid}.${Date.now()}.tmp`;
  const handle = await open(tempPath, 'wx', 0o600);
  try {
    await handle.writeFile(`${JSON.stringify(value, null, 2)}\n`, 'utf8');
    await handle.sync();
  } finally {
    await handle.close();
  }
  await chmod(tempPath, 0o600).catch(() => undefined);
  await rename(tempPath, path);
  await chmod(path, 0o600).catch(() => undefined);
}

export async function saveConfig(dataDir: string, config: AgentConfig): Promise<void> {
  await ensureDataDir(dataDir);
  await atomicWriteJson(configPaths(dataDir).config, config);
}

export async function saveRuntime(dataDir: string, runtime: RuntimeState): Promise<void> {
  await ensureDataDir(dataDir);
  await atomicWriteJson(configPaths(dataDir).runtime, runtime);
}

export async function clearRuntime(dataDir: string): Promise<void> {
  await unlink(configPaths(dataDir).runtime).catch((error: unknown) => {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
  });
}

export function validateConfig(input: AgentConfig): { ok: true; config: AgentConfig } | { ok: false; error: string } {
  const config: AgentConfig = { ...DEFAULT_CONFIG, ...input };
  if (!config.include) config.include = [...DEFAULT_INCLUDE];
  if (!config.exclude) config.exclude = [...DEFAULT_EXCLUDE];
  if (config.syncIntervalMinutes === undefined) config.syncIntervalMinutes = 0;
  if (config.vaultRoot !== undefined && typeof config.vaultRoot !== 'string') return { ok: false, error: 'vaultRoot must be a string' };
  if (config.remoteServerUrl !== undefined && typeof config.remoteServerUrl !== 'string') return { ok: false, error: 'remoteServerUrl must be a string' };
  if (config.vaultId !== undefined && !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(config.vaultId)) return { ok: false, error: 'vaultId contains unsupported characters' };
  if (!Array.isArray(config.include) || config.include.some((pattern) => typeof pattern !== 'string' || pattern.length > 256)) return { ok: false, error: 'include must be a list of short patterns' };
  if (!Array.isArray(config.exclude) || config.exclude.some((pattern) => typeof pattern !== 'string' || pattern.length > 256)) return { ok: false, error: 'exclude must be a list of short patterns' };
  const interval = Number(config.syncIntervalMinutes);
  if (!Number.isInteger(interval) || interval < 0 || interval > 1440) return { ok: false, error: 'syncIntervalMinutes must be an integer between 0 and 1440' };
  return { ok: true, config: { ...config, syncIntervalMinutes: interval } };
}

export { DEFAULT_CONFIG };
