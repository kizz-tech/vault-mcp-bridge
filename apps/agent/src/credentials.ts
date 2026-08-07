import { randomBytes } from 'node:crypto';
import { chmod, readFile } from 'node:fs/promises';
import { configPaths, atomicWriteJson } from './config.js';
import type { CredentialStore, DeviceIdentity } from './types.js';

interface CredentialFile {
  privateKey?: string;
  publicKey?: string;
  createdAt?: string;
  idKey?: string;
}

async function readCredentialFile(path: string): Promise<CredentialFile> {
  try {
    return JSON.parse(await readFile(path, 'utf8')) as CredentialFile;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return {};
    throw error;
  }
}

/**
 * File credentials are intentionally marked development-only. Production wiring
 * should replace this with the Keychain adapter without changing the service API.
 */
export class FileCredentialStore implements CredentialStore {
  readonly kind = 'file-development' as const;

  constructor(private readonly dataDir: string) {}

  async getPrivateKey(): Promise<string | undefined> {
    return (await readCredentialFile(configPaths(this.dataDir).credentials)).privateKey;
  }

  async savePrivateKey(privateKey: string): Promise<void> {
    const path = configPaths(this.dataDir).credentials;
    const current = await readCredentialFile(path);
    await atomicWriteJson(path, { ...current, privateKey });
    await chmod(configPaths(this.dataDir).credentials, 0o600).catch(() => undefined);
  }

  async deletePrivateKey(): Promise<void> {
    const path = configPaths(this.dataDir).credentials;
    const current = await readCredentialFile(path);
    const next: CredentialFile = {};
    if (current.idKey) next.idKey = current.idKey;
    await atomicWriteJson(path, next);
  }

  async identity(): Promise<DeviceIdentity | undefined> {
    const value = await readCredentialFile(configPaths(this.dataDir).credentials);
    if (!value.publicKey || !value.createdAt) return undefined;
    return { publicKey: value.publicKey, keyAlgorithm: 'ed25519', createdAt: value.createdAt };
  }

  async saveIdentity(privateKey: string, publicKey: string, createdAt: string): Promise<void> {
    const path = configPaths(this.dataDir).credentials;
    const current = await readCredentialFile(path);
    await atomicWriteJson(path, { ...current, privateKey, publicKey, createdAt });
    await chmod(configPaths(this.dataDir).credentials, 0o600).catch(() => undefined);
  }

  async getOrCreateIdKey(): Promise<string> {
    const path = configPaths(this.dataDir).credentials;
    const current = await readCredentialFile(path);
    if (current.idKey) return current.idKey;
    const idKey = randomBytes(32).toString('base64url');
    await atomicWriteJson(path, { ...current, idKey });
    await chmod(path, 0o600).catch(() => undefined);
    return idKey;
  }
}

/** Production seam. The prototype refuses to claim Keychain storage exists. */
export class MacKeychainCredentialStore implements CredentialStore {
  readonly kind = 'keychain-unavailable' as const;
  async getPrivateKey(): Promise<string | undefined> {
    throw new Error('macOS Keychain adapter is not configured; use the local file store only for development');
  }
  async savePrivateKey(): Promise<void> {
    throw new Error('macOS Keychain adapter is not configured');
  }
  async deletePrivateKey(): Promise<void> {
    throw new Error('macOS Keychain adapter is not configured');
  }
}
