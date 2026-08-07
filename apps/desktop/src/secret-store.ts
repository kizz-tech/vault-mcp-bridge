import { chmod, mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import { randomUUID } from "node:crypto";

export interface SafeStorageLike {
  isEncryptionAvailable?(): boolean;
  isAsyncEncryptionAvailable?(): boolean | Promise<boolean>;
  encryptString?(value: string): Buffer;
  encryptStringAsync?(value: string): Promise<Buffer>;
  decryptString?(value: Buffer): string;
  decryptStringAsync?(value: Buffer): Promise<string | { result: string; shouldReEncrypt: boolean }>;
}

export interface SecretStore {
  put(reference: string, value: string): Promise<void>;
  get(reference: string): Promise<string | null>;
  remove(reference: string): Promise<void>;
}

export class SecretStoreUnavailableError extends Error {
  constructor(message = "Secure local storage is unavailable") {
    super(message);
    this.name = "SecretStoreUnavailableError";
  }
}

interface EncryptedFile {
  version: 1;
  records: Record<string, string>;
}

function assertReference(reference: string): void {
  if (!/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/u.test(reference)) {
    throw new TypeError("Invalid secret reference");
  }
}

function assertSecret(value: string): void {
  if (!value || value.length > 64 * 1024) throw new TypeError("Invalid secret value");
}

/**
 * File-backed index whose values are encrypted by Electron safeStorage.
 * The file is an implementation detail; callers only receive opaque refs.
 * There is deliberately no cleartext fallback when encryption is unavailable.
 */
export class SafeStorageSecretStore implements SecretStore {
  private records: Record<string, string> | null = null;
  private operation: Promise<void> = Promise.resolve();

  constructor(
    private readonly filePath: string,
    private readonly safeStorage: SafeStorageLike,
    private readonly fs = { readFile, writeFile, rename, mkdir, chmod }
  ) {}

  async put(reference: string, value: string): Promise<void> {
    assertReference(reference);
    assertSecret(value);
    await this.withLock(async () => {
      await this.ensureAvailable();
      const records = await this.load();
      records[reference] = (await this.encrypt(value)).toString("base64");
      await this.persist(records);
    });
  }

  async get(reference: string): Promise<string | null> {
    assertReference(reference);
    return this.withLock(async () => {
      await this.ensureAvailable();
      const records = await this.load();
      const encrypted = records[reference];
      if (!encrypted) return null;
      try {
        return await this.decrypt(Buffer.from(encrypted, "base64"));
      } catch {
        // A corrupted record is not a reason to return an unsafe value.
        throw new SecretStoreUnavailableError("Secure local storage could not decrypt a credential");
      }
    });
  }

  async remove(reference: string): Promise<void> {
    assertReference(reference);
    await this.withLock(async () => {
      await this.ensureAvailable();
      const records = await this.load();
      if (!(reference in records)) return;
      delete records[reference];
      await this.persist(records);
    });
  }

  private async ensureAvailable(): Promise<void> {
    const available = this.safeStorage.isEncryptionAvailable?.()
      ?? (typeof this.safeStorage.isAsyncEncryptionAvailable === "function" ? await this.safeStorage.isAsyncEncryptionAvailable() : false);
    if (!available) throw new SecretStoreUnavailableError();
  }

  private async encrypt(value: string): Promise<Buffer> {
    if (typeof this.safeStorage.encryptStringAsync === "function") return this.safeStorage.encryptStringAsync(value);
    if (typeof this.safeStorage.encryptString === "function") return this.safeStorage.encryptString(value);
    throw new SecretStoreUnavailableError();
  }

  private async decrypt(value: Buffer): Promise<string> {
    if (typeof this.safeStorage.decryptStringAsync === "function") {
      const decrypted = await this.safeStorage.decryptStringAsync(value);
      if (typeof decrypted === "string") return decrypted;
      if (typeof decrypted.result === "string") return decrypted.result;
    }
    if (typeof this.safeStorage.decryptString === "function") return this.safeStorage.decryptString(value);
    throw new SecretStoreUnavailableError();
  }

  private async load(): Promise<Record<string, string>> {
    if (this.records) return { ...this.records };
    try {
      const raw = await this.fs.readFile(this.filePath, "utf8");
      const parsed: unknown = JSON.parse(raw);
      if (!parsed || typeof parsed !== "object") throw new Error("invalid secret store");
      const candidate = parsed as Partial<EncryptedFile>;
      if (candidate.version !== 1 || !candidate.records || typeof candidate.records !== "object") {
        throw new Error("invalid secret store");
      }
      const records: Record<string, string> = {};
      for (const [key, value] of Object.entries(candidate.records)) {
        if (typeof value === "string") records[key] = value;
      }
      this.records = records;
      return { ...records };
    } catch (error) {
      if (isNotFound(error)) {
        this.records = {};
        return {};
      }
      throw new SecretStoreUnavailableError("Secure local storage is unreadable");
    }
  }

  private async persist(records: Record<string, string>): Promise<void> {
    await this.fs.mkdir(dirname(this.filePath), { recursive: true, mode: 0o700 });
    const temporary = `${this.filePath}.${randomUUID()}.tmp`;
    const payload: EncryptedFile = { version: 1, records };
    await this.fs.writeFile(temporary, `${JSON.stringify(payload)}\n`, { encoding: "utf8", mode: 0o600 });
    await this.fs.chmod(temporary, 0o600);
    await this.fs.rename(temporary, this.filePath);
    this.records = { ...records };
  }

  private async withLock<T>(operation: () => Promise<T>): Promise<T> {
    const previous = this.operation;
    let release!: () => void;
    this.operation = new Promise<void>((resolve) => {
      release = resolve;
    });
    await previous;
    try {
      return await operation();
    } finally {
      release();
    }
  }
}

function isNotFound(error: unknown): boolean {
  return Boolean(error && typeof error === "object" && "code" in error && error.code === "ENOENT");
}
