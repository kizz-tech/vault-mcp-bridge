import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
} from "node:crypto";
import { chmodSync, existsSync, lstatSync, readFileSync } from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import { open, mkdir, rename, chmod, unlink } from "node:fs/promises";
import type { SecretReference } from "@vault-mcp-bridge/contracts";
import type { CredentialVault } from "./providers.js";

/** Version of the encrypted credential envelope written by this adapter. */
export const CREDENTIAL_VAULT_SCHEMA_VERSION = 1 as const;
const MASTER_KEY_BYTES = 32;
const GCM_NONCE_BYTES = 12;
const GCM_TAG_BYTES = 16;

type DurableReference = Pick<SecretReference, "provider" | "id">;

type EncryptedCredential = {
  ref: DurableReference;
  nonce: string;
  ciphertext: string;
  tag: string;
};

type PersistedCredentialVault = {
  schemaVersion: typeof CREDENTIAL_VAULT_SCHEMA_VERSION;
  entries: EncryptedCredential[];
};

export type DurableCredentialVaultOptions = {
  /** Absolute or relative path to the encrypted credential file. */
  filePath?: string;
  /** Alias for filePath. */
  path?: string;
  /** Exactly 32 bytes. The bytes are copied and never read from disk again. */
  masterKey?: Uint8Array;
  /** Raw key file containing exactly 32 bytes, mode 0400 or 0600. */
  masterKeyFile?: string;
  /** Alias for masterKeyFile. */
  keyFile?: string;
  /** Alias for masterKeyFile. */
  keyPath?: string;
  /** Alias for masterKeyFile. */
  masterKeyPath?: string;
  /** Alias for masterKeyFile. */
  keyFilePath?: string;
};

export class DurableCredentialVaultError extends Error {
  constructor(
    readonly code: "invalid_path" | "invalid_key" | "invalid_reference" | "corrupt" | "newer_version" | "io",
    message: string,
    options?: { cause?: unknown },
  ) {
    super(message, options);
    this.name = "DurableCredentialVaultError";
  }
}

const isObject = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

const isBase64Url = (value: unknown): value is string =>
  typeof value === "string" && value.length > 0 && /^[A-Za-z0-9_-]+$/u.test(value);

const invalid = (message: string): DurableCredentialVaultError => new DurableCredentialVaultError("corrupt", message);

const referenceKey = (reference: DurableReference): string => `${reference.provider}:${reference.id}`;

const validateReference = (reference: SecretReference): DurableReference => {
  if (!isObject(reference) || typeof reference.provider !== "string" || reference.provider.length === 0 || reference.provider.length > 64) {
    throw new DurableCredentialVaultError("invalid_reference", "credential reference is invalid");
  }
  if (typeof reference.id !== "string" || reference.id.length === 0 || reference.id.length > 512) {
    throw new DurableCredentialVaultError("invalid_reference", "credential reference is invalid");
  }
  return { provider: reference.provider, id: reference.id };
};

/** AAD binds a ciphertext to both its reference and this exact envelope schema. */
export const credentialVaultAad = (reference: DurableReference): Buffer =>
  Buffer.from(`vault-mcp-bridge/credential-vault/${CREDENTIAL_VAULT_SCHEMA_VERSION}/${reference.provider}:${reference.id}`, "utf8");

const decodeBase64Url = (value: unknown, expectedLength: number, field: string): Buffer => {
  if (!isBase64Url(value)) throw invalid(`credential ${field} is invalid`);
  const decoded = Buffer.from(value, "base64url");
  if (decoded.length !== expectedLength || decoded.toString("base64url") !== value) throw invalid(`credential ${field} is invalid`);
  return decoded;
};

const decodeCiphertext = (value: unknown): Buffer => {
  if (!isBase64Url(value)) throw invalid("credential ciphertext is invalid");
  const decoded = Buffer.from(value, "base64url");
  if (decoded.length === 0 || decoded.toString("base64url") !== value) throw invalid("credential ciphertext is invalid");
  return decoded;
};

function assertPersistedEnvelope(value: unknown): asserts value is PersistedCredentialVault {
  if (!isObject(value)) throw invalid("credential vault envelope is invalid");
  if (typeof value.schemaVersion !== "number") throw invalid("credential vault schema version is missing");
  if (value.schemaVersion > CREDENTIAL_VAULT_SCHEMA_VERSION) {
    throw new DurableCredentialVaultError("newer_version", "credential vault schema version is newer than this runtime supports");
  }
  if (value.schemaVersion !== CREDENTIAL_VAULT_SCHEMA_VERSION) throw invalid("credential vault schema version is unsupported");
  if (Object.keys(value).some((key) => key !== "schemaVersion" && key !== "entries")) throw invalid("credential vault envelope contains unknown fields");
  if (!Array.isArray(value.entries)) throw invalid("credential vault entries are invalid");
  for (const entry of value.entries) {
    if (!isObject(entry) || !isObject(entry.ref)) throw invalid("credential vault entry is invalid");
    const ref = entry.ref;
    if (typeof ref.provider !== "string" || ref.provider.length === 0 || ref.provider.length > 64) throw invalid("credential reference is invalid");
    if (typeof ref.id !== "string" || ref.id.length === 0 || ref.id.length > 512) throw invalid("credential reference is invalid");
    decodeBase64Url(entry.nonce, GCM_NONCE_BYTES, "nonce");
    decodeBase64Url(entry.tag, GCM_TAG_BYTES, "tag");
    decodeCiphertext(entry.ciphertext);
  }
}

const resolveFilePath = (input: string | DurableCredentialVaultOptions): string => {
  const candidate = typeof input === "string" ? input : input.filePath ?? input.path;
  if (!candidate || typeof candidate !== "string" || candidate.trim() === "") {
    throw new DurableCredentialVaultError("invalid_path", "durable credential vault file path is required");
  }
  return resolve(candidate);
};

const validateMasterKey = (key: Uint8Array): Buffer => {
  if (!(key instanceof Uint8Array) || key.byteLength !== MASTER_KEY_BYTES) {
    throw new DurableCredentialVaultError("invalid_key", "credential vault master key must be exactly 32 bytes");
  }
  return Buffer.from(key);
};

const readMasterKeyFile = (filePath: string): Buffer => {
  try {
    const stat = lstatSync(filePath);
    if (!stat.isFile()) throw new DurableCredentialVaultError("invalid_key", "credential vault master key file is not a regular file");
    // 0400 and 0600 are the only accepted modes. Group/world bits are never tolerated.
    const mode = stat.mode & 0o7777;
    if (mode !== 0o400 && mode !== 0o600) {
      throw new DurableCredentialVaultError("invalid_key", "credential vault master key file must be mode 0400 or 0600");
    }
    const bytes = readFileSync(filePath);
    return validateMasterKey(bytes);
  } catch (error) {
    if (error instanceof DurableCredentialVaultError) throw error;
    throw new DurableCredentialVaultError("invalid_key", "credential vault master key file is unavailable", { cause: error });
  }
};

const resolveMasterKey = (input: DurableCredentialVaultOptions, explicitKey?: Uint8Array): Buffer => {
  const key = explicitKey ?? input.masterKey;
  const keyFile = input.masterKeyFile ?? input.keyFile ?? input.keyPath ?? input.masterKeyPath ?? input.keyFilePath;
  if (key && keyFile) throw new DurableCredentialVaultError("invalid_key", "provide either a master key or a master key file, not both");
  if (key) return validateMasterKey(key);
  if (keyFile) return readMasterKeyFile(resolve(keyFile));
  throw new DurableCredentialVaultError("invalid_key", "credential vault master key is required");
};

const atomicWrite = async (filePath: string, contents: string): Promise<void> => {
  const directory = dirname(filePath);
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const temporaryPath = join(directory, `.${basename(filePath)}.${process.pid}.${randomBytes(12).toString("hex")}.tmp`);
  let handle: Awaited<ReturnType<typeof open>> | undefined;
  try {
    handle = await open(temporaryPath, "wx", 0o600);
    await handle.writeFile(contents, "utf8");
    await handle.sync();
    await handle.close();
    handle = undefined;
    await rename(temporaryPath, filePath);
    await chmod(filePath, 0o600);
    const directoryHandle = await open(directory, "r");
    try {
      await directoryHandle.sync();
    } finally {
      await directoryHandle.close();
    }
  } catch (error) {
    if (handle) await handle.close().catch(() => undefined);
    await unlink(temporaryPath).catch(() => undefined);
    throw new DurableCredentialVaultError("io", "durable credential vault write failed", { cause: error });
  }
};

const loadEnvelope = (filePath: string): PersistedCredentialVault | null => {
  if (!existsSync(filePath)) return null;
  try {
    const stat = lstatSync(filePath);
    if (!stat.isFile()) throw new DurableCredentialVaultError("io", "durable credential vault path is not a regular file");
    chmodSync(filePath, 0o600);
    const parsed: unknown = JSON.parse(readFileSync(filePath, "utf8"));
    assertPersistedEnvelope(parsed);
    return parsed;
  } catch (error) {
    if (error instanceof DurableCredentialVaultError) throw error;
    throw new DurableCredentialVaultError("corrupt", "durable credential vault is corrupt", { cause: error });
  }
};

const encrypt = (masterKey: Buffer, reference: DurableReference, value: string): Omit<EncryptedCredential, "ref"> => {
  const nonce = randomBytes(GCM_NONCE_BYTES);
  const cipher = createCipheriv("aes-256-gcm", masterKey, nonce);
  cipher.setAAD(credentialVaultAad(reference));
  const ciphertext = Buffer.concat([cipher.update(value, "utf8"), cipher.final()]);
  return {
    nonce: nonce.toString("base64url"),
    ciphertext: ciphertext.toString("base64url"),
    tag: cipher.getAuthTag().toString("base64url"),
  };
};

const decrypt = (masterKey: Buffer, entry: EncryptedCredential): string => {
  try {
    const nonce = decodeBase64Url(entry.nonce, GCM_NONCE_BYTES, "nonce");
    const tag = decodeBase64Url(entry.tag, GCM_TAG_BYTES, "tag");
    const ciphertext = decodeCiphertext(entry.ciphertext);
    const decipher = createDecipheriv("aes-256-gcm", masterKey, nonce);
    decipher.setAAD(credentialVaultAad(entry.ref));
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString("utf8");
  } catch (error) {
    // Never include the reference, key, or decrypted value in an error.
    throw new DurableCredentialVaultError("corrupt", "durable credential vault could not decrypt an entry", { cause: error });
  }
};

type ConstructorInput = string | DurableCredentialVaultOptions;

/**
 * AES-256-GCM encrypted, file-backed implementation of CredentialVault.
 * Values are plaintext only in this process' private map; every mutation is
 * synchronously queued behind an atomic encrypted flush. Queueing is per
 * adapter instance; callers sharing a path across processes need an external
 * single-writer/transaction boundary.
 */
export class DurableCredentialVault implements CredentialVault {
  readonly filePath: string;
  #masterKey: Buffer;
  #values = new Map<string, { reference: DurableReference; value: string }>();
  #operationChain: Promise<void> = Promise.resolve();

  constructor(input: ConstructorInput, explicitMasterKeyOrOptions?: Uint8Array | DurableCredentialVaultOptions | string) {
    const baseOptions: DurableCredentialVaultOptions = typeof input === "string" ? { filePath: input } : input;
    const options: DurableCredentialVaultOptions = typeof explicitMasterKeyOrOptions === "string"
      ? { ...baseOptions, masterKeyFile: explicitMasterKeyOrOptions }
      : explicitMasterKeyOrOptions && !(explicitMasterKeyOrOptions instanceof Uint8Array)
        ? { ...baseOptions, ...explicitMasterKeyOrOptions }
      : baseOptions;
    const explicitMasterKey = explicitMasterKeyOrOptions instanceof Uint8Array ? explicitMasterKeyOrOptions : undefined;
    this.filePath = resolveFilePath(input);
    this.#masterKey = resolveMasterKey(options, explicitMasterKey);
    const envelope = loadEnvelope(this.filePath);
    if (!envelope) return;
    for (const entry of envelope.entries) {
      const reference = validateReference(entry.ref as SecretReference);
      const key = referenceKey(reference);
      if (this.#values.has(key)) throw new DurableCredentialVaultError("corrupt", "durable credential vault contains duplicate references");
      this.#values.set(key, { reference, value: decrypt(this.#masterKey, { ...entry, ref: reference }) });
    }
  }

  /** Return a value or null; decryption failures fail closed. */
  get(reference: SecretReference): Promise<string | null> {
    const normalized = validateReference(reference);
    return this.enqueue(() => Promise.resolve(this.#values.get(referenceKey(normalized))?.value ?? null));
  }

  put(reference: SecretReference, value: string): Promise<void> {
    const normalized = validateReference(reference);
    if (typeof value !== "string" || value.length === 0) throw new DurableCredentialVaultError("invalid_reference", "credential value is invalid");
    return this.enqueue(async () => {
      const key = referenceKey(normalized);
      const previous = this.#values.get(key);
      this.#values.set(key, { reference: normalized, value });
      try {
        await this.writeSnapshot();
      } catch (error) {
        if (previous) this.#values.set(key, previous);
        else this.#values.delete(key);
        throw error;
      }
    });
  }

  revoke(reference: SecretReference): Promise<void> {
    const normalized = validateReference(reference);
    return this.enqueue(async () => {
      const key = referenceKey(normalized);
      const previous = this.#values.get(key);
      this.#values.delete(key);
      try {
        await this.writeSnapshot();
      } catch (error) {
        if (previous) this.#values.set(key, previous);
        throw error;
      }
    });
  }

  /** Explicit durability port for callers that need to checkpoint state. */
  flush(): Promise<void> {
    return this.enqueue(() => this.writeSnapshot());
  }

  private enqueue<T>(operation: () => Promise<T>): Promise<T> {
    const result = this.#operationChain.then(operation);
    this.#operationChain = result.then(() => undefined, () => undefined);
    return result;
  }

  private async writeSnapshot(): Promise<void> {
    const entries = [...this.#values.values()]
      .sort((left, right) => referenceKey(left.reference).localeCompare(referenceKey(right.reference)))
      .map(({ reference, value }) => ({ ref: reference, ...encrypt(this.#masterKey, reference, value) }));
    const envelope: PersistedCredentialVault = { schemaVersion: CREDENTIAL_VAULT_SCHEMA_VERSION, entries };
    await atomicWrite(this.filePath, JSON.stringify(envelope));
  }
}

export type CreateDurableCredentialVaultInput = ConstructorInput;

export const createDurableCredentialVault = (input: ConstructorInput, masterKeyOrOptions?: Uint8Array | DurableCredentialVaultOptions | string): DurableCredentialVault =>
  new DurableCredentialVault(input, masterKeyOrOptions);
export const openDurableCredentialVault = createDurableCredentialVault;
