import { randomBytes } from "node:crypto";
import { chmodSync, existsSync, lstatSync, readFileSync } from "node:fs";
import { dirname, basename, join, resolve } from "node:path";
import { open, mkdir, rename, chmod, unlink } from "node:fs/promises";
import type {
  AuthorizationCodeRecord,
  CredentialLease,
  EdgeStore,
  InstallationIdempotencyRecord,
  InstallationRecord,
  OwnerSession,
  RefreshTokenRecord,
  RegisteredClient,
} from "./types.js";

/** The on-disk representation is intentionally independent from the in-memory EdgeStore shape. */
export const EDGE_STORE_SCHEMA_VERSION = 1 as const;

type PersistedMapEntry<T> = readonly [string, T];

type PersistedEdgeStore = {
  schemaVersion: typeof EDGE_STORE_SCHEMA_VERSION;
  installations: PersistedMapEntry<InstallationRecord>[];
  clients: PersistedMapEntry<RegisteredClient>[];
  authorizationCodes: PersistedMapEntry<AuthorizationCodeRecord>[];
  refreshTokens: PersistedMapEntry<RefreshTokenRecord>[];
  ownerSessions: PersistedMapEntry<OwnerSession>[];
  revokedAccessJtis: PersistedMapEntry<number>[];
  installationIdempotency: PersistedMapEntry<InstallationIdempotencyRecord>[];
};

export type DurableEdgeStoreOptions = {
  /** Absolute or relative path to the single state file. */
  filePath?: string;
  /** Alias for filePath, useful for callers that call this a state path. */
  path?: string;
  /** Alias for filePath for callers that name the persisted state explicitly. */
  statePath?: string;
};

export type DurableEdgeStoreLike = EdgeStore & {
  flush(): Promise<void>;
  readonly filePath: string;
};

export class DurableEdgeStoreError extends Error {
  constructor(
    readonly code: "invalid_path" | "corrupt" | "newer_version" | "io",
    message: string,
    options?: { cause?: unknown },
  ) {
    super(message, options);
    this.name = "DurableEdgeStoreError";
  }
}

const hasOwn = (value: object, key: string): boolean => Object.prototype.hasOwnProperty.call(value, key);

const isObject = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

const isFiniteNumber = (value: unknown): value is number => typeof value === "number" && Number.isFinite(value);

const invalid = (message: string): DurableEdgeStoreError => new DurableEdgeStoreError("corrupt", message);

function assertRecord(value: unknown, name: string): asserts value is Record<string, unknown> {
  if (!isObject(value)) throw invalid(`${name} record is invalid`);
}

function assertString(value: unknown, name: string): asserts value is string {
  if (typeof value !== "string" || value.length === 0) throw invalid(`${name} is invalid`);
}

const assertOptionalString = (value: unknown, name: string): void => {
  if (value !== undefined && typeof value !== "string") throw invalid(`${name} is invalid`);
};

function assertNumber(value: unknown, name: string): asserts value is number {
  if (!isFiniteNumber(value)) throw invalid(`${name} is invalid`);
}

function assertMapEntries(value: unknown, name: string): asserts value is unknown[] {
  if (!Array.isArray(value)) throw invalid(`${name} is invalid`);
  for (const entry of value) {
    if (!Array.isArray(entry) || entry.length !== 2 || typeof entry[0] !== "string" || entry[0].length === 0) {
      throw invalid(`${name} entry is invalid`);
    }
  }
}

function assertInstallation(value: unknown): asserts value is InstallationRecord {
  assertRecord(value, "installation");
  for (const key of ["installationId", "ownerId", "vaultId", "providerResourceId", "createdAt", "updatedAt"]) {
    assertString(value[key], `installation.${key}`);
  }
  if (value.mode !== "managed" && value.mode !== "self-hosted") throw invalid("installation.mode is invalid");
  if (value.status !== "provisioning" && value.status !== "ready" && value.status !== "revoked") {
    throw invalid("installation.status is invalid");
  }
  assertOptionalString(value.revokedAt, "installation.revokedAt");
  assertRecord(value.endpointBundle, "installation.endpointBundle");
}

function assertClient(value: unknown): asserts value is RegisteredClient {
  assertRecord(value, "client");
  for (const key of ["clientId", "installationId", "createdAt"]) assertString(value[key], `client.${key}`);
  if (!Array.isArray(value.redirectUris) || value.redirectUris.some((uri) => typeof uri !== "string")) {
    throw invalid("client.redirectUris is invalid");
  }
  if (!Array.isArray(value.grantTypes) || value.grantTypes.length === 0 || value.grantTypes.some((grant) => typeof grant !== "string")) {
    throw invalid("client.grantTypes is invalid");
  }
  if (value.grantTypes[0] !== "authorization_code") throw invalid("client.grantTypes is invalid");
  if (!Array.isArray(value.responseTypes) || value.responseTypes.length === 0 || value.responseTypes.some((response) => typeof response !== "string")) {
    throw invalid("client.responseTypes is invalid");
  }
  if (value.responseTypes[0] !== "code" || value.tokenEndpointAuthMethod !== "none") throw invalid("client authentication is invalid");
  if (value.revocationEpoch !== undefined && (!isFiniteNumber(value.revocationEpoch) || !Number.isSafeInteger(value.revocationEpoch) || value.revocationEpoch < 0)) {
    throw invalid("client.revocationEpoch is invalid");
  }
  assertOptionalString(value.clientName, "client.clientName");
}

function assertAuthorizationCode(value: unknown): asserts value is AuthorizationCodeRecord {
  assertRecord(value, "authorization code");
  for (const key of ["codeHash", "installationId", "ownerId", "clientId", "redirectUri", "codeChallenge", "scope", "resource"]) {
    assertString(value[key], `authorization code.${key}`);
  }
  if (value.codeChallengeMethod !== "S256") throw invalid("authorization code.codeChallengeMethod is invalid");
  for (const key of ["createdAt", "expiresAt"]) assertNumber(value[key], `authorization code.${key}`);
  if (value.revocationEpoch !== undefined && (!isFiniteNumber(value.revocationEpoch) || !Number.isSafeInteger(value.revocationEpoch) || value.revocationEpoch < 0)) {
    throw invalid("authorization code.revocationEpoch is invalid");
  }
  if (value.consumedAt !== undefined) assertNumber(value.consumedAt, "authorization code.consumedAt");
  assertOptionalString(value.nonce, "authorization code.nonce");
}

function assertRefreshToken(value: unknown): asserts value is RefreshTokenRecord {
  assertRecord(value, "refresh token");
  for (const key of ["tokenHash", "installationId", "ownerId", "clientId", "scope", "resource"]) {
    assertString(value[key], `refresh token.${key}`);
  }
  for (const key of ["createdAt", "expiresAt"]) assertNumber(value[key], `refresh token.${key}`);
  if (value.revocationEpoch !== undefined && (!isFiniteNumber(value.revocationEpoch) || !Number.isSafeInteger(value.revocationEpoch) || value.revocationEpoch < 0)) {
    throw invalid("refresh token.revocationEpoch is invalid");
  }
  if (value.revokedAt !== undefined) assertNumber(value.revokedAt, "refresh token.revokedAt");
}

function assertOwnerSession(value: unknown): asserts value is OwnerSession {
  assertRecord(value, "owner session");
  for (const key of ["sessionHash", "ownerId"]) assertString(value[key], `owner session.${key}`);
  for (const key of ["createdAt", "expiresAt"]) assertNumber(value[key], `owner session.${key}`);
}

function assertIdempotency(value: unknown): asserts value is InstallationIdempotencyRecord {
  assertRecord(value, "idempotency");
  for (const key of ["keyHash", "ownerId", "vaultId", "installationId"]) assertString(value[key], `idempotency.${key}`);
  assertNumber(value.createdAt, "idempotency.createdAt");
}

function assertPersistedEnvelope(value: unknown): asserts value is PersistedEdgeStore {
  assertRecord(value, "store envelope");
  if (!hasOwn(value, "schemaVersion") || typeof value.schemaVersion !== "number") throw invalid("store schema version is missing");
  if (value.schemaVersion > EDGE_STORE_SCHEMA_VERSION) {
    throw new DurableEdgeStoreError("newer_version", "store schema version is newer than this runtime supports");
  }
  if (value.schemaVersion !== EDGE_STORE_SCHEMA_VERSION) throw invalid("store schema version is unsupported");
  const expectedKeys = ["schemaVersion", "installations", "clients", "authorizationCodes", "refreshTokens", "ownerSessions", "revokedAccessJtis", "installationIdempotency"];
  if (Object.keys(value).some((key) => !expectedKeys.includes(key))) throw invalid("store envelope contains unknown fields");
  for (const key of ["installations", "clients", "authorizationCodes", "refreshTokens", "ownerSessions", "revokedAccessJtis", "installationIdempotency"]) {
    assertMapEntries(value[key], key);
  }

  const envelope = value as unknown as PersistedEdgeStore;
  const assertUniqueKeys = (entries: readonly PersistedMapEntry<unknown>[], name: string): void => {
    const keys = new Set<string>();
    for (const [key] of entries) {
      if (keys.has(key)) throw invalid(`${name} contains duplicate keys`);
      keys.add(key);
    }
  };
  assertUniqueKeys(envelope.installations, "installations");
  assertUniqueKeys(envelope.clients, "clients");
  assertUniqueKeys(envelope.authorizationCodes, "authorizationCodes");
  assertUniqueKeys(envelope.refreshTokens, "refreshTokens");
  assertUniqueKeys(envelope.ownerSessions, "ownerSessions");
  assertUniqueKeys(envelope.revokedAccessJtis, "revokedAccessJtis");
  assertUniqueKeys(envelope.installationIdempotency, "installationIdempotency");
  for (const entry of envelope.installations) assertInstallation(entry[1]);
  for (const entry of envelope.clients) assertClient(entry[1]);
  for (const entry of envelope.authorizationCodes) assertAuthorizationCode(entry[1]);
  for (const entry of envelope.refreshTokens) assertRefreshToken(entry[1]);
  for (const entry of envelope.ownerSessions) assertOwnerSession(entry[1]);
  for (const entry of envelope.revokedAccessJtis) assertNumber(entry[1], "revoked access JTI expiry");
  for (const entry of envelope.installationIdempotency) assertIdempotency(entry[1]);
  const assertRecordKeys = <T extends Record<string, unknown>>(entries: readonly PersistedMapEntry<T>[], field: keyof T, name: string): void => {
    for (const [key, value] of entries) {
      if (value[field] !== key) throw invalid(`${name} key does not match its record`);
    }
  };
  assertRecordKeys(envelope.installations, "installationId", "installation");
  assertRecordKeys(envelope.clients, "clientId", "client");
  assertRecordKeys(envelope.authorizationCodes, "codeHash", "authorization code");
  assertRecordKeys(envelope.refreshTokens, "tokenHash", "refresh token");
  assertRecordKeys(envelope.ownerSessions, "sessionHash", "owner session");
  assertRecordKeys(envelope.installationIdempotency, "keyHash", "idempotency");
}

const sortedEntries = <T>(map: Map<string, T>): PersistedMapEntry<T>[] =>
  [...map.entries()].sort(([left], [right]) => left.localeCompare(right));

/** Legacy schema-v1 client records did not carry an epoch. Keep migration at
 * the durable boundary so every in-memory consumer observes a deterministic
 * zero rather than having to branch on absent data. */
const withClientEpoch = (client: RegisteredClient): RegisteredClient => ({
  ...client,
  revocationEpoch: client.revocationEpoch ?? 0,
});

const serializeStore = (store: DurableEdgeStore): string => {
  const envelope: PersistedEdgeStore = {
    schemaVersion: EDGE_STORE_SCHEMA_VERSION,
    installations: sortedEntries(store.installations),
    clients: sortedEntries(store.clients).map(([key, value]) => [key, withClientEpoch(value)] as const),
    authorizationCodes: sortedEntries(store.authorizationCodes),
    refreshTokens: sortedEntries(store.refreshTokens),
    ownerSessions: sortedEntries(store.ownerSessions),
    revokedAccessJtis: sortedEntries(store.revokedAccessJtis),
    installationIdempotency: sortedEntries(store.installationIdempotency),
  };
  // Validate before touching the current file. A malformed direct Map mutation
  // must fail closed rather than replace a known-good snapshot.
  assertPersistedEnvelope(envelope);
  return JSON.stringify(envelope);
};

const resolveFilePath = (input: string | DurableEdgeStoreOptions): string => {
  const candidate = typeof input === "string" ? input : input.filePath ?? input.path ?? input.statePath;
  if (!candidate || typeof candidate !== "string" || candidate.trim() === "") {
    throw new DurableEdgeStoreError("invalid_path", "durable edge store file path is required");
  }
  return resolve(candidate);
};

const loadStoreFile = (filePath: string): PersistedEdgeStore | null => {
  if (!existsSync(filePath)) return null;
  let stat;
  try {
    stat = lstatSync(filePath);
    if (!stat.isFile()) throw new DurableEdgeStoreError("io", "durable edge store path is not a regular file");
  } catch (error) {
    if (error instanceof DurableEdgeStoreError) throw error;
    throw new DurableEdgeStoreError("io", "durable edge store could not be inspected", { cause: error });
  }
  try {
    // Correct an old mode before reading it. Every file emitted by this adapter is 0600.
    chmodSync(filePath, 0o600);
    const text = readFileSync(filePath, "utf8");
    const parsed: unknown = JSON.parse(text);
    assertPersistedEnvelope(parsed);
    return parsed;
  } catch (error) {
    if (error instanceof DurableEdgeStoreError) throw error;
    throw new DurableEdgeStoreError("corrupt", "durable edge store is corrupt", { cause: error });
  }
};

/**
 * Write a complete replacement and make it current with one rename. The temp
 * file and final file are both private, and both file and directory metadata
 * are synced before this operation resolves.
 */
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
    throw new DurableEdgeStoreError("io", "durable edge store write failed", { cause: error });
  }
};

/**
 * A file-backed EdgeStore. Maps intentionally remain ordinary maps so the
 * existing service code does not need a new persistence-aware collection API.
 * Call flush() after a completed mutation (the service integration point is
 * documented in the parent task); credentialLeases are process-local by design.
 */
export class DurableEdgeStore implements DurableEdgeStoreLike {
  readonly installations = new Map<string, InstallationRecord>();
  readonly clients = new Map<string, RegisteredClient>();
  readonly authorizationCodes = new Map<string, AuthorizationCodeRecord>();
  readonly refreshTokens = new Map<string, RefreshTokenRecord>();
  readonly ownerSessions = new Map<string, OwnerSession>();
  readonly revokedAccessJtis = new Map<string, number>();
  readonly credentialLeases = new Map<string, CredentialLease>();
  readonly installationIdempotency = new Map<string, InstallationIdempotencyRecord>();
  readonly isDurable = true as const;
  readonly filePath: string;

  private writeChain: Promise<void> = Promise.resolve();

  constructor(input: string | DurableEdgeStoreOptions) {
    this.filePath = resolveFilePath(input);
    const persisted = loadStoreFile(this.filePath);
    if (!persisted) return;
    for (const [key, value] of persisted.installations) this.installations.set(key, value);
    for (const [key, value] of persisted.clients) this.clients.set(key, withClientEpoch(value));
    for (const [key, value] of persisted.authorizationCodes) this.authorizationCodes.set(key, value);
    for (const [key, value] of persisted.refreshTokens) this.refreshTokens.set(key, value);
    for (const [key, value] of persisted.ownerSessions) this.ownerSessions.set(key, value);
    for (const [key, value] of persisted.revokedAccessJtis) this.revokedAccessJtis.set(key, value);
    for (const [key, value] of persisted.installationIdempotency) this.installationIdempotency.set(key, value);
  }

  /**
   * Persist a snapshot. Concurrent calls on this adapter instance are
   * serialized and each is atomic; this is not a cross-process transaction
   * boundary (production multi-worker deployments need a single writer or a
   * transactional repository above this Map-shaped compatibility port).
   */
  flush(): Promise<void> {
    const operation = this.writeChain.then(async () => {
      const contents = serializeStore(this);
      await atomicWrite(this.filePath, contents);
    });
    this.writeChain = operation.catch(() => undefined);
    return operation;
  }
}

/** Factory aliases keep the adapter convenient for both constructor and DI callers. */
export const createDurableEdgeStore = (input: string | DurableEdgeStoreOptions): DurableEdgeStore => new DurableEdgeStore(input);
export const createDurableStore = createDurableEdgeStore;
export const openDurableEdgeStore = createDurableEdgeStore;
