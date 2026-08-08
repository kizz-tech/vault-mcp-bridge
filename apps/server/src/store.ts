import { mkdirSync, readdirSync, statSync, statfsSync } from "node:fs";
import { basename, dirname } from "node:path";
import { DatabaseSync, type StatementSync } from "node:sqlite";
import { randomUUID } from "node:crypto";
import { hashPairingCode } from "./crypto.js";
import { computeSnapshotDigest, SnapshotSchema } from "@vault-mcp-bridge/contracts";
import type { FetchOutput, PairingConsumeInput, SearchOutput, Snapshot } from "./types.js";

export type DeviceRecord = {
  deviceId: string;
  vaultId: string;
  publicKey: Buffer;
  name: string | null;
  createdAt: number;
  revokedAt: number | null;
};

export type PairingRecord = {
  code: string;
  vaultId: string;
  expiresAt: number;
};

export type PairingConsumeResult = {
  device: DeviceRecord;
  idempotent: boolean;
};

export type UploadResult = {
  accepted: boolean;
  idempotent: boolean;
  snapshotId: string;
  vaultId: string;
  generation: number;
  digest: string;
  documentCount: number;
  receivedAt: number;
};

type SnapshotRow = {
  snapshot_id: string;
  vault_id: string;
  generation: number;
  digest: string;
  created_at: number;
};

export type StorageLimits = {
  maxVaultBytes: number;
  maxDatabaseBytes: number;
  maxIndexBytes: number;
  maxTempBytes: number;
  minFreeBytes: number;
  maxRetainedGenerations: number;
};

export type StorageStatus = {
  databaseBytes: number;
  indexBytes: number;
  tempBytes: number;
  freeBytes: number | null;
  maxDatabaseBytes: number;
  maxIndexBytes: number;
  maxTempBytes: number;
  minFreeBytes: number;
};

const DEFAULT_STORAGE_LIMITS: StorageLimits = {
  maxVaultBytes: 512 * 1024 * 1024,
  maxDatabaseBytes: 2 * 1024 * 1024 * 1024,
  maxIndexBytes: 1024 * 1024 * 1024,
  maxTempBytes: 128 * 1024 * 1024,
  // Tests and :memory: stores do not have a meaningful host free-space floor.
  minFreeBytes: 0,
  maxRetainedGenerations: 2,
};

export const SQLITE_SCHEMA_VERSION = 1;

const nowSeconds = (): number => Math.floor(Date.now() / 1000);

const toDocument = (row: Record<string, unknown>): FetchOutput => {
  const metadata = row.metadata_json ? JSON.parse(String(row.metadata_json)) as FetchOutput["metadata"] : undefined;
  const output: FetchOutput = {
    id: String(row.document_id),
    title: String(row.title),
    text: String(row.text),
    url: "",
  };
  if (metadata) output.metadata = metadata;
  return output;
};

export class VaultStore {
  readonly db: DatabaseSync;
  readonly nonceRetentionSeconds: number;
  readonly storageLimits: StorageLimits;
  private readonly databasePath: string;

  constructor(databasePath = ":memory:", nonceRetentionSeconds = 86_400, storageLimits: Partial<StorageLimits> = {}) {
    this.nonceRetentionSeconds = nonceRetentionSeconds;
    this.storageLimits = {
      ...DEFAULT_STORAGE_LIMITS,
      ...storageLimits,
      maxRetainedGenerations: Math.max(2, storageLimits.maxRetainedGenerations ?? DEFAULT_STORAGE_LIMITS.maxRetainedGenerations),
    };
    this.databasePath = databasePath;
    if (databasePath !== ":memory:") mkdirSync(dirname(databasePath), { recursive: true });
    this.db = new DatabaseSync(databasePath);
    this.db.exec("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000; PRAGMA temp_store=FILE;");
    if (databasePath !== ":memory:" && this.storageLimits.maxDatabaseBytes > 0) {
      const pageRow = this.db.prepare("PRAGMA page_size").get() as Record<string, unknown> | undefined;
      const pageSize = Number(pageRow?.page_size ?? 4096);
      const maxPages = Math.floor(this.storageLimits.maxDatabaseBytes / Math.max(1, pageSize));
      if (maxPages > 0) this.db.exec(`PRAGMA max_page_count=${maxPages}`);
    }
    const versionRow = this.db.prepare("PRAGMA user_version").get() as Record<string, unknown> | undefined;
    const userVersion = Number(versionRow?.user_version ?? 0);
    if (!Number.isInteger(userVersion) || userVersion < 0 || userVersion > SQLITE_SCHEMA_VERSION) {
      this.db.close();
      throw new Error(`unsupported SQLite schema version: ${String(versionRow?.user_version ?? userVersion)}`);
    }
    this.db.exec("BEGIN IMMEDIATE");
    try {
      this.db.exec(`
      CREATE TABLE IF NOT EXISTS pairing_codes (
        code_hash TEXT PRIMARY KEY,
        vault_id TEXT NOT NULL,
        expires_at INTEGER NOT NULL,
        consumed_at INTEGER
      );
      CREATE TABLE IF NOT EXISTS devices (
        device_id TEXT PRIMARY KEY,
        vault_id TEXT NOT NULL,
        public_key BLOB NOT NULL,
        name TEXT,
        created_at INTEGER NOT NULL,
        revoked_at INTEGER
      );
      CREATE TABLE IF NOT EXISTS used_nonces (
        device_id TEXT NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,
        nonce TEXT NOT NULL,
        used_at INTEGER NOT NULL,
        PRIMARY KEY (device_id, nonce)
      );
      CREATE INDEX IF NOT EXISTS used_nonces_used_at ON used_nonces(used_at);
      CREATE TABLE IF NOT EXISTS snapshots (
        snapshot_id TEXT PRIMARY KEY,
        vault_id TEXT NOT NULL,
        generation INTEGER NOT NULL,
        digest TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        device_id TEXT NOT NULL REFERENCES devices(device_id)
      );
      CREATE UNIQUE INDEX IF NOT EXISTS snapshots_vault_generation ON snapshots(vault_id, generation);
      CREATE TABLE IF NOT EXISTS documents (
        document_id TEXT NOT NULL,
        snapshot_id TEXT NOT NULL REFERENCES snapshots(snapshot_id) ON DELETE CASCADE,
        title TEXT NOT NULL,
        media_type TEXT NOT NULL,
        text TEXT NOT NULL,
        source_hash TEXT NOT NULL,
        modified_at TEXT,
        metadata_json TEXT,
        PRIMARY KEY (snapshot_id, document_id)
      );
      CREATE VIRTUAL TABLE IF NOT EXISTS documents_fts USING fts5(
        document_id UNINDEXED,
        snapshot_id UNINDEXED,
        title,
        text,
        tokenize='unicode61'
      );
      CREATE TABLE IF NOT EXISTS active_snapshots (
        vault_id TEXT PRIMARY KEY,
        snapshot_id TEXT NOT NULL REFERENCES snapshots(snapshot_id),
        generation INTEGER NOT NULL,
        activated_at INTEGER NOT NULL
      );
      `);
      // Version 0 is the legacy auto-created schema. Its DDL is idempotent;
      // recording version 1 in the same transaction makes upgrades atomic.
      this.db.exec(`PRAGMA user_version=${SQLITE_SCHEMA_VERSION}`);
      this.db.exec("COMMIT");
    } catch (error) {
      try { this.db.exec("ROLLBACK"); } catch { /* preserve migration error */ }
      this.db.close();
      throw error;
    }
  }

  close(): void {
    this.db.close();
  }

  /** Apply the app-level limits to injected stores as well as owned stores. */
  configureStorageLimits(limits: Partial<StorageLimits>): void {
    Object.assign(this.storageLimits, limits);
    this.storageLimits.maxRetainedGenerations = Math.max(2, this.storageLimits.maxRetainedGenerations);
  }

  private fileBytes(path: string): number {
    try {
      const stats = statSync(path);
      return stats.isFile() ? stats.size : 0;
    } catch {
      return 0;
    }
  }

  private sidecarBytes(): number {
    if (this.databasePath === ":memory:") return 0;
    return ["-wal", "-shm", "-journal"].reduce((total, suffix) => total + this.fileBytes(`${this.databasePath}${suffix}`), 0);
  }

  private tempFileBytes(): number {
    if (this.databasePath === ":memory:") return 0;
    const directory = dirname(this.databasePath);
    const prefix = basename(this.databasePath);
    try {
      return readdirSync(directory, { withFileTypes: true }).reduce((total, entry) => {
        if (!entry.isFile() || !(entry.name.startsWith("etilqs_") || entry.name.startsWith(`${prefix}-tmp`))) return total;
        return total + this.fileBytes(`${directory}/${entry.name}`);
      }, this.sidecarBytes());
    } catch {
      return this.sidecarBytes();
    }
  }

  private freeBytes(): number | null {
    if (this.databasePath === ":memory:") return null;
    try {
      const stats = statfsSync(dirname(this.databasePath));
      return Number(stats.bavail) * Number(stats.bsize);
    } catch {
      return null;
    }
  }

  private indexBytes(): number {
    try {
      const row = this.statement("SELECT COALESCE(SUM(pgsize), 0) AS bytes FROM dbstat WHERE name = 'documents_fts' OR name LIKE 'documents_fts_%'").get() as Record<string, unknown>;
      return Number(row.bytes) || 0;
    } catch {
      // dbstat is optional in SQLite builds. The aggregate database limit is
      // still enforced, so absence of this introspection fails safe enough.
      return 0;
    }
  }

  storageStatus(): StorageStatus {
    return {
      databaseBytes: this.databasePath === ":memory:" ? 0 : this.fileBytes(this.databasePath) + this.sidecarBytes(),
      indexBytes: this.indexBytes(),
      tempBytes: this.tempFileBytes(),
      freeBytes: this.freeBytes(),
      maxDatabaseBytes: this.storageLimits.maxDatabaseBytes,
      maxIndexBytes: this.storageLimits.maxIndexBytes,
      maxTempBytes: this.storageLimits.maxTempBytes,
      minFreeBytes: this.storageLimits.minFreeBytes,
    };
  }

  readiness(): { ok: boolean; storage: StorageStatus } {
    try {
      this.statement("SELECT 1").get();
      const storage = this.storageStatus();
      const ok = storage.databaseBytes <= storage.maxDatabaseBytes
        && storage.indexBytes <= storage.maxIndexBytes
        && storage.tempBytes <= storage.maxTempBytes
        && (storage.freeBytes === null || storage.freeBytes >= storage.minFreeBytes);
      return { ok, storage };
    } catch {
      return { ok: false, storage: this.storageStatus() };
    }
  }

  private retainedSnapshotBytes(vaultId: string, minimumGeneration: number): number {
    const row = this.statement("SELECT COALESCE(SUM(LENGTH(d.title) + LENGTH(d.text) + LENGTH(d.source_hash) + COALESCE(LENGTH(d.metadata_json), 0) + 64), 0) AS bytes FROM documents d JOIN snapshots s ON s.snapshot_id = d.snapshot_id WHERE s.vault_id = ? AND s.generation >= ?").get(vaultId, minimumGeneration) as Record<string, unknown>;
    // FTS stores title/text a second time; account for that duplication even
    // when the optional SQLite dbstat virtual table is unavailable.
    return Math.max(0, Number(row.bytes) || 0) * 2;
  }

  private assertCapacity(snapshot: Snapshot): void {
    const incomingBytes = Buffer.byteLength(JSON.stringify(snapshot), "utf8") * 2;
    if (incomingBytes > this.storageLimits.maxVaultBytes) throw new SnapshotError("snapshot exceeds vault storage quota", 413);
    const retained = this.retainedSnapshotBytes(snapshot.vaultId, snapshot.generation - this.storageLimits.maxRetainedGenerations + 1);
    if (retained + incomingBytes > this.storageLimits.maxVaultBytes) throw new SnapshotError("vault storage quota exceeded", 413);
    const status = this.storageStatus();
    if (status.databaseBytes + incomingBytes > status.maxDatabaseBytes) throw new SnapshotError("server storage quota exceeded", 507);
    if (status.indexBytes > status.maxIndexBytes) throw new SnapshotError("server index quota exceeded", 507);
    if (status.tempBytes > status.maxTempBytes) throw new SnapshotError("server temporary storage quota exceeded", 507);
    if (status.freeBytes !== null && status.freeBytes < status.minFreeBytes + incomingBytes) throw new SnapshotError("server free-space floor reached", 507);
  }

  private assertPostWriteCapacity(snapshot: Snapshot): void {
    const status = this.storageStatus();
    if (status.databaseBytes > status.maxDatabaseBytes || status.indexBytes > status.maxIndexBytes || status.tempBytes > status.maxTempBytes) {
      throw new SnapshotError("snapshot exceeds server storage quota", 507);
    }
    const retained = this.retainedSnapshotBytes(snapshot.vaultId, snapshot.generation - this.storageLimits.maxRetainedGenerations + 1);
    if (retained > this.storageLimits.maxVaultBytes) throw new SnapshotError("vault storage quota exceeded", 413);
  }

  private checkpointWal(): void {
    if (this.databasePath === ":memory:") return;
    try {
      this.db.exec("PRAGMA wal_checkpoint(TRUNCATE)");
    } catch {
      // A concurrent reader may hold the WAL briefly. The next request/readiness
      // check will observe the bounded sidecar and retry naturally.
    }
  }

  private statement(sql: string): StatementSync {
    return this.db.prepare(sql);
  }

  createPairingCode(vaultId: string, ttlSeconds: number, code: string): PairingRecord {
    const expiresAt = nowSeconds() + ttlSeconds;
    this.statement("INSERT INTO pairing_codes(code_hash, vault_id, expires_at) VALUES (?, ?, ?)").run(hashPairingCode(code), vaultId, expiresAt);
    return { code, vaultId, expiresAt };
  }

  consumePairingCode(input: PairingConsumeInput): DeviceRecord {
    return this.consumePairingCodeResult(input).device;
  }

  consumePairingCodeResult(input: PairingConsumeInput): PairingConsumeResult {
    const now = nowSeconds();
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const row = this.statement("SELECT code_hash, vault_id, expires_at, consumed_at FROM pairing_codes WHERE code_hash = ?").get(hashPairingCode(input.pairCode)) as Record<string, unknown> | undefined;
      if (!row || Number(row.expires_at) <= now || row.consumed_at !== null) throw new PairingError("invalid or expired pairing code", 400);
      if (input.vaultId && input.vaultId !== String(row.vault_id)) throw new PairingError("vault is not allowed", 403);
      const key = Buffer.from(input.publicKey, "base64url");
      if (key.length < 32 || key.length > 128) throw new PairingError("invalid public key", 400);

      const existing = this.statement("SELECT device_id, vault_id, public_key, name, created_at, revoked_at FROM devices WHERE device_id = ?").get(input.agentId) as Record<string, unknown> | undefined;
      if (existing) {
        const existingKey = Buffer.from(existing.public_key as Uint8Array);
        const sameIdentity = String(existing.vault_id) === String(row.vault_id) && existingKey.equals(key);
        // A revoked identity must never be silently reactivated by a retry.
        if (!sameIdentity || existing.revoked_at !== null) throw new PairingError("device id is already paired", 409);
        const consumed = this.statement("UPDATE pairing_codes SET consumed_at = ? WHERE code_hash = ? AND consumed_at IS NULL").run(now, String(row.code_hash));
        if (Number(consumed.changes) !== 1) throw new PairingError("invalid or expired pairing code", 400);
        this.db.exec("COMMIT");
        return {
          idempotent: true,
          device: {
            deviceId: String(existing.device_id),
            vaultId: String(existing.vault_id),
            publicKey: existingKey,
            name: existing.name === null ? null : String(existing.name),
            createdAt: Number(existing.created_at),
            revokedAt: null,
          },
        };
      }

      const consumed = this.statement("UPDATE pairing_codes SET consumed_at = ? WHERE code_hash = ? AND consumed_at IS NULL").run(now, String(row.code_hash));
      if (Number(consumed.changes) !== 1) throw new PairingError("invalid or expired pairing code", 400);
      this.statement("INSERT INTO devices(device_id, vault_id, public_key, name, created_at) VALUES (?, ?, ?, ?, ?)").run(input.agentId, String(row.vault_id), key, input.label ?? null, now);
      this.db.exec("COMMIT");
      return { idempotent: false, device: { deviceId: input.agentId, vaultId: String(row.vault_id), publicKey: key, name: input.label ?? null, createdAt: now, revokedAt: null } };
    } catch (error) {
      this.db.exec("ROLLBACK");
      throw error;
    }
  }

  getDevice(deviceId: string): DeviceRecord | null {
    const row = this.statement("SELECT device_id, vault_id, public_key, name, created_at, revoked_at FROM devices WHERE device_id = ?").get(deviceId) as Record<string, unknown> | undefined;
    if (!row) return null;
    return {
      deviceId: String(row.device_id),
      vaultId: String(row.vault_id),
      publicKey: Buffer.from(row.public_key as Uint8Array),
      name: row.name === null ? null : String(row.name),
      createdAt: Number(row.created_at),
      revokedAt: row.revoked_at === null ? null : Number(row.revoked_at),
    };
  }

  revokeDevice(deviceId: string): boolean {
    const result = this.statement("UPDATE devices SET revoked_at = ? WHERE device_id = ? AND revoked_at IS NULL").run(nowSeconds(), deviceId);
    return Number(result.changes) === 1;
  }

  /**
   * Provision the non-network identity used only by the fixed private import
   * command. It cannot authenticate to the signed publisher HTTP surface.
   */
  ensurePrivateImportDevice(deviceId: string, vaultId: string): void {
    const marker = Buffer.from("vault-mcp-bridge:private-import:v1", "utf8");
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const existing = this.statement("SELECT vault_id, public_key, name, revoked_at FROM devices WHERE device_id = ?").get(deviceId) as Record<string, unknown> | undefined;
      if (existing) {
        const matches = String(existing.vault_id) === vaultId
          && Buffer.from(existing.public_key as Uint8Array).equals(marker)
          && existing.name === "Private tunnel importer"
          && existing.revoked_at === null;
        if (!matches) throw new SnapshotError("private import device conflicts with an existing identity", 409);
        this.db.exec("COMMIT");
        return;
      }
      this.statement("INSERT INTO devices(device_id, vault_id, public_key, name, created_at) VALUES (?, ?, ?, ?, ?)")
        .run(deviceId, vaultId, marker, "Private tunnel importer", nowSeconds());
      this.db.exec("COMMIT");
    } catch (error) {
      this.db.exec("ROLLBACK");
      throw error;
    }
  }

  consumeNonce(deviceId: string, nonce: string): boolean {
    try {
      const now = nowSeconds();
      this.statement("DELETE FROM used_nonces WHERE used_at < ?").run(now - this.nonceRetentionSeconds);
      this.statement("INSERT INTO used_nonces(device_id, nonce, used_at) VALUES (?, ?, ?)").run(deviceId, nonce, now);
      return true;
    } catch {
      return false;
    }
  }

  getActive(vaultId: string): { snapshotId: string; generation: number; activatedAt: number } | null {
    const row = this.statement("SELECT snapshot_id, generation, activated_at FROM active_snapshots WHERE vault_id = ?").get(vaultId) as Record<string, unknown> | undefined;
    if (!row) return null;
    return { snapshotId: String(row.snapshot_id), generation: Number(row.generation), activatedAt: Number(row.activated_at) };
  }

  firstActiveVaultId(): string | null {
    const row = this.statement("SELECT vault_id FROM active_snapshots ORDER BY activated_at DESC LIMIT 1").get() as Record<string, unknown> | undefined;
    return row ? String(row.vault_id) : null;
  }

  getSnapshot(snapshotId: string): SnapshotRow | null {
    const row = this.statement("SELECT snapshot_id, vault_id, generation, digest, created_at FROM snapshots WHERE snapshot_id = ?").get(snapshotId) as SnapshotRow | undefined;
    return row ?? null;
  }

  activateSnapshot(snapshot: Snapshot, deviceId: string): UploadResult {
    try {
      SnapshotSchema.parse(snapshot);
      if (computeSnapshotDigest(snapshot) !== snapshot.digest) throw new Error("digest mismatch");
    } catch {
      throw new SnapshotError("snapshot validation failed", 400);
    }
    this.assertCapacity(snapshot);
    const receivedAt = nowSeconds();

    this.db.exec("BEGIN IMMEDIATE");
    try {
      // Device, existing-snapshot and active-generation checks are all under
      // the same write lock as insertion and pointer activation. This keeps
      // two VaultStore instances sharing SQLite from validating stale state.
      const device = this.statement("SELECT vault_id, revoked_at FROM devices WHERE device_id = ?").get(deviceId) as Record<string, unknown> | undefined;
      if (!device || device.revoked_at !== null || String(device.vault_id) !== snapshot.vaultId) throw new SnapshotError("device is not allowed", 403);
      const existing = this.statement("SELECT snapshot_id, vault_id, generation, digest FROM snapshots WHERE snapshot_id = ?").get(snapshot.snapshotId) as SnapshotRow | undefined;
      const active = this.statement("SELECT snapshot_id, generation, activated_at FROM active_snapshots WHERE vault_id = ?").get(snapshot.vaultId) as Record<string, unknown> | undefined;
      if (existing) {
        if (existing.digest !== snapshot.digest || existing.vault_id !== snapshot.vaultId || existing.generation !== snapshot.generation) {
          throw new SnapshotError("snapshot id is already bound to another digest", 409);
        }
        // A retained but inactive generation is stale, not a successful retry.
        if (!active || String(active.snapshot_id) !== snapshot.snapshotId || Number(active.generation) !== snapshot.generation) {
          throw new SnapshotError("snapshot is retained but inactive", 409);
        }
        this.db.exec("COMMIT");
        return { accepted: true, idempotent: true, snapshotId: snapshot.snapshotId, vaultId: snapshot.vaultId, generation: snapshot.generation, digest: snapshot.digest, documentCount: snapshot.documents.length, receivedAt: Number(active.activated_at) };
      }
      if (active && snapshot.generation <= Number(active.generation)) throw new SnapshotError("snapshot generation is not newer than active generation", 409);

      this.statement("INSERT INTO snapshots(snapshot_id, vault_id, generation, digest, created_at, device_id) VALUES (?, ?, ?, ?, ?, ?)").run(snapshot.snapshotId, snapshot.vaultId, snapshot.generation, snapshot.digest, receivedAt, deviceId);
      const insertDocument = this.statement("INSERT INTO documents(document_id, snapshot_id, title, media_type, text, source_hash, modified_at, metadata_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?)");
      const insertFts = this.statement("INSERT INTO documents_fts(document_id, snapshot_id, title, text) VALUES (?, ?, ?, ?)");
      for (const document of snapshot.documents) {
        const metadataJson = document.metadata ? JSON.stringify(document.metadata) : null;
        insertDocument.run(document.id, snapshot.snapshotId, document.title, document.mediaType, document.text, document.sourceHash, document.modifiedAt ?? null, metadataJson);
        insertFts.run(document.id, snapshot.snapshotId, document.title, document.text);
      }
      this.assertPostWriteCapacity(snapshot);
      if (active) {
        const updated = this.statement("UPDATE active_snapshots SET snapshot_id = ?, generation = ?, activated_at = ? WHERE vault_id = ? AND generation < ?").run(snapshot.snapshotId, snapshot.generation, receivedAt, snapshot.vaultId, snapshot.generation);
        if (Number(updated.changes) !== 1) throw new SnapshotError("active snapshot generation changed during activation", 409);
      } else {
        this.statement("INSERT INTO active_snapshots(vault_id, snapshot_id, generation, activated_at) VALUES (?, ?, ?, ?)").run(snapshot.vaultId, snapshot.snapshotId, snapshot.generation, receivedAt);
      }
      const cutoffGeneration = snapshot.generation - this.storageLimits.maxRetainedGenerations + 1;
      const oldRows = this.statement("SELECT snapshot_id FROM snapshots WHERE vault_id = ? AND generation < ?").all(snapshot.vaultId, cutoffGeneration) as Array<Record<string, unknown>>;
      const deleteFts = this.statement("DELETE FROM documents_fts WHERE snapshot_id = ?");
      for (const row of oldRows) deleteFts.run(String(row.snapshot_id));
      this.statement("DELETE FROM snapshots WHERE vault_id = ? AND generation < ?").run(snapshot.vaultId, cutoffGeneration);
      this.db.exec("COMMIT");
      this.checkpointWal();
      return { accepted: true, idempotent: false, snapshotId: snapshot.snapshotId, vaultId: snapshot.vaultId, generation: snapshot.generation, digest: snapshot.digest, documentCount: snapshot.documents.length, receivedAt };
    } catch (error) {
      this.db.exec("ROLLBACK");
      throw error;
    }
  }

  search(vaultId: string, query: string, limit: number): SearchOutput {
    const active = this.getActive(vaultId);
    if (!active) return { results: [] };
    const terms = query.trim().split(/\s+/u).filter(Boolean).slice(0, 32).map((term) => `"${term.replaceAll('"', '""')}"`);
    if (terms.length === 0) return { results: [] };
    let rows: unknown[];
    try {
      rows = this.statement("SELECT f.document_id, d.title FROM documents_fts f JOIN documents d ON d.document_id = f.document_id AND d.snapshot_id = f.snapshot_id WHERE f.snapshot_id = ? AND documents_fts MATCH ? ORDER BY rank LIMIT ?").all(active.snapshotId, terms.join(" OR "), Math.min(limit, 10)) as unknown[];
    } catch {
      return { results: [] };
    }
    return { results: rows.map((row) => {
      const item = row as Record<string, unknown>;
      return { id: String(item.document_id), title: String(item.title), url: "" };
    }) };
  }

  fetch(vaultId: string, documentId: string, maxBytes: number): FetchOutput | null {
    const active = this.getActive(vaultId);
    if (!active) return null;
    const row = this.statement("SELECT document_id, title, text, metadata_json FROM documents WHERE snapshot_id = ? AND document_id = ?").get(active.snapshotId, documentId) as Record<string, unknown> | undefined;
    if (!row) return null;
    const output = toDocument(row);
    if (Buffer.byteLength(output.text, "utf8") > maxBytes) throw new SnapshotError("document exceeds fetch response limit", 413);
    return output;
  }

  status(vaultId: string): { active: { snapshotId: string; generation: number; activatedAt: number } | null; documentCount: number } {
    const active = this.getActive(vaultId);
    if (!active) return { active: null, documentCount: 0 };
    const row = this.statement("SELECT COUNT(*) AS count FROM documents WHERE snapshot_id = ?").get(active.snapshotId) as Record<string, unknown>;
    return { active, documentCount: Number(row.count) };
  }

  static makeSnapshotDigest(snapshot: Omit<Snapshot, "digest">): string {
    return computeSnapshotDigest(snapshot);
  }
}

export class PairingError extends Error {
  constructor(message: string, readonly statusCode: number) {
    super(message);
    this.name = "PairingError";
  }
}

export class SnapshotError extends Error {
  constructor(message: string, readonly statusCode: number) {
    super(message);
    this.name = "SnapshotError";
  }
}

export const newVaultId = (): string => `vault_${randomUUID()}`;
