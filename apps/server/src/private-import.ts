import { OpaqueIdSchema, SnapshotSchema, computeSnapshotDigest } from "@vault-mcp-bridge/contracts";
import { SnapshotError, type UploadResult, type VaultStore } from "./store.js";

export type PrivateSnapshotImport = {
  expectedVaultId: string;
  deviceId: string;
  snapshotJson: string;
};

/**
 * Import one already-local snapshot through the fixed SSH/Docker admin path.
 * The remote vault copy remains derived and activation stays atomic inside
 * VaultStore. No filesystem path or credential is accepted in this command.
 */
export const importPrivateSnapshot = (store: VaultStore, input: PrivateSnapshotImport): UploadResult => {
  const expectedVaultId = OpaqueIdSchema.parse(input.expectedVaultId);
  const deviceId = OpaqueIdSchema.parse(input.deviceId);
  let raw: unknown;
  try {
    raw = JSON.parse(input.snapshotJson) as unknown;
  } catch {
    throw new SnapshotError("snapshot JSON is invalid", 400);
  }
  const parsed = SnapshotSchema.safeParse(raw);
  if (!parsed.success || computeSnapshotDigest(parsed.data) !== parsed.data.digest) {
    throw new SnapshotError("snapshot validation failed", 400);
  }
  if (parsed.data.vaultId !== expectedVaultId) throw new SnapshotError("snapshot vault is not allowed", 403);
  store.ensurePrivateImportDevice(deviceId, expectedVaultId);
  return store.activateSnapshot(parsed.data, deviceId);
};
