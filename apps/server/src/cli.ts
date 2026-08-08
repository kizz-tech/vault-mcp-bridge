import { createPairingCode } from "./app.js";
import { loadConfig } from "./config.js";
import { VaultStore } from "./store.js";
import { OpaqueIdSchema, normalizeVaultId } from "@vault-mcp-bridge/contracts";
import { importPrivateSnapshot } from "./private-import.js";

const readBoundedStdin = async (maximumBytes: number): Promise<string> => {
  const chunks: Buffer[] = [];
  let bytes = 0;
  for await (const chunk of process.stdin) {
    const value = Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk));
    bytes += value.length;
    if (bytes > maximumBytes) throw new Error("snapshot exceeds input limit");
    chunks.push(value);
  }
  if (bytes === 0) throw new Error("snapshot JSON is required on stdin");
  return Buffer.concat(chunks, bytes).toString("utf8");
};

const args = process.argv.slice(2);
const config = loadConfig();
const store = new VaultStore(config.databasePath);
try {
  if (args[0] === "pairing-code") {
    const vaultIndex = args.indexOf("--vault-id");
    const vaultAlias = vaultIndex >= 0 ? args[vaultIndex + 1] : undefined;
    if (!vaultAlias) throw new Error("--vault-id is required");
    const vaultId = normalizeVaultId(vaultAlias);
    const ttlIndex = args.indexOf("--ttl-seconds");
    const ttl = ttlIndex >= 0 ? Number.parseInt(args[ttlIndex + 1] ?? "", 10) : config.pairingTtlSeconds;
    if (!Number.isInteger(ttl) || ttl < 30 || ttl > 86_400) throw new Error("invalid --ttl-seconds");
    const pairing = createPairingCode(store, vaultId, ttl);
    process.stdout.write(`${JSON.stringify({ vaultId: pairing.vaultId, code: pairing.code, expiresAt: pairing.expiresAt })}\n`);
  } else if (args[0] === "revoke-device") {
    const deviceIndex = args.indexOf("--device-id");
    const deviceId = deviceIndex >= 0 ? args[deviceIndex + 1] : undefined;
    if (!deviceId || !/^[A-Za-z0-9_-]{16,256}$/u.test(deviceId)) throw new Error("--device-id must be an opaque identifier");
    const revoked = store.revokeDevice(deviceId);
    process.stdout.write(`${JSON.stringify({ deviceId, revoked })}\n`);
    if (!revoked) process.exitCode = 2;
  } else if (args[0] === "private-import") {
    if (process.env.PRIVATE_SNAPSHOT_IMPORT !== "1") throw new Error("private snapshot import is disabled");
    const vaultIndex = args.indexOf("--vault-id");
    const vaultId = OpaqueIdSchema.parse(vaultIndex >= 0 ? args[vaultIndex + 1] : undefined);
    const deviceIndex = args.indexOf("--device-id");
    const deviceId = OpaqueIdSchema.parse(deviceIndex >= 0 ? args[deviceIndex + 1] : undefined);
    if (config.mcpVaultId && config.mcpVaultId !== vaultId) throw new Error("--vault-id does not match MCP_VAULT_ID");
    const result = importPrivateSnapshot(store, {
      expectedVaultId: vaultId,
      deviceId,
      snapshotJson: await readBoundedStdin(config.maxSnapshotBytes),
    });
    process.stdout.write(`${JSON.stringify({
      version: 1,
      ...result,
      receivedAt: new Date(result.receivedAt * 1000).toISOString(),
    })}\n`);
  } else {
    throw new Error("usage: server <pairing-code --vault-id <id> | revoke-device --device-id <id> | private-import --vault-id <id> --device-id <id>>");
  }
} finally {
  store.close();
}
