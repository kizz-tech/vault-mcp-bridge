import { createPairingCode } from "./app.js";
import { loadConfig } from "./config.js";
import { VaultStore } from "./store.js";
import { normalizeVaultId } from "@vault-mcp-bridge/contracts";

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
  } else {
    throw new Error("usage: server <pairing-code --vault-id <id> | revoke-device --device-id <id>>");
  }
} finally {
  store.close();
}
