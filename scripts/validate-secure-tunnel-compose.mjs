#!/usr/bin/env node
/* global console, process */
/** Validate the primary Secure Tunnel Compose template without starting it. */

import { copyFileSync, mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";

const root = resolve(import.meta.dirname, "..");
const sourcePath = resolve(root, process.argv[2] ?? "deploy/secure-tunnel/compose.example.yaml");
const source = await import("node:fs/promises").then(({ readFile }) => readFile(sourcePath, "utf8"));
const failures = [];

function requirePattern(pattern, message) {
  if (!pattern.test(source)) failures.push(message);
}

requirePattern(/^name:\s*\$\{COMPOSE_PROJECT_NAME/mu, "Compose project name must be installation-scoped");
requirePattern(/^ {2}runtime:\s*$/mu, "missing runtime service");
requirePattern(/^ {2}runtime_secrets_init:\s*$/mu, "missing secret-init service");
requirePattern(/image:\s*\$\{VAULT_BRIDGE_IMAGE/mu, "runtime image must come from the validated product configuration");
requirePattern(/user:\s*"10001:10001"/u, "runtime must use the unprivileged application UID");
requirePattern(/read_only:\s*true/u, "runtime filesystem must be read-only");
requirePattern(/cap_drop:\s*\[ALL\]/u, "runtime must drop every Linux capability");
requirePattern(/no-new-privileges:true/u, "runtime must disable privilege escalation");
requirePattern(/runtime_secrets:\/run\/secrets:ro/u, "runtime secret volume must be read-only");
requirePattern(/network_mode:\s*none/u, "secret-init must have no network");
requirePattern(/control_plane_api_key:\s*\n\s+file:\s*\.\/secrets\/control-plane-api-key/u, "runtime key must use a Compose file secret");
requirePattern(/replica_data:\/var\/lib\/vault-mcp-bridge/u, "replica must use its named data volume");
requirePattern(/max-size:\s*8m/u, "container logs must be size-limited");

for (const [pattern, message] of [
  [/^\s+ports:\s*$/mu, "host ports are forbidden"],
  [/container_name:/u, "fixed container names are forbidden"],
  [/privileged:\s*true/iu, "privileged containers are forbidden"],
  [/network_mode:\s*host/iu, "host networking is forbidden"],
  [/docker\.sock|\/var\/run\/docker\.sock/u, "Docker socket mounts are forbidden"],
  [/\$\{CONTROL_PLANE_API_KEY/u, "runtime key must never be passed through the environment"]
]) {
  if (pattern.test(source)) failures.push(message);
}

const serviceNames = [...source.matchAll(/^ {2}([A-Za-z0-9_.-]+):\s*$/gmu)].map((match) => match[1]);
if (serviceNames.join(",") !== "runtime,runtime_secrets_init,replica_data,runtime_secrets,control_plane_api_key") {
  // The indentation pattern also sees top-level volume and secret entries. An
  // exact list makes accidental service or storage expansion review-visible.
  failures.push(`unexpected Compose entries: ${serviceNames.join(",")}`);
}

const temporary = mkdtempSync(join(tmpdir(), "vmb-secure-compose-"));
try {
  copyFileSync(sourcePath, join(temporary, "compose.yaml"));
  mkdirSync(join(temporary, "secrets"), { mode: 0o700 });
  writeFileSync(join(temporary, "secrets", "control-plane-api-key"), "TEST_RUNTIME_API_KEY_000000000\n", { mode: 0o600 });
  const compose = spawnSync("docker", ["compose", "-f", "compose.yaml", "config", "--quiet"], {
    cwd: temporary,
    encoding: "utf8",
    timeout: 20_000,
    env: {
      ...process.env,
      COMPOSE_PROJECT_NAME: "vmb-test0123456789ab",
      VAULT_BRIDGE_IMAGE: `ghcr.io/example/vault-bridge@sha256:${"a".repeat(64)}`,
      CONTROL_PLANE_TUNNEL_ID: `tunnel_${"b".repeat(32)}`,
      MCP_VAULT_ID: `vault_${"c".repeat(32)}`
    }
  });
  if (compose.error?.code === "ENOENT") console.warn("WARN docker compose is unavailable; structural checks only");
  else if (compose.status !== 0) failures.push("docker compose config rejected the Secure Tunnel template");
} finally {
  rmSync(temporary, { recursive: true, force: true });
}

if (failures.length) {
  for (const failure of failures) console.error(`ERROR ${failure}`);
  process.exitCode = 1;
} else {
  console.log(`Secure Tunnel Compose OK: ${sourcePath}`);
}
