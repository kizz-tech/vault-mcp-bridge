#!/usr/bin/env node
/* global console, process */
/**
 * Validate the checked-in Compose contract without starting Docker.
 *
 * This intentionally performs structural checks instead of loading a YAML
 * library: the repository has no runtime YAML dependency, and the same checks
 * must work on a clean release runner. Docker Compose config validation is
 * attempted when the CLI is available, but a missing daemon is not treated as
 * a reason to skip the local contract checks.
 */

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { spawnSync } from "node:child_process";

const root = resolve(import.meta.dirname, "..");
const positional = process.argv.slice(2).filter((argument) => !argument.startsWith("--"));
const composePath = positional[0]
  ? resolve(process.cwd(), positional[0])
  : resolve(root, "deploy/compose.example.yaml");
const strict = process.argv.includes("--strict");
const allowLocalExample = process.argv.includes("--allow-local-example");

const source = readFileSync(composePath, "utf8");
const lines = source.split(/\r?\n/);
const errors = [];
const warnings = [];

function fail(message) {
  errors.push(message);
}

function has(pattern) {
  return pattern.test(source);
}

if (!has(/^services:\s*$/m)) fail("missing top-level services block");
if (!has(/^networks:\s*$/m)) {
  if (allowLocalExample) warnings.push("local example uses the implicit default network");
  else fail("missing top-level networks block");
}
if (!has(/^secrets:\s*$/m)) warnings.push("no top-level secrets block found");

const serviceStarts = [];
for (let index = 0; index < lines.length; index += 1) {
  const match = lines[index].match(/^ {2}([A-Za-z0-9_.-]+):\s*$/);
  if (match) serviceStarts.push({ index, name: match[1] });
}
const serviceEnd = (position) =>
  serviceStarts[position + 1]?.index ?? lines.length;
const service = (name) => {
  const position = serviceStarts.findIndex((entry) => entry.name === name);
  return position === -1
    ? null
    : lines.slice(serviceStarts[position].index, serviceEnd(position)).join("\n");
};

const server = service("server");
const serverSecretsInit = service("server_secrets_init");
if (!server) fail("missing server service");
if (server) {
  for (const required of ["read_only:", "cap_drop:", "security_opt:", "healthcheck:", "tmpfs:"]) {
    if (!server.includes(required)) fail(`server is missing ${required}`);
  }
  for (const required of ["pids_limit:", "mem_limit:", "cpus:"]) {
    if (!server.includes(required)) fail(`server is missing resource limit ${required}`);
  }
  if (!/\n\s+networks:\s*\n/.test(server)) {
    if (allowLocalExample) warnings.push("local example does not declare a server network");
    else fail("server must attach to an explicit network");
  }
  if (strict && !server.includes("server_secrets:/run/secrets:ro")) {
    fail("strict mode requires the server secret volume to be mounted read-only");
  }
  if (strict && /\n\s+secrets:\s*\n/.test(server)) {
    fail("runtime server must not mount host file-source secrets directly");
  }
}

const tunnelName = serviceStarts.find((entry) => /tunnel|cloudflared|edge/i.test(entry.name))?.name;
const tunnel = tunnelName ? service(tunnelName) : null;
if (!tunnel) {
  if (allowLocalExample) warnings.push("local example has no tunnel/edge service");
  else fail("missing tunnel/edge service");
} else {
  if (!/\n\s+networks:\s*\n/.test(tunnel)) fail(`${tunnelName} must attach to explicit networks`);
  if (!/depends_on:/.test(tunnel)) warnings.push(`${tunnelName} has no depends_on entry`);
  if (strict && !tunnel.includes("tunnel_secrets:/run/secrets:ro")) fail(`${tunnelName} must mount its secret volume read-only`);
  if (strict && /\n\s+secrets:\s*\n/.test(tunnel)) fail(`${tunnelName} must not mount host file-source secrets directly`);
}

const validateSecretInit = (name, block, volume, expectedSources) => {
  if (!block) {
    fail(`missing ${name} service`);
    return;
  }
  for (const required of ["user: \"0:0\"", "restart: \"no\"", "read_only:", "cap_drop:", "cap_add:", "CHOWN", "DAC_OVERRIDE", "no-new-privileges:true", "network_mode: none", "entrypoint:", "secrets:"]) {
    if (!block.includes(required)) fail(`${name} is missing ${required}`);
  }
  if (!block.includes(`${volume}:/out:rw`)) fail(`${name} must write only its named secret volume`);
  if (/\n\s+networks:\s*\n/.test(block) || /\n\s+ports:\s*\n/.test(block)) fail(`${name} must not attach to a network or publish ports`);
  for (const source of expectedSources) {
    if (!block.includes(`source: ${source}`)) fail(`${name} is missing source ${source}`);
  }
};

if (strict && !allowLocalExample) {
  validateSecretInit("server_secrets_init", serverSecretsInit, "server_secrets", ["publisher_edge_attestation", "mcp_edge_attestation", "oauth_verification_bundle"]);
  validateSecretInit("tunnel_secrets_init", service("tunnel_secrets_init"), "tunnel_secrets", ["tunnel_credential"]);
}

if (/^\s+ports:\s*$/m.test(source)) {
  if (allowLocalExample) warnings.push("local example publishes a loopback port; production must be tunnel-only");
  else fail("host ports are forbidden; ingress must be tunnel-only");
}
if (/^\s+container_name:\s*\S+/m.test(source)) fail("container_name is forbidden; Compose project isolation owns names");
if (/^\s+privileged:\s*true\s*$/im.test(source)) fail("privileged containers are forbidden");
if (/^\s+network_mode:\s*host\s*$/im.test(source)) fail("host network mode is forbidden");
if (/docker\.sock|\/var\/run\/docker\.sock/.test(source)) fail("Docker socket mounts are forbidden");
const projectName = source.match(/^name:\s*(\S+)\s*$/m)?.[1];
if (strict && !allowLocalExample && !projectName) fail("strict mode requires an installation-scoped Compose project name");
if (projectName && !/^vmb-[0-9a-f]{12}$/.test(projectName)) {
  if (allowLocalExample) warnings.push("local example uses a fixed Compose name; production must generate vmb-* per installation");
  else fail("top-level Compose name must be an installation-scoped vmb-<12 hex> project name");
}

const networkNames = [];
let inNetworks = false;
for (const line of lines) {
  if (/^networks:\s*$/.test(line)) {
    inNetworks = true;
    continue;
  }
  if (inNetworks && /^\S/.test(line)) inNetworks = false;
  if (inNetworks) {
    const match = line.match(/^ {2}([A-Za-z0-9_.-]+):\s*$/);
    if (match) networkNames.push(match[1]);
  }
}
if (networkNames.length < 2) {
  if (allowLocalExample) warnings.push(`local example has ${networkNames.length} explicit network(s); production requires internal + tunnel-egress networks`);
  else fail(`expected at least two explicit networks, found ${networkNames.length}`);
}

const serviceNetworkCount = (block) => {
  if (!block) return 0;
  const linesInBlock = block.split(/\r?\n/);
  const networkLine = linesInBlock.findIndex((line) => /^\s{4}networks:\s*$/.test(line));
  if (networkLine === -1) return 0;
  let count = 0;
  for (const line of linesInBlock.slice(networkLine + 1)) {
    if (/^\s{4}\S/.test(line)) break;
    if (/^\s{6}[A-Za-z0-9_.-]+:\s*$/.test(line)) count += 1;
    if (/^\s{6}-\s*[A-Za-z0-9_.-]+\s*$/.test(line)) count += 1;
  }
  return count;
};
const serviceNetworkNames = (block) => {
  if (!block) return [];
  const linesInBlock = block.split(/\r?\n/);
  const networkLine = linesInBlock.findIndex((line) => /^\s{4}networks:\s*$/.test(line));
  if (networkLine === -1) return [];
  const names = [];
  for (const line of linesInBlock.slice(networkLine + 1)) {
    if (/^\s{4}\S/.test(line)) break;
    const map = line.match(/^\s{6}([A-Za-z0-9_.-]+):\s*$/);
    const list = line.match(/^\s{6}-\s*([A-Za-z0-9_.-]+)\s*$/);
    if (map) names.push(map[1]);
    if (list) names.push(list[1]);
  }
  return names;
};
if (server && serviceNetworkCount(server) < 1) {
  if (allowLocalExample) warnings.push("local example uses the default network; production must attach server only to app_internal");
  else fail("server network list is empty");
}
if (tunnel && serviceNetworkCount(tunnel) < 2) {
  if (allowLocalExample) warnings.push(`${tunnelName} must join both the internal and tunnel-egress networks in production`);
  else fail(`${tunnelName} must join both the internal and tunnel-egress networks`);
}
if (!allowLocalExample && server) {
  const names = serviceNetworkNames(server);
  if (names.length !== 1 || names[0] !== "app_internal") fail("server must join only app_internal");
  if (!server.includes("/readyz")) fail("server healthcheck must use /readyz");
  if (!server.includes("PUBLISHER_MTLS_REQUIRED")) fail("server must require publisher mTLS policy");
  if (!server.includes("MCP_EDGE_ATTESTATION_SECRET_FILE")) fail("server must require MCP edge attestation");
  if (/\n\s+MCP_EDGE_ATTESTATION_SECRET:\s*/.test(server)) fail("server must not receive inline MCP edge attestation material");
  if (!/image:\s*\S+@sha256:[a-f0-9]{64}/.test(server)) fail("server image must be digest-pinned");
}
if (!allowLocalExample && tunnel) {
  const names = serviceNetworkNames(tunnel).sort();
  if (names.join(",") !== "app_internal,tunnel_egress") fail(`${tunnelName} network list must be app_internal + tunnel_egress`);
  for (const required of ["read_only:", "cap_drop:", "security_opt:", "pids_limit:", "mem_limit:", "cpus:", "tmpfs:", "healthcheck:"]) {
    if (!tunnel.includes(required)) fail(`${tunnelName} is missing ${required}`);
  }
  if (!/image:\s*\S+@sha256:[a-f0-9]{64}/.test(tunnel)) fail(`${tunnelName} image must be digest-pinned`);
}

if (strict && /build:\s*/.test(server ?? "")) {
  warnings.push("strict mode permits build only for local examples; production generation should pin an image digest");
}

const compose = spawnSync("docker", ["compose", "-f", composePath, "config", "--quiet"], {
  cwd: root,
  encoding: "utf8",
  timeout: 20_000
});
const composeUnavailable = compose.error?.code === "ENOENT";
if (composeUnavailable) {
  warnings.push("docker compose is not installed; structural checks only");
} else if (compose.status !== 0) {
  if (strict) fail("docker compose config rejected the strict fixture");
  else warnings.push("docker compose config could not be evaluated locally (daemon-independent parsing may still pass)");
}

if (warnings.length) {
  for (const warning of warnings) console.warn(`WARN ${warning}`);
}
if (errors.length) {
  for (const error of errors) console.error(`ERROR ${error}`);
  process.exitCode = 1;
} else {
  console.log(`Compose contract OK: ${composePath}`);
}
