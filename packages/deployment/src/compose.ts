import { stringify } from "yaml";
import type { ComposeProject, DeploymentSpec, ImageReference, ResourceLimits, SecretReference } from "./types.js";
import {
  assertHost,
  assertImageReference,
  assertInstallationFile,
  assertInstallationId,
  assertPort,
  assertProjectName,
  assertSecretName,
  assertVaultId,
  projectNameForInstallation
} from "./validation.js";

const INSTALLATION_LABEL = "com.vault-mcp-bridge.installation-id";
const COMPONENT_LABEL = "com.vault-mcp-bridge.component";
const PROJECT_LABEL = "com.vault-mcp-bridge.project";
const SERVER_UID = 10_001;
const SERVER_GID = 10_001;
const TUNNEL_UID = 65_532;
const TUNNEL_GID = 65_532;

interface ComposeSecret {
  readonly file: string;
}

interface ComposeService {
  readonly image: string;
  readonly user: string;
  readonly init: true;
  readonly restart: "unless-stopped" | "no";
  readonly read_only: true;
  readonly cap_drop: readonly ["ALL"];
  readonly cap_add?: readonly string[];
  readonly security_opt: readonly ["no-new-privileges:true"];
  readonly pids_limit: number;
  readonly mem_limit: string;
  readonly cpus: string;
  readonly labels: Readonly<Record<string, string>>;
  readonly environment?: Readonly<Record<string, string>>;
  readonly volumes?: readonly string[];
  readonly secrets?: readonly Readonly<Record<string, string | number>>[];
  readonly tmpfs: readonly [string];
  readonly logging: Readonly<Record<string, unknown>>;
  readonly deploy: Readonly<Record<string, unknown>>;
  readonly networks?: Readonly<Record<string, Readonly<Record<string, unknown>>>> | readonly [];
  readonly network_mode?: "none";
  readonly depends_on?: Readonly<Record<string, Readonly<Record<string, string>>>>;
  readonly entrypoint?: readonly string[];
  readonly command?: readonly string[];
  readonly healthcheck?: Readonly<Record<string, unknown>>;
}

interface ComposeDocument {
  readonly name: string;
  readonly services: Readonly<Record<string, ComposeService>>;
  readonly volumes: Readonly<Record<string, Readonly<Record<string, unknown>>>>;
  readonly networks: Readonly<Record<string, Readonly<Record<string, unknown>>>>;
  readonly secrets: Readonly<Record<string, ComposeSecret>>;
}

function imageValue(image: ImageReference): string {
  assertImageReference(image.repository, image.digest);
  return `${image.repository}@${image.digest}`;
}

function bytesToMiB(bytes: number, field: string): number {
  if (!Number.isInteger(bytes) || bytes <= 0) throw new TypeError(`${field} must be a positive integer`);
  return Math.max(1, Math.ceil(bytes / (1024 * 1024)));
}

function bytesToDockerSize(bytes: number, field: string): string {
  return `${bytesToMiB(bytes, field)}m`;
}

function endpointUrl(value: string, field: string, path: "/" | "/mcp"): URL {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new TypeError(`${field} must be an HTTPS URL`);
  }
  if (parsed.protocol !== "https:" || parsed.username || parsed.password || parsed.search || parsed.hash) {
    throw new TypeError(`${field} must be an origin HTTPS URL`);
  }
  assertHost(parsed.hostname);
  if (parsed.pathname !== path) throw new TypeError(`${field} must end at ${path}`);
  return parsed;
}

function httpsUrl(value: string, field: string): URL {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new TypeError(`${field} must be an HTTPS URL`);
  }
  if (parsed.protocol !== "https:" || parsed.username || parsed.password || parsed.search || parsed.hash) {
    throw new TypeError(`${field} must be an HTTPS URL without credentials or query`);
  }
  assertHost(parsed.hostname);
  return parsed;
}

function validateLimits(limits: ResourceLimits): void {
  bytesToMiB(limits.memoryBytes, "memoryBytes");
  bytesToMiB(limits.tmpfsBytes, "tmpfsBytes");
  bytesToMiB(limits.logBytes, "logBytes");
  bytesToMiB(limits.maxVaultBytes, "maxVaultBytes");
  bytesToMiB(limits.maxDatabaseBytes, "maxDatabaseBytes");
  bytesToMiB(limits.maxIndexBytes, "maxIndexBytes");
  bytesToMiB(limits.maxTempBytes, "maxTempBytes");
  if (!Number.isInteger(limits.minFreeBytes) || limits.minFreeBytes < 0) {
    throw new TypeError("minFreeBytes must be a non-negative integer");
  }
  if (limits.minFreeBytes > 0) bytesToMiB(limits.minFreeBytes, "minFreeBytes");
  if (!Number.isFinite(limits.cpuCores) || limits.cpuCores <= 0) throw new TypeError("cpuCores must be positive");
  if (!Number.isInteger(limits.pids) || limits.pids < 16) throw new TypeError("pids must be at least 16");
  if (!Number.isInteger(limits.maxBodyBytes) || limits.maxBodyBytes <= 0) {
    throw new TypeError("maxBodyBytes must be a positive integer");
  }
  if (!Number.isInteger(limits.maxRetainedGenerations) || limits.maxRetainedGenerations < 2) {
    throw new TypeError("maxRetainedGenerations must be at least two");
  }
  if (!Number.isInteger(limits.logFiles) || limits.logFiles < 1) throw new TypeError("logFiles must be at least one");
}

interface NormalizedSecret extends SecretReference {
  readonly mode: number;
}

function normalizeSecret(baseDirectory: string, secret: SecretReference): NormalizedSecret {
  const name = assertSecretName(secret.name);
  const file = assertInstallationFile(baseDirectory, secret.file);
  if (!Number.isInteger(secret.uid) || secret.uid < 1 || !Number.isInteger(secret.gid) || secret.gid < 1) {
    throw new TypeError(`Invalid uid/gid for secret ${name}`);
  }
  const mode = secret.mode ?? 0o440;
  if (!Number.isInteger(mode) || mode < 0o400 || mode > 0o444) throw new TypeError(`Invalid mode for secret ${name}`);
  return { ...secret, name, file, mode };
}

/** Compose file-source secrets are readable only by the privileged init job.
 * Runtime services consume copies from their own named volume instead. */
function initSecretMount(secret: NormalizedSecret): Readonly<Record<string, string>> {
  return { source: secret.name, target: secret.name };
}

function assertContainerSecretPath(value: string, field: string): string {
  if (!/^\/run\/secrets\/[a-z][a-z0-9_-]{0,62}$/u.test(value)) {
    throw new TypeError(`${field} must point to a Compose secret`);
  }
  return value;
}

function secretContainerPath(secret: SecretReference): string {
  return `/run/secrets/${assertSecretName(secret.name)}`;
}

function labels(installationId: string, projectName: string, component: string): Readonly<Record<string, string>> {
  return {
    [INSTALLATION_LABEL]: installationId,
    [PROJECT_LABEL]: projectName,
    [COMPONENT_LABEL]: component
  };
}

function environment(spec: DeploymentSpec): Readonly<Record<string, string>> {
  const serverPort = spec.environment.serverPort ?? 8787;
  assertPort(serverPort);
  endpointUrl(spec.environment.mcpResourceUrl, "mcpResourceUrl", "/mcp");
  endpointUrl(spec.environment.publisherUrl, "publisherUrl", "/");
  if (!spec.environment.jwtIssuer || !spec.environment.jwtAudience) throw new TypeError("JWT issuer and audience are required");
  httpsUrl(spec.environment.jwtIssuer, "jwtIssuer");
  if (!spec.environment.allowedHosts) throw new TypeError("allowedHosts is required");
  const allowedHosts = new Set(spec.environment.allowedHosts.split(",").map((host) => host.trim().toLowerCase()).filter(Boolean));
  for (const host of allowedHosts) assertHost(host);
  if (!allowedHosts.has(spec.endpoints.mcpHost.toLowerCase()) || !allowedHosts.has(spec.endpoints.publisherHost.toLowerCase())) {
    throw new TypeError("allowedHosts must include both MCP and publisher hosts");
  }
  if (spec.endpoints.mcpHost.toLowerCase() === spec.endpoints.publisherHost.toLowerCase()) {
    throw new TypeError("MCP and publisher hosts must be separate");
  }
  const result: Record<string, string> = {
    NODE_ENV: spec.environment.nodeEnvironment ?? "production",
    SERVER_HOST: "0.0.0.0",
    SERVER_PORT: String(serverPort),
    SERVER_DATABASE_PATH: spec.environment.databasePath ?? "/var/lib/vault-mcp-bridge/vault.sqlite",
    MCP_VAULT_ID: spec.vaultId,
    MCP_INSTALLATION_ID: spec.installationId,
    MCP_RESOURCE_URL: spec.environment.mcpResourceUrl,
    PUBLISHER_PUBLIC_URL: spec.environment.publisherUrl,
    MCP_HOSTS: spec.endpoints.mcpHost.toLowerCase(),
    PUBLISHER_HOSTS: spec.endpoints.publisherHost.toLowerCase(),
    // Container health probes use the loopback Host header. Sensitive MCP and
    // publisher routes still apply their own disjoint hostname allow-lists.
    ALLOWED_HOSTS: [...allowedHosts, "127.0.0.1"].join(","),
    JWT_ISSUER: spec.environment.jwtIssuer,
    JWT_AUDIENCE: spec.environment.jwtAudience,
    JWT_SCOPE: spec.environment.jwtScope ?? "vault:read",
    PUBLISHER_MTLS_REQUIRED: "true",
    MAX_BODY_BYTES: String(spec.limits.maxBodyBytes),
    MAX_VAULT_BYTES: String(spec.limits.maxVaultBytes),
    MAX_DATABASE_BYTES: String(spec.limits.maxDatabaseBytes),
    MAX_INDEX_BYTES: String(spec.limits.maxIndexBytes),
    MAX_TEMP_BYTES: String(spec.limits.maxTempBytes),
    MIN_FREE_BYTES: String(spec.limits.minFreeBytes),
    MAX_RETAINED_GENERATIONS: String(spec.limits.maxRetainedGenerations)
  };
  if (spec.environment.jwtClientId) result.JWT_CLIENT_ID = spec.environment.jwtClientId;
  if (spec.environment.jwksFile) result.JWT_JWKS_FILE = assertContainerSecretPath(spec.environment.jwksFile, "jwksFile");
  result.PUBLISHER_EDGE_ATTESTATION_SECRET_FILE = secretContainerPath(spec.publisherEdgeAttestationSecret);
  result.MCP_EDGE_ATTESTATION_SECRET_FILE = secretContainerPath(spec.mcpEdgeAttestationSecret);
  if (spec.oauthVerificationBundle && !spec.environment.jwksFile) {
    result.JWT_JWKS_FILE = secretContainerPath(spec.oauthVerificationBundle);
  }
  const reservedKeys = new Set([
    ...Object.keys(result),
    "JWT_JWKS_URL",
    "JWT_JWKS_JSON",
    "MCP_DEV_TOKEN",
    "PUBLISHER_EDGE_ATTESTATION_SECRET",
    "MCP_EDGE_ATTESTATION_SECRET",
    "PUBLISHER_MTLS_CREDENTIAL_FILE",
    "DOCKER_HOST",
    "NODE_OPTIONS",
    "LD_PRELOAD",
    "PATH",
    "HOME"
  ]);
  for (const [key, value] of Object.entries(spec.environment.limits ?? {})) {
    if (!/^[A-Z][A-Z0-9_]{0,63}$/u.test(key)) throw new TypeError(`Invalid environment key: ${key}`);
    if (reservedKeys.has(key)) throw new TypeError(`Environment key is reserved: ${key}`);
    result[key] = String(value);
  }
  return result;
}

function healthcheck(): Readonly<Record<string, unknown>> {
  return {
    test: ["CMD", "node", "--input-type=module", "-e", "fetch('http://127.0.0.1:8787/readyz').then(r=>{if(!r.ok)process.exit(1)}).catch(()=>process.exit(1))"],
    interval: "30s",
    timeout: "3s",
    retries: 3,
    start_period: "10s"
  };
}

function tunnelHealthcheck(): Readonly<Record<string, unknown>> {
  return {
    test: ["CMD", "cloudflared", "--version"],
    interval: "30s",
    timeout: "3s",
    retries: 3,
    start_period: "10s"
  };
}

function serviceResources(limits: ResourceLimits): Pick<ComposeService, "pids_limit" | "mem_limit" | "cpus" | "tmpfs" | "logging" | "deploy"> {
  const memory = bytesToDockerSize(limits.memoryBytes, "memoryBytes");
  const cpus = String(limits.cpuCores);
  return {
    pids_limit: limits.pids,
    mem_limit: memory,
    cpus,
    tmpfs: [`/tmp:rw,noexec,nosuid,nodev,size=${bytesToMiB(limits.tmpfsBytes, "tmpfsBytes")}m`],
    logging: {
      driver: "json-file",
      options: {
        "max-size": bytesToDockerSize(limits.logBytes, "logBytes"),
        "max-file": String(limits.logFiles)
      }
    },
    deploy: {
      resources: {
        limits: {
          cpus,
          memory,
          pids: limits.pids
        }
      }
    }
  };
}

function serviceSecurity(uid: number, gid: number): Pick<ComposeService, "user" | "init" | "restart" | "read_only" | "cap_drop" | "security_opt"> {
  return {
    user: `${uid}:${gid}`,
    init: true,
    restart: "unless-stopped",
    read_only: true,
    cap_drop: ["ALL"],
    security_opt: ["no-new-privileges:true"]
  };
}

function secretInitSecurity(): Pick<ComposeService, "user" | "init" | "restart" | "read_only" | "cap_drop" | "cap_add" | "security_opt"> {
  return {
    // The init job needs to read the SSH-uploaded 0600 source and chown the
    // copy in its named volume. These are the only capabilities it receives.
    user: "0:0",
    init: true,
    restart: "no",
    read_only: true,
    cap_drop: ["ALL"],
    cap_add: ["CHOWN", "DAC_OVERRIDE"],
    security_opt: ["no-new-privileges:true"]
  };
}

interface SecretCopyEntry {
  readonly name: string;
  readonly uid: number;
  readonly gid: number;
  readonly mode: number;
}

/**
 * Use the pinned server image's Node runtime for the copy job instead of
 * assuming that either the tunnel image or a generic utility image has a
 * shell. The generated script contains names and numeric metadata only; it
 * never embeds secret values.
 */
function secretCopyCommand(entries: readonly SecretCopyEntry[]): readonly string[] {
  if (entries.length === 0) throw new TypeError("At least one secret is required for an init job");
  const encodedEntries = JSON.stringify(entries.map(({ name, uid, gid, mode }) => ({ name, uid, gid, mode })));
  const script = [
    "import { chmod, chown, copyFile, mkdir, readdir, rm } from 'node:fs/promises';",
    "import { join } from 'node:path';",
    `const entries = ${encodedEntries};`,
    "await mkdir('/out', { recursive: true });",
    "for (const name of await readdir('/out')) await rm(join('/out', name), { recursive: true, force: true });",
    "await chmod('/out', 0o700);",
    "await chown('/out', entries[0].uid, entries[0].gid);",
    "for (const entry of entries) {",
    "  const source = join('/run/secrets', entry.name);",
    "  const target = join('/out', entry.name);",
    "  await rm(target, { force: true });",
    "  await copyFile(source, target);",
    "  await chmod(target, entry.mode);",
    "  await chown(target, entry.uid, entry.gid);",
    "}"
  ].join("\n");
  return ["--input-type=module", "-e", script];
}

function secretInitService(
  spec: DeploymentSpec,
  projectName: string,
  image: string,
  volumeName: string,
  secrets: readonly NormalizedSecret[]
): ComposeService {
  const resources = serviceResources(spec.limits);
  return {
    ...secretInitSecurity(),
    ...resources,
    image,
    entrypoint: ["node"],
    command: secretCopyCommand(secrets),
    labels: labels(spec.installationId, projectName, `${volumeName}-init`),
    volumes: [`${volumeName}:/out:rw`],
    secrets: secrets.map(initSecretMount),
    network_mode: "none"
  };
}

/** Generate a deterministic, per-installation Compose project. */
export function generateComposeProject(spec: DeploymentSpec): ComposeProject {
  assertInstallationId(spec.installationId);
  assertVaultId(spec.vaultId);
  const projectName = projectNameForInstallation(spec.installationId);
  assertProjectName(projectName);
  if (!spec.installationDirectory.startsWith("/")) throw new TypeError("installationDirectory must be absolute");
  assertImageReference(spec.images.server.repository, spec.images.server.digest);
  assertImageReference(spec.images.tunnel.repository, spec.images.tunnel.digest);
  validateLimits(spec.limits);
  assertHost(spec.endpoints.mcpHost);
  assertHost(spec.endpoints.publisherHost);

  const tunnelSecret = normalizeSecret(spec.installationDirectory, spec.tunnelCredential);
  const publisherSecret = normalizeSecret(spec.installationDirectory, spec.publisherEdgeAttestationSecret);
  const mcpSecret = normalizeSecret(spec.installationDirectory, spec.mcpEdgeAttestationSecret);
  const oauthSecret = normalizeSecret(spec.installationDirectory, spec.oauthVerificationBundle);
  if (!spec.environment.jwksFile && !spec.oauthVerificationBundle) {
    throw new TypeError("An offline OAuth verification bundle is required");
  }
  const expectedJwksPath = spec.oauthVerificationBundle ? secretContainerPath(oauthSecret) : undefined;
  if (spec.environment.jwksFile && spec.environment.jwksFile !== expectedJwksPath) {
    throw new TypeError("jwksFile must point to the mounted OAuth verification bundle");
  }
  const serverUid = spec.deploymentUid ?? SERVER_UID;
  const serverGid = spec.deploymentGid ?? SERVER_GID;
  if (!Number.isInteger(serverUid) || serverUid < 1 || !Number.isInteger(serverGid) || serverGid < 1) {
    throw new TypeError("Server runtime uid/gid must be positive integers");
  }
  // Secret copies are owned by the exact runtime identity. A mismatch would
  // make a nominally healthy container unable to read its own volume.
  for (const secret of [publisherSecret, mcpSecret, oauthSecret]) {
    if (secret.uid !== serverUid || secret.gid !== serverGid) {
      throw new TypeError(`Secret ${secret.name} uid/gid must match the server runtime identity`);
    }
  }
  if (tunnelSecret.uid !== TUNNEL_UID || tunnelSecret.gid !== TUNNEL_GID) {
    throw new TypeError("Tunnel credential uid/gid must match the tunnel runtime identity");
  }
  const secretMap: Record<string, ComposeSecret> = {
    [tunnelSecret.name]: { file: tunnelSecret.file }
  };
  for (const secret of [publisherSecret, mcpSecret, oauthSecret]) {
    if (secret.name === tunnelSecret.name || secretMap[secret.name]) {
      throw new TypeError(`Duplicate Compose secret name: ${secret.name}`);
    }
    secretMap[secret.name] = { file: secret.file };
  }

  const serverResources = serviceResources(spec.limits);
  const tunnelResources = serviceResources(spec.limits);
  const serverImage = imageValue(spec.images.server);
  const serverSecretsInit = secretInitService(
    spec,
    projectName,
    serverImage,
    "server_secrets",
    [publisherSecret, mcpSecret, oauthSecret]
  );
  const tunnelSecretsInit = secretInitService(
    spec,
    projectName,
    serverImage,
    "tunnel_secrets",
    [tunnelSecret]
  );
  const server: ComposeService = {
    ...serviceSecurity(serverUid, serverGid),
    ...serverResources,
    image: serverImage,
    labels: labels(spec.installationId, projectName, "server"),
    environment: environment(spec),
    volumes: [
      "replica_data:/var/lib/vault-mcp-bridge",
      "server_secrets:/run/secrets:ro"
    ],
    networks: { app_internal: { aliases: ["server"] } },
    depends_on: { server_secrets_init: { condition: "service_completed_successfully" } },
    healthcheck: healthcheck()
  };
  const tunnel: ComposeService = {
    ...serviceSecurity(TUNNEL_UID, TUNNEL_GID),
    ...tunnelResources,
    image: imageValue(spec.images.tunnel),
    labels: labels(spec.installationId, projectName, "tunnel"),
    command: ["tunnel", "--no-autoupdate", "run", "--token-file", `/run/secrets/${tunnelSecret.name}`],
    volumes: ["tunnel_secrets:/run/secrets:ro"],
    networks: { app_internal: { aliases: ["tunnel"] }, tunnel_egress: { aliases: ["tunnel-egress"] } },
    depends_on: {
      server: { condition: "service_healthy" },
      tunnel_secrets_init: { condition: "service_completed_successfully" }
    },
    healthcheck: tunnelHealthcheck()
  };

  const document: ComposeDocument = {
    name: projectName,
    services: { server, server_secrets_init: serverSecretsInit, tunnel, tunnel_secrets_init: tunnelSecretsInit },
    volumes: {
      replica_data: {
        labels: labels(spec.installationId, projectName, "replica")
      },
      server_secrets: {
        labels: labels(spec.installationId, projectName, "server-secrets")
      },
      tunnel_secrets: {
        labels: labels(spec.installationId, projectName, "tunnel-secrets")
      }
    },
    networks: {
      app_internal: {
        internal: true,
        labels: labels(spec.installationId, projectName, "internal-network")
      },
      tunnel_egress: {
        labels: labels(spec.installationId, projectName, "egress-network")
      }
    },
    secrets: secretMap
  };
  const yaml = stringify(document, { lineWidth: 0, sortMapEntries: true });
  return {
    installationId: spec.installationId,
    projectName,
    fileName: "compose.yaml",
    yaml,
    dataVolumeName: `${projectName}_replica_data`,
    labels: labels(spec.installationId, projectName, "project")
  };
}

export const COMPOSE_RUNTIME_CONTRACT = Object.freeze({
  serverNetwork: "app_internal",
  tunnelNetworks: ["app_internal", "tunnel_egress"],
  serverService: "server",
  tunnelService: "tunnel",
  replicaVolume: "replica_data",
  noPublishedPorts: true
});
