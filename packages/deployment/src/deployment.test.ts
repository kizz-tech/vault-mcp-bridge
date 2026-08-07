import { describe, expect, it } from "vitest";
import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parse } from "yaml";
import { composeCommand, composeDownCommand, generateComposeProject, stageComposeProject } from "./index.js";
import { evaluatePreflight } from "./preflight.js";
import type { DeploymentSpec, HostProbe } from "./types.js";
import { assertInstallationFile, assertNoProjectCollision, projectNameForInstallation } from "./validation.js";

const installationId = "inst_test_1234567890";
const base: DeploymentSpec = {
  installationId,
  vaultId: "vault_test_1234567890",
  installationDirectory: "/srv/vault-bridge/inst_test_1234567890",
  images: {
    server: { repository: "ghcr.io/example/vault-bridge-server", digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" },
    tunnel: { repository: "cloudflare/cloudflared", digest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" }
  },
  endpoints: {
    mcpHost: "mcp.example.invalid",
    publisherHost: "ingest.example.invalid"
  },
  environment: {
    mcpResourceUrl: "https://mcp.example.invalid/mcp",
    publisherUrl: "https://ingest.example.invalid/",
    jwtIssuer: "https://issuer.example.invalid/",
    jwtAudience: "vault-mcp-bridge",
    jwtScope: "vault:read",
    jwksFile: "/run/secrets/oauth_verification_bundle",
    allowedHosts: "mcp.example.invalid,ingest.example.invalid"
  },
  tunnelCredential: {
    name: "tunnel_credential",
    file: "/srv/vault-bridge/inst_test_1234567890/secrets/tunnel.token",
    uid: 65532,
    gid: 65532,
    mode: 0o440
  },
  publisherEdgeAttestationSecret: {
    name: "publisher_edge_attestation",
    file: "/srv/vault-bridge/inst_test_1234567890/secrets/edge.attestation",
    uid: 10001,
    gid: 10001,
    mode: 0o440
  },
  mcpEdgeAttestationSecret: {
    name: "mcp_edge_attestation",
    file: "/srv/vault-bridge/inst_test_1234567890/secrets/mcp.edge.attestation",
    uid: 10001,
    gid: 10001,
    mode: 0o440
  },
  oauthVerificationBundle: {
    name: "oauth_verification_bundle",
    file: "/srv/vault-bridge/inst_test_1234567890/secrets/jwks.json",
    uid: 10001,
    gid: 10001,
    mode: 0o440
  },
  limits: {
    memoryBytes: 512 * 1024 * 1024,
    cpuCores: 1,
    pids: 128,
    tmpfsBytes: 32 * 1024 * 1024,
    maxBodyBytes: 16 * 1024 * 1024,
    maxVaultBytes: 512 * 1024 * 1024,
    maxDatabaseBytes: 2 * 1024 * 1024 * 1024,
    maxIndexBytes: 512 * 1024 * 1024,
    maxTempBytes: 512 * 1024 * 1024,
    minFreeBytes: 2 * 1024 * 1024 * 1024,
    maxRetainedGenerations: 2,
    logBytes: 8 * 1024 * 1024,
    logFiles: 3
  }
};

const healthyHost: HostProbe = {
  os: "linux",
  arch: "x86_64",
  docker: { available: true, version: "28.0.0", rootless: true, composeAvailable: true, composeVersion: "v2.35.0" },
  cpuCores: 4,
  memoryBytes: 8 * 1024 * 1024 * 1024,
  freeSpaceBytes: 20 * 1024 * 1024 * 1024,
  outboundHttps: true,
  projectNames: [],
  filesystemQuota: "available"
};

describe("deployment compose generation", () => {
  it("is deterministic and digest-pinned", () => {
    const first = generateComposeProject(base);
    const second = generateComposeProject({ ...base });
    expect(first).toEqual(second);
    const document = parse(first.yaml) as Record<string, unknown>;
    expect(document.name).toBe(first.projectName);
    const services = document.services as Record<string, Record<string, unknown>>;
    const server = services.server as Record<string, unknown>;
    const tunnel = services.tunnel as Record<string, unknown>;
    expect(server.image).toContain("@sha256:");
    expect(tunnel.image).toContain("@sha256:");
    expect(server.ports).toBeUndefined();
    expect(server.build).toBeUndefined();
    expect(server.container_name).toBeUndefined();
    expect(tunnel.ports).toBeUndefined();
    expect(tunnel.build).toBeUndefined();
    expect(server.networks).toEqual({ app_internal: { aliases: ["server"] } });
    expect(tunnel.networks).toEqual({ app_internal: { aliases: ["tunnel"] }, tunnel_egress: { aliases: ["tunnel-egress"] } });
    expect(tunnel.command).toEqual(["tunnel", "--no-autoupdate", "run", "--token-file", "/run/secrets/tunnel_credential"]);
  });

  it("sets read-only non-root limits, bounded logs, health and labels", () => {
    const document = parse(generateComposeProject(base).yaml) as Record<string, unknown>;
    const services = document.services as Record<string, Record<string, unknown>>;
    const server = services.server as Record<string, unknown>;
    const tunnel = services.tunnel as Record<string, unknown>;
    const serverSecretsInit = services.server_secrets_init as Record<string, unknown>;
    const tunnelSecretsInit = services.tunnel_secrets_init as Record<string, unknown>;
    for (const service of [server, tunnel]) {
      expect(service.read_only).toBe(true);
      expect(service.cap_drop).toEqual(["ALL"]);
      expect(service.security_opt).toEqual(["no-new-privileges:true"]);
      expect(service.pids_limit).toBe(128);
      expect(service.deploy).toBeDefined();
      expect(service.tmpfs).toEqual(["/tmp:rw,noexec,nosuid,nodev,size=32m"]);
      expect(service.logging).toBeDefined();
      expect(service.healthcheck).toBeDefined();
      expect((service.labels as Record<string, string>)["com.vault-mcp-bridge.installation-id"]).toBe(installationId);
    }
    const networks = document.networks as Record<string, Record<string, unknown>>;
    const internalNetwork = networks.app_internal as Record<string, unknown>;
    expect(internalNetwork.internal).toBe(true);
    expect(server.secrets).toBeUndefined();
    expect(tunnel.secrets).toBeUndefined();
    expect(server.volumes).toEqual([
      "replica_data:/var/lib/vault-mcp-bridge",
      "server_secrets:/run/secrets:ro"
    ]);
    expect(tunnel.volumes).toEqual(["tunnel_secrets:/run/secrets:ro"]);
    expect(server.depends_on).toEqual({ server_secrets_init: { condition: "service_completed_successfully" } });
    expect(tunnel.depends_on).toEqual({
      server: { condition: "service_healthy" },
      tunnel_secrets_init: { condition: "service_completed_successfully" }
    });
    for (const init of [serverSecretsInit, tunnelSecretsInit]) {
      expect(init.user).toBe("0:0");
      expect(init.restart).toBe("no");
      expect(init.read_only).toBe(true);
      expect(init.cap_drop).toEqual(["ALL"]);
      expect(init.cap_add).toEqual(["CHOWN", "DAC_OVERRIDE"]);
      expect(init.security_opt).toEqual(["no-new-privileges:true"]);
      expect(init.network_mode).toBe("none");
      expect(init.networks).toBeUndefined();
      expect(init.ports).toBeUndefined();
      expect(init.entrypoint).toEqual(["node"]);
    }
    expect((serverSecretsInit.secrets as readonly Record<string, unknown>[]).map((secret) => secret.source)).toEqual([
      "publisher_edge_attestation",
      "mcp_edge_attestation",
      "oauth_verification_bundle"
    ]);
    expect((tunnelSecretsInit.secrets as readonly Record<string, unknown>[]).map((secret) => secret.source)).toEqual(["tunnel_credential"]);
    expect(serverSecretsInit.volumes).toEqual(["server_secrets:/out:rw"]);
    expect(tunnelSecretsInit.volumes).toEqual(["tunnel_secrets:/out:rw"]);
    expect(generateComposeProject(base).yaml).not.toContain("${");
    const volumes = document.volumes as Record<string, unknown>;
    expect(Object.keys(volumes).sort()).toEqual(["replica_data", "server_secrets", "tunnel_secrets"]);
    const environment = server.environment as Record<string, string>;
    expect(environment.PUBLISHER_MTLS_REQUIRED).toBe("true");
    expect(environment.PUBLISHER_EDGE_ATTESTATION_SECRET_FILE).toBe("/run/secrets/publisher_edge_attestation");
    expect(environment.MCP_EDGE_ATTESTATION_SECRET_FILE).toBe("/run/secrets/mcp_edge_attestation");
    expect(environment.JWT_JWKS_FILE).toBe("/run/secrets/oauth_verification_bundle");
    expect((environment.ALLOWED_HOSTS ?? "").split(",")).toEqual(expect.arrayContaining(["mcp.example.invalid", "ingest.example.invalid", "127.0.0.1"]));
    expect(environment.MAX_BODY_BYTES).toBe(String(base.limits.maxBodyBytes));
    expect(environment.MAX_RETAINED_GENERATIONS).toBe("2");
    expect(environment.JWT_CLIENT_ID).toBeUndefined();
    expect(JSON.stringify(document)).not.toContain("tunnel-token-value");
  });

  it("rejects secret paths outside the installation directory", () => {
    expect(() => assertInstallationFile(base.installationDirectory, "/srv/other/tunnel.token")).toThrow();
    expect(() => generateComposeProject({
      ...base,
      tunnelCredential: { ...base.tunnelCredential, file: "/etc/passwd" }
    })).toThrow();
  });

  it("rejects an unmounted OAuth path and duplicate secret identities", () => {
    expect(() => generateComposeProject({
      ...base,
      environment: { ...base.environment, jwksFile: "/run/secrets/not-mounted" }
    })).toThrow(/jwksFile/iu);
    expect(() => generateComposeProject({
      ...base,
      publisherEdgeAttestationSecret: { ...base.publisherEdgeAttestationSecret, name: base.oauthVerificationBundle.name }
    })).toThrow(/duplicate/iu);
    expect(() => generateComposeProject({
      ...base,
      mcpEdgeAttestationSecret: { ...base.mcpEdgeAttestationSecret, name: base.publisherEdgeAttestationSecret.name }
    })).toThrow(/duplicate/iu);
  });

  it("keeps installations isolated by deterministic project names", () => {
    const project = projectNameForInstallation(installationId);
    const other = projectNameForInstallation("inst_test_1234567891");
    expect(project).toMatch(/^vmb-[0-9a-f]{12}$/u);
    expect(project).not.toBe(other);
    expect(() => assertNoProjectCollision(project, [project])).toThrow(/collision/iu);
    expect(() => assertNoProjectCollision(project, [other])).not.toThrow();
  });
});

describe("deployment lifecycle safety", () => {
  it("uses only exact project-scoped Compose commands", () => {
    const project = projectNameForInstallation(installationId);
    const start = composeCommand(project, "/tmp/compose.yaml", "start");
    const down = composeDownCommand(project, "/tmp/compose.yaml", false);
    const remove = composeDownCommand(project, "/tmp/compose.yaml", true);
    expect(start).toContain("--project-name");
    expect(start).toContain(project);
    expect(start).toContain("--no-build");
    expect(down).not.toContain("--volumes");
    expect(remove).toContain("--volumes");
    expect([...start, ...down, ...remove].join(" ")).not.toContain("--remove-orphans");
    expect([...start, ...down, ...remove].join(" ")).not.toContain("system prune");
  });

  it("stages the generated file atomically below the installation directory", async () => {
    const directory = await mkdtemp(join(tmpdir(), "vmb-deployment-"));
    const project = generateComposeProject(base);
    const staged = await stageComposeProject(directory, project);
    expect(staged.path).toBe(join(directory, "compose.yaml"));
    expect(staged.bytes).toBe(Buffer.byteLength(project.yaml));
    expect(await readFile(staged.path, "utf8")).toBe(project.yaml);
  });
});

describe("host preflight", () => {
  it("passes a healthy rootless host and reports filesystem quota", () => {
    const report = evaluatePreflight(projectNameForInstallation(installationId), healthyHost, { mode: "rootless" });
    expect(report.ok).toBe(true);
    expect(report.checks.find((item) => item.id === "rootless")?.status).toBe("pass");
  });

  it("fails closed on rootful fallback, collisions and low disk", () => {
    const report = evaluatePreflight(projectNameForInstallation(installationId), {
      ...healthyHost,
      docker: { ...healthyHost.docker, rootless: false },
      freeSpaceBytes: 1,
      projectNames: [projectNameForInstallation(installationId)]
    }, { mode: "rootless", expectedStagingBytes: 1024 });
    expect(report.ok).toBe(false);
    expect(report.collision).toBe(true);
    expect(report.checks.filter((item) => item.status === "fail").map((item) => item.id)).toEqual(
      expect.arrayContaining(["rootless", "disk", "project-collision"])
    );
  });
});
