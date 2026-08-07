import type { HostProbe, PreflightCheck, PreflightReport, PreflightRequirements } from "./types.js";
import { assertNoProjectCollision, assertProjectName } from "./validation.js";

const DEFAULT_ARCHITECTURES = ["x64", "arm64", "x86_64", "aarch64"] as const;

function check(id: string, status: PreflightCheck["status"], detail: string): PreflightCheck {
  return { id, status, detail };
}
function canonicalArch(value: string): string {
  const lower = value.toLowerCase();
  if (lower === "amd64" || lower === "x86_64") return "x64";
  if (lower === "arm64" || lower === "aarch64") return "arm64";
  return lower;
}

/**
 * Evaluate a host without changing it. The caller obtains HostProbe through a
 * bounded SSH/Docker adapter; this function has no shell or network side
 * effects and can therefore be used in previews and tests.
 */
export function evaluatePreflight(projectName: string, host: HostProbe, requirements: PreflightRequirements): PreflightReport {
  assertProjectName(projectName);
  const checks: PreflightCheck[] = [];
  const allowedArchitectures = requirements.allowedArchitectures ?? DEFAULT_ARCHITECTURES;
  const architecture = canonicalArch(host.arch);
  checks.push(
    allowedArchitectures.map(canonicalArch).includes(architecture)
      ? check("architecture", "pass", architecture)
      : check("architecture", "fail", `Unsupported architecture: ${host.arch}`)
  );
  checks.push(host.os.toLowerCase() === "linux"
    ? check("os", "pass", "linux")
    : check("os", "fail", `Docker runtime requires Linux; got ${host.os}`));
  checks.push(host.docker.available
    ? check("docker", "pass", host.docker.version ? `Docker ${host.docker.version}` : "Docker available")
    : check("docker", "fail", "Docker is unavailable"));
  checks.push(host.docker.composeAvailable
    ? check("compose", "pass", host.docker.composeVersion ? `Compose ${host.docker.composeVersion}` : "Compose available")
    : check("compose", "fail", "Docker Compose v2 is unavailable"));
  if (requirements.mode === "rootless") {
    checks.push(host.docker.rootless
      ? check("rootless", "pass", "rootless Docker")
      : check("rootless", "fail", "Rootless Docker is required for the default shared-host mode"));
  } else {
    checks.push(host.docker.rootless
      ? check("rootless", "pass", "rootless Docker")
      : check("rootless", "warn", "Using the explicit rootful compatibility mode"));
  }
  const minimumCpu = requirements.minimumCpuCores ?? 1;
  checks.push(host.cpuCores >= minimumCpu
    ? check("cpu", "pass", `${host.cpuCores} cores available`)
    : check("cpu", "fail", `${minimumCpu} CPU cores required`));
  const minimumMemory = requirements.minimumMemoryBytes ?? 512 * 1024 * 1024;
  checks.push(host.memoryBytes >= minimumMemory
    ? check("memory", "pass", `${host.memoryBytes} bytes available`)
    : check("memory", "fail", `${minimumMemory} bytes of memory required`));
  const minimumFreeSpace = requirements.minimumFreeSpaceBytes ?? 2 * 1024 * 1024 * 1024;
  const expectedStaging = requirements.expectedStagingBytes ?? 0;
  const requiredFreeSpace = minimumFreeSpace + expectedStaging;
  checks.push(host.freeSpaceBytes >= requiredFreeSpace
    ? check("disk", "pass", `${host.freeSpaceBytes} bytes free`)
    : check("disk", "fail", `${requiredFreeSpace} bytes free space required`));
  if (requirements.requireOutboundHttps ?? true) {
    checks.push(host.outboundHttps
      ? check("outbound-https", "pass", "outbound HTTPS available")
      : check("outbound-https", "fail", "Outbound HTTPS is required for the tunnel and publisher"));
  }
  checks.push(host.filesystemQuota === "available"
    ? check("filesystem-quota", "pass", "filesystem quota available")
    : check("filesystem-quota", "warn", "Filesystem quota unavailable; application-level quotas remain active"));
  let collision = false;
  try {
    assertNoProjectCollision(projectName, host.projectNames);
    checks.push(check("project-collision", "pass", `No existing project named ${projectName}`));
  } catch {
    collision = true;
    checks.push(check("project-collision", "fail", `Project ${projectName} already exists`));
  }
  return {
    ok: checks.every((item) => item.status !== "fail"),
    checks,
    collision
  };
}

export class PreflightError extends Error {
  public constructor(public readonly report: PreflightReport) {
    super(report.checks.filter((item) => item.status === "fail").map((item) => `${item.id}: ${item.detail}`).join("; "));
    this.name = "PreflightError";
  }
}

export function assertPreflight(report: PreflightReport): void {
  if (!report.ok) throw new PreflightError(report);
}
