import { createHash } from "node:crypto";
import { isAbsolute, relative, resolve, sep } from "node:path";

const INSTALLATION_ID_PATTERN = /^[A-Za-z0-9_-]{16,128}$/u;
const VAULT_ID_PATTERN = /^[A-Za-z0-9_-]{16,256}$/u;
const PROJECT_PATTERN = /^[a-z0-9][a-z0-9_-]{0,62}$/u;
const IMAGE_REPOSITORY_PATTERN = /^[a-z0-9][a-z0-9./_-]{0,255}$/u;
const DIGEST_PATTERN = /^sha256:[a-f0-9]{64}$/u;
const SECRET_NAME_PATTERN = /^[a-z][a-z0-9_-]{0,62}$/u;
const HOST_PATTERN = /^[a-z0-9][a-z0-9.-]{0,252}$/u;

export function assertInstallationId(value: string): string {
  if (!INSTALLATION_ID_PATTERN.test(value)) throw new TypeError("Invalid installation id");
  return value;
}
export function assertVaultId(value: string): string {
  if (!VAULT_ID_PATTERN.test(value)) throw new TypeError("Invalid vault id");
  return value;
}

export function projectNameForInstallation(installationId: string): string {
  assertInstallationId(installationId);
  const digest = createHash("sha256").update(`compose-project:${installationId}`, "utf8").digest("hex");
  return `vmb-${digest.slice(0, 12)}`;
}

export function assertProjectName(value: string): string {
  if (!PROJECT_PATTERN.test(value)) throw new TypeError("Invalid Compose project name");
  return value;
}

export function assertImageReference(repository: string, digest: string): void {
  if (!IMAGE_REPOSITORY_PATTERN.test(repository) || !DIGEST_PATTERN.test(digest)) {
    throw new TypeError("Images must use a repository@sha256:<64 hex> digest");
  }
}

export function assertHost(value: string): string {
  const candidate = value.toLowerCase();
  if (!HOST_PATTERN.test(candidate) || candidate.includes("..")) throw new TypeError("Invalid endpoint host");
  return candidate;
}

export function assertPort(value: number): number {
  if (!Number.isInteger(value) || value < 1 || value > 65_535) throw new TypeError("Invalid TCP port");
  return value;
}

export function assertPositiveFinite(value: number, field: string): number {
  if (!Number.isFinite(value) || value <= 0) throw new TypeError(`${field} must be positive`);
  return value;
}

/**
 * Compose secret files are intentionally restricted to the installation's
 * private directory. This prevents a caller from smuggling a vault path or
 * arbitrary host file into the generated YAML.
 */
export function assertInstallationFile(baseDirectory: string, file: string): string {
  if (!isAbsolute(baseDirectory) || !isAbsolute(file)) throw new TypeError("Installation paths must be absolute");
  const base = resolve(baseDirectory);
  const target = resolve(file);
  const rel = relative(base, target);
  if (rel === "" || rel === ".." || rel.startsWith(`..${sep}`) || isAbsolute(rel)) {
    throw new TypeError("Secret files must be inside the installation directory");
  }
  return target;
}

export function assertSecretName(value: string): string {
  if (!SECRET_NAME_PATTERN.test(value)) throw new TypeError("Invalid Compose secret name");
  return value;
}

export function assertSafeRelativePath(value: string, field: string): string {
  if (!value || isAbsolute(value) || value.split(/[\\/]/u).some((part) => part === ".." || part === "")) {
    throw new TypeError(`${field} must be a safe relative path`);
  }
  return value;
}

export function assertNoProjectCollision(projectName: string, existingProjects: readonly string[]): void {
  assertProjectName(projectName);
  if (existingProjects.includes(projectName)) {
    throw new Error(`Compose project collision: ${projectName}`);
  }
}
