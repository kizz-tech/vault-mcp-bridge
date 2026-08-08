#!/usr/bin/env node
/* global console, process */
/** Bounded repository release hygiene checks; no network, credentials, or daemon. */

import { readdir, readFile } from "node:fs/promises";
import { extname, relative, resolve, sep } from "node:path";

const root = resolve(import.meta.dirname, "..");
const MAX_FILE_BYTES = 512 * 1024;
const MAX_TOTAL_BYTES = 20 * 1024 * 1024;
const packageManifests = [
  "package.json",
  "apps/agent/package.json",
  "apps/desktop/package.json",
  "apps/edge/package.json",
  "apps/server/package.json",
  "packages/agent-core/package.json",
  "packages/contracts/package.json",
  "packages/deployment/package.json",
  "packages/orchestrator/package.json",
  "packages/vault-core/package.json"
];
const excludedDirectories = new Set([
  ".git",
  ".data",
  ".runtime",
  "coverage",
  "dist",
  "node_modules",
  "out",
  "snapshots"
]);
const sourceExtensions = new Set([
  ".cjs",
  ".css",
  ".dockerfile",
  ".html",
  ".ini",
  ".js",
  ".json",
  ".mjs",
  ".md",
  ".sh",
  ".toml",
  ".ts",
  ".tsx",
  ".txt",
  ".yaml",
  ".yml"
]);
const sensitiveExtensions = new Set([".der", ".jks", ".key", ".keystore", ".p12", ".pfx", ".pem"]);
const pemPrivateKey = /-----BEGIN (?:OPENSSH|RSA|EC|DSA|ENCRYPTED|PRIVATE) KEY-----\s+[A-Za-z0-9+/=\r\n]{40,}-----END (?:OPENSSH|RSA|EC|DSA|ENCRYPTED|PRIVATE) KEY-----/;
const quotedCredentialAssignment = /(?:api[_-]?key|access[_-]?token|client[_-]?secret|private[_-]?key|secret[_-]?access[_-]?key|github[_-]?token)\s*[:=]\s*(["'])(?!\$\{|\$\(|<REPLACE|REPLACE_|CHANGEME|YOUR_|EXAMPLE|TEST|DUMMY|NULL|TRUE|FALSE)[A-Za-z0-9_./+=:-]{16,}\1/i;
const envCredentialAssignment = /^\s*(?:API[_-]?KEY|ACCESS[_-]?TOKEN|CLIENT[_-]?SECRET|PRIVATE[_-]?KEY|SECRET[_-]?ACCESS[_-]?KEY|GITHUB[_-]?TOKEN)\s*=\s*(?!\$\{|\$\(|<REPLACE|REPLACE_|CHANGEME|YOUR_|EXAMPLE|TEST|DUMMY|NULL|TRUE|FALSE)[A-Za-z0-9_./+=:-]{16,}\s*$/im;
const failures = [];
let totalBytes = 0;

function candidate(path) {
  const name = path.split(sep).pop() ?? "";
  if (name === "Dockerfile" || name.startsWith("Dockerfile.") || name.startsWith(".env")) return true;
  const extension = extname(name).toLowerCase();
  return sourceExtensions.has(extension) || sensitiveExtensions.has(extension);
}

async function filesUnder(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const files = [];
  for (const entry of entries.sort((left, right) => left.name.localeCompare(right.name))) {
    if (entry.isDirectory() && excludedDirectories.has(entry.name)) continue;
    const path = resolve(directory, entry.name);
    if (entry.isDirectory()) files.push(...(await filesUnder(path)));
    else if (entry.isFile() && candidate(path)) files.push(path);
  }
  return files;
}

for (const path of await filesUnder(root)) {
  const buffer = await readFile(path);
  const relativePath = relative(root, path).split(sep).join("/");
  if (sensitiveExtensions.has(extname(path).toLowerCase()) && !/\.example\.[^.]+$/u.test(path)) {
    failures.push(`${relativePath} uses a credential-bearing file extension`);
  }
  if (buffer.byteLength > MAX_FILE_BYTES) {
    failures.push(`${relativePath} exceeds the per-file secret-scan limit`);
    continue;
  }
  if (buffer.includes(0)) {
    failures.push(`${relativePath} is binary and could not be secret-scanned`);
    continue;
  }
  totalBytes += buffer.byteLength;
  if (totalBytes > MAX_TOTAL_BYTES) {
    failures.push(`candidate sources exceed the ${MAX_TOTAL_BYTES}-byte secret-scan budget`);
    break;
  }
  const text = buffer.toString("utf8");
  if (pemPrivateKey.test(text)) failures.push(`${relativePath} contains a PEM private-key marker`);
  if (quotedCredentialAssignment.test(text) || envCredentialAssignment.test(text)) {
    failures.push(`${relativePath} contains a high-confidence credential assignment`);
  }
}

const rootManifest = JSON.parse(await readFile(resolve(root, "package.json"), "utf8"));
const expectedVersion = typeof rootManifest.version === "string" ? rootManifest.version : "";
if (!/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/u.test(expectedVersion)) failures.push("root package version is not valid semver");
const pnpmPolicy = rootManifest.pnpm && typeof rootManifest.pnpm === "object" ? rootManifest.pnpm : {};
const allowedBuilds = new Set(Array.isArray(pnpmPolicy.onlyBuiltDependencies) ? pnpmPolicy.onlyBuiltDependencies : []);
const ignoredBuilds = new Set(Array.isArray(pnpmPolicy.ignoredBuiltDependencies) ? pnpmPolicy.ignoredBuiltDependencies : []);
for (const dependency of ["electron", "esbuild"]) {
  if (!allowedBuilds.has(dependency)) failures.push(`pnpm build policy must allow ${dependency}`);
}
for (const dependency of ["fs-xattr", "macos-alias"]) {
  if (allowedBuilds.has(dependency) || !ignoredBuilds.has(dependency)) {
    failures.push(`pnpm build policy must defer ${dependency} to the sanitized DMG rebuild`);
  }
}
for (const manifestPath of packageManifests.slice(1)) {
  const manifest = JSON.parse(await readFile(resolve(root, manifestPath), "utf8"));
  if (manifest.version !== expectedVersion) failures.push(`${manifestPath} version does not match ${expectedVersion}`);
}
const releaseTag = process.env.GITHUB_REF_TYPE === "tag"
  ? process.env.GITHUB_REF_NAME
  : process.env.VAULT_BRIDGE_RELEASE_TAG;
if (releaseTag && releaseTag !== `v${expectedVersion}`) failures.push(`release tag ${releaseTag} does not match v${expectedVersion}`);
const dockerIgnore = new Set((await readFile(resolve(root, ".dockerignore"), "utf8")).split(/\r?\n/u).map((line) => line.trim()).filter(Boolean));
for (const pattern of [".env", ".credentials", "**/.credentials", "**/secrets", "*.key", "*.p12", "*.pfx", "*.pem", "certs"]) {
  if (!dockerIgnore.has(pattern)) failures.push(`.dockerignore is missing ${pattern}`);
}
const workflowPaths = [".github/workflows/ci.yml", ".github/workflows/release.yml"];
for (const workflowPath of workflowPaths) {
  const workflow = await readFile(resolve(root, workflowPath), "utf8");
  for (const match of workflow.matchAll(/^\s*uses:\s*([^\s@]+)@([^\s#]+)/gmu)) {
    const action = match[1] ?? "unknown";
    const reference = match[2] ?? "";
    if (!/^[0-9a-f]{40}$/u.test(reference)) failures.push(`${workflowPath} action ${action} is not pinned to a full commit SHA`);
  }
}
const releaseWorkflow = await readFile(resolve(root, ".github/workflows/release.yml"), "utf8");
if (!releaseWorkflow.includes("workflow_dispatch:")) failures.push("release workflow must be manual-only");
if (/^\s{2}(?:push|pull_request|schedule):/mu.test(releaseWorkflow)) failures.push("release workflow must not have an automatic trigger");
const repositoryCheck = releaseWorkflow.indexOf("Check repository");
const registryLogin = releaseWorkflow.indexOf("Log in to GHCR");
const publishImage = releaseWorkflow.indexOf("Build and publish the multi-arch image");
const digestVerify = releaseWorkflow.indexOf("Verify the published manifest digest");
if (repositoryCheck < 0 || registryLogin <= repositoryCheck || publishImage <= registryLogin || digestVerify <= publishImage) {
  failures.push("release workflow must validate before registry login, then publish and verify one image");
}
if ((releaseWorkflow.match(/packages:\s*write/gu) ?? []).length !== 1) {
  failures.push("release workflow must grant packages: write exactly once");
}
for (const requiredBoundary of [
  "deploy/Dockerfile.secure-tunnel",
  "linux/amd64,linux/arm64",
  "push: true",
  "sha-${{ github.sha }}",
  "steps.image.outputs.digest",
  "docker buildx imagetools inspect"
]) {
  if (!releaseWorkflow.includes(requiredBoundary)) failures.push(`release workflow is missing Secure Tunnel release boundary ${requiredBoundary}`);
}
for (const requiredPin of [
  "tonistiigi/binfmt@sha256:",
  "moby/buildkit@sha256:",
  "docker/buildkit-syft-scanner@sha256:"
]) {
  if (!releaseWorkflow.includes(requiredPin)) failures.push(`release workflow is missing digest pin ${requiredPin}`);
}
if (/Dockerfile\.(?:server|edge)/u.test(releaseWorkflow)) failures.push("primary release workflow must not publish legacy server/edge images");
if (releaseWorkflow.includes("sbom: true")) {
  failures.push("release workflow must pin the BuildKit SBOM generator by digest");
}
if (failures.length) {
  for (const failure of failures) console.error(`ERROR ${failure}`);
  process.exitCode = 1;
} else {
  console.log(`Release hygiene OK (${totalBytes} bytes scanned)`);
}
