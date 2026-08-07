#!/usr/bin/env node
/* global console, process */
/** Verify artifact sizes and SHA-256 digests from a release manifest. */

import { createHash } from "node:crypto";
import { readdir, readFile, stat } from "node:fs/promises";
import { dirname, isAbsolute, relative, resolve, sep } from "node:path";
import { spawnSync } from "node:child_process";

const positional = [];
const signatureIndex = process.argv.indexOf("--signature");
const signaturePath = signatureIndex === -1 ? undefined : process.argv[signatureIndex + 1];
for (let index = 2; index < process.argv.length; index += 1) {
  const argument = process.argv[index];
  if (argument === "--signature") {
    index += 1;
    continue;
  }
  if (!argument.startsWith("--")) positional.push(argument);
}
const manifestPath = resolve(positional[0] ?? "release-manifest.json");
const artifactRoot = resolve(positional[1] ?? dirname(manifestPath));

const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
if (manifest.schemaVersion !== 1) throw new Error("unsupported release manifest schema");
if (!Array.isArray(manifest.artifacts)) throw new Error("manifest artifacts must be an array");

const seen = new Set();
for (const artifact of manifest.artifacts) {
  if (!artifact || typeof artifact.path !== "string") throw new Error("artifact path is missing");
  if (isAbsolute(artifact.path) || artifact.path.includes("\\")) throw new Error(`unsafe artifact path: ${artifact.path}`);
  const target = resolve(artifactRoot, artifact.path);
  const rel = relative(artifactRoot, target);
  if (!rel || rel.startsWith(`..${sep}`) || isAbsolute(rel)) throw new Error(`artifact escapes root: ${artifact.path}`);
  if (seen.has(artifact.path)) throw new Error(`duplicate artifact path: ${artifact.path}`);
  seen.add(artifact.path);
  if (!/^\d+$/.test(String(artifact.bytes))) throw new Error(`invalid byte count: ${artifact.path}`);
  if (!/^[a-f0-9]{64}$/.test(artifact.sha256)) throw new Error(`invalid SHA-256 digest: ${artifact.path}`);

  const metadata = await stat(target).catch(() => null);
  if (!metadata?.isFile()) throw new Error(`artifact is missing: ${artifact.path}`);
  if (metadata.size !== Number(artifact.bytes)) throw new Error(`byte count mismatch: ${artifact.path}`);
  const hash = createHash("sha256");
  hash.update(await readFile(target));
  if (hash.digest("hex") !== artifact.sha256) throw new Error(`SHA-256 mismatch: ${artifact.path}`);
}

async function filesUnder(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const files = [];
  for (const entry of entries.sort((left, right) => left.name.localeCompare(right.name))) {
    const path = resolve(directory, entry.name);
    if (entry.isDirectory()) files.push(...(await filesUnder(path)));
    else if (entry.isFile()) files.push(relative(artifactRoot, path).split(sep).join("/"));
  }
  return files;
}
const excludedVerificationFiles = new Set([
  relative(artifactRoot, manifestPath).split(sep).join("/"),
  ...(signaturePath ? [relative(artifactRoot, resolve(signaturePath)).split(sep).join("/")] : [])
]);
const actual = (await filesUnder(artifactRoot)).filter((path) => !excludedVerificationFiles.has(path));
if (actual.length !== seen.size || actual.some((path) => !seen.has(path))) {
  throw new Error("artifact directory contains files not covered by the release manifest");
}

if (signaturePath) {
  const signature = resolve(signaturePath);
  const publicKey = process.env.COSIGN_PUBLIC_KEY_PATH;
  if (!publicKey) throw new Error("COSIGN_PUBLIC_KEY_PATH is required when --signature is supplied");
  const verifier = spawnSync("cosign", ["verify-blob", "--key", resolve(publicKey), "--signature", signature, manifestPath], {
    encoding: "utf8",
    stdio: "inherit"
  });
  if (verifier.error?.code === "ENOENT") throw new Error("cosign is required when --signature is supplied");
  if (verifier.status !== 0) throw new Error("release manifest signature verification failed");
}

console.log(`Release manifest OK: ${manifest.artifacts.length} artifact(s)`);
