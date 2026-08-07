#!/usr/bin/env node
/* global console, process */
/** Generate a deterministic, secret-free release manifest for artifacts. */

import { createHash } from "node:crypto";
import { readdir, readFile, stat, writeFile } from "node:fs/promises";
import { basename, relative, resolve, sep } from "node:path";

const args = new Map();
for (let index = 2; index < process.argv.length; index += 1) {
  const token = process.argv[index];
  if (!token.startsWith("--")) continue;
  const key = token.slice(2);
  const value = process.argv[index + 1]?.startsWith("--") ? undefined : process.argv[++index];
  args.set(key, value ?? "true");
}

const artifactRoot = resolve(args.get("artifacts") ?? "out/make");
const output = resolve(args.get("output") ?? "release-manifest.json");
const version = args.get("version") ?? process.env.RELEASE_VERSION ?? "0.0.0-dev";
const allowEmpty = args.get("allow-empty") === "true";
const commit = process.env.GITHUB_SHA ?? process.env.GIT_COMMIT ?? null;

const digest = async (path) => {
  const hash = createHash("sha256");
  hash.update(await readFile(path));
  return hash.digest("hex");
};

async function filesUnder(directory) {
  const entries = await readdir(directory, { withFileTypes: true }).catch((error) => {
    if (error.code === "ENOENT") return [];
    throw error;
  });
  const files = [];
  for (const entry of entries.sort((left, right) => left.name.localeCompare(right.name))) {
    const path = resolve(directory, entry.name);
    if (entry.isDirectory()) files.push(...(await filesUnder(path)));
    else if (entry.isFile()) files.push(path);
  }
  return files;
}

const paths = (await filesUnder(artifactRoot)).filter((path) => resolve(path) !== output);
if (paths.length === 0 && !allowEmpty) {
  throw new Error(`no release artifacts found under ${artifactRoot}`);
}

const artifacts = [];
for (const path of paths) {
  const metadata = await stat(path);
  const relativePath = relative(artifactRoot, path).split(sep).join("/");
  if (!relativePath || relativePath.startsWith("../") || relativePath.includes("/../")) {
    throw new Error(`artifact path escapes artifact root: ${relativePath}`);
  }
  artifacts.push({
    path: relativePath,
    bytes: metadata.size,
    sha256: await digest(path)
  });
}

const manifest = {
  schemaVersion: 1,
  product: "vault-mcp-bridge",
  version,
  commit,
  generatedAt: new Date().toISOString(),
  artifacts
};
await writeFile(output, `${JSON.stringify(manifest, null, 2)}\n`, { mode: 0o644 });
console.log(`Wrote ${basename(output)} with ${artifacts.length} artifact(s)`);
