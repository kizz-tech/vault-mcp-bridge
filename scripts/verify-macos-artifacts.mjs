#!/usr/bin/env node
/* global console, process */
/** Verify the macOS package, archive, code signature, and locked Electron fuses. */

import { readdir } from "node:fs/promises";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";

if (process.platform !== "darwin") throw new Error("macOS artifact verification must run on macOS");
const root = resolve(process.argv[2] ?? "apps/desktop/out");
const notarized = process.argv.includes("--notarized");

async function collect(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const paths = [];
  for (const entry of entries.sort((left, right) => left.name.localeCompare(right.name))) {
    const path = resolve(directory, entry.name);
    if (entry.isDirectory() && entry.name.endsWith(".app")) paths.push(path);
    else if (entry.isDirectory()) paths.push(...(await collect(path)));
    else if (entry.isFile() && (entry.name.endsWith(".dmg") || entry.name.endsWith(".zip"))) paths.push(path);
  }
  return paths;
}

function run(command, args) {
  const result = spawnSync(command, args, { encoding: "utf8" });
  if (result.status !== 0) throw new Error(`${command} verification failed`);
  return `${result.stdout ?? ""}${result.stderr ?? ""}`;
}

function smokeApplication(path) {
  const executable = join(path, "Contents", "MacOS", "Vault Bridge");
  const result = spawnSync(executable, [], {
    encoding: "utf8",
    env: {
      ...process.env,
      VAULT_BRIDGE_NO_BOOT: "1",
      VAULT_BRIDGE_SMOKE_MAIN: "1"
    },
    timeout: 20_000
  });
  if (result.error || result.status !== 0) throw new Error("packaged Electron main smoke failed");
}

const paths = await collect(root);
const apps = paths.filter((path) => path.endsWith(".app"));
const dmgs = paths.filter((path) => path.endsWith(".dmg"));
const zips = paths.filter((path) => path.endsWith(".zip"));
if (apps.length === 0 || dmgs.length === 0 || zips.length === 0) throw new Error("expected app, DMG, and ZIP artifacts");
for (const path of dmgs) run("/usr/bin/hdiutil", ["verify", path]);
for (const path of zips) run("/usr/bin/unzip", ["-t", path]);
for (const path of apps) {
  run("/usr/bin/codesign", ["--verify", "--deep", "--strict", path]);
  smokeApplication(path);
  const plist = JSON.parse(run("/usr/bin/plutil", ["-convert", "json", "-o", "-", join(path, "Contents", "Info.plist")]));
  if (plist.NSAppTransportSecurity?.NSAllowsArbitraryLoads !== false) {
    throw new Error("macOS package must keep App Transport Security enabled");
  }
  const fuses = run("pnpm", ["exec", "electron-fuses", "read", "--app", path]);
  for (const expected of [
    "RunAsNode is Disabled",
    "EnableCookieEncryption is Enabled",
    "EnableNodeOptionsEnvironmentVariable is Disabled",
    "EnableNodeCliInspectArguments is Disabled",
    "EnableEmbeddedAsarIntegrityValidation is Enabled",
    "OnlyLoadAppFromAsar is Enabled",
    "LoadBrowserProcessSpecificV8Snapshot is Disabled",
    "GrantFileProtocolExtraPrivileges is Disabled"
  ]) {
    if (!fuses.includes(expected)) throw new Error(`unsafe Electron fuse state: ${expected}`);
  }
  if (notarized) {
    run("/usr/sbin/spctl", ["--assess", "--type", "execute", "--verbose=2", path]);
    run("/usr/bin/xcrun", ["stapler", "validate", path]);
  }
}
console.log(`macOS artifacts OK (${apps.length} app, ${dmgs.length} DMG, ${zips.length} ZIP)`);
