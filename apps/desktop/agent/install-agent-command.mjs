#!/usr/bin/env node
/* global process */
import { chmod, mkdir, open, rename, stat } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";

const arguments_ = process.argv.slice(2);
const appIndex = arguments_.indexOf("--app");
if (arguments_.length !== 0 && (arguments_.length !== 2 || appIndex !== 0 || !arguments_[1])) {
  fail("usage: install-agent-command.mjs [--app /absolute/path/to/Vault Bridge.app]");
}

const application = resolve(arguments_[1] ?? "/Applications/Vault Bridge.app");
if (!application.endsWith(".app")) fail("application path must end in .app");
const executable = join(application, "Contents", "MacOS", "Vault Bridge");
try {
  const metadata = await stat(executable);
  if (!metadata.isFile()) fail("Vault Bridge executable was not found");
} catch {
  fail("Vault Bridge executable was not found");
}

const destination = join(homedir(), ".local", "bin", "vault-bridge");
await mkdir(dirname(destination), { recursive: true, mode: 0o700 });
const temporary = `${destination}.${process.pid}.tmp`;
const handle = await open(temporary, "wx", 0o700);
try {
  await handle.writeFile([
    "#!/bin/sh",
    "set -eu",
    `VAULT_BRIDGE_AGENT_MODE=1 exec ${shellQuote(executable)} "$@"`,
    ""
  ].join("\n"), "utf8");
  await handle.sync();
} finally {
  await handle.close();
}
await chmod(temporary, 0o700);
await rename(temporary, destination);
await chmod(destination, 0o700);
process.stdout.write(`${JSON.stringify({ ok: true, command: destination })}\n`);

function shellQuote(value) {
  return `'${value.replaceAll("'", "'\\''")}'`;
}

function fail(message) {
  process.stderr.write(`${message}\n`);
  process.exit(1);
}
