#!/usr/bin/env node
/* global process */

import { spawn } from "node:child_process";
import { createRequire } from "node:module";
import { resolve } from "node:path";

if (process.platform !== "darwin") process.exit(0);

const require = createRequire(import.meta.url);
const nodeGyp = require.resolve("@electron/node-gyp/bin/node-gyp.js");
const repositoryRoot = resolve(import.meta.dirname, "../../..");
const allowedEnvironmentKeys = [
  "CC",
  "CXX",
  "DEVELOPER_DIR",
  "HOME",
  "PATH",
  "PYTHON",
  "SDKROOT",
  "TMPDIR",
  "npm_config_arch",
  "npm_config_cache",
  "npm_config_devdir",
  "npm_config_nodedir",
  "npm_config_target_arch"
];
const buildEnvironment = Object.fromEntries(
  allowedEnvironmentKeys.flatMap((key) => process.env[key] ? [[key, process.env[key]]] : [])
);
buildEnvironment.NO_COLOR = "1";
buildEnvironment.npm_config_loglevel = "error";

for (const dependency of ["macos-alias", "fs-xattr"]) {
  const workingDirectory = resolve(repositoryRoot, "node_modules", dependency);
  const exitCode = await new Promise((resolveExit, reject) => {
    const child = spawn(process.execPath, [nodeGyp, "rebuild", "--loglevel=error"], {
      cwd: workingDirectory,
      env: buildEnvironment,
      stdio: "ignore"
    });
    child.once("error", reject);
    child.once("exit", (code) => resolveExit(code ?? 1));
  });
  if (exitCode !== 0) throw new Error(`Failed to build ${dependency}`);
}
