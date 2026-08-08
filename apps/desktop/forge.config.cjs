/* eslint-disable @typescript-eslint/no-require-imports, no-undef */
const { execFile } = require("node:child_process");
const { readdir } = require("node:fs/promises");
const path = require("node:path");
const { promisify } = require("node:util");

const execFileAsync = promisify(execFile);
const productConfigPath = process.env.VAULT_BRIDGE_PRODUCT_CONFIG_PATH
  ? path.resolve(process.env.VAULT_BRIDGE_PRODUCT_CONFIG_PATH)
  : undefined;
if (productConfigPath && path.basename(productConfigPath) !== "product-config.json") {
  throw new Error("VAULT_BRIDGE_PRODUCT_CONFIG_PATH must end in product-config.json");
}
const secureTunnelConfigPath = process.env.VAULT_BRIDGE_SECURE_TUNNEL_CONFIG_PATH
  ? path.resolve(process.env.VAULT_BRIDGE_SECURE_TUNNEL_CONFIG_PATH)
  : undefined;
if (secureTunnelConfigPath && path.basename(secureTunnelConfigPath) !== "secure-tunnel-config.json") {
  throw new Error("VAULT_BRIDGE_SECURE_TUNNEL_CONFIG_PATH must end in secure-tunnel-config.json");
}
const agentResourcesPath = path.resolve(__dirname, "agent");

module.exports = {
  packagerConfig: {
    asar: true,
    prune: false,
    ignore: [
      /^\/src(?:\/|$)/,
      /^\/tests(?:\/|$)/,
      /^\/scripts(?:\/|$)/,
      /^\/node_modules(?:\/|$)/,
      /^\/out(?:\/|$)/,
      /^\/product-config\.example\.json$/,
      /^\/tsconfig(?:\.|$)/,
      /^\/forge\.config\.cjs$/
    ],
    appBundleId: "app.vaultbridge.desktop",
    name: "Vault Bridge",
    executableName: "Vault Bridge",
    extendInfo: {
      NSAppTransportSecurity: {
        NSAllowsArbitraryLoads: false
      }
    },
    extraResource: [
      agentResourcesPath,
      ...[productConfigPath, secureTunnelConfigPath].filter(Boolean)
    ],
    osxSign: process.env.VAULT_BRIDGE_OSX_SIGN_IDENTITY
      ? { identity: process.env.VAULT_BRIDGE_OSX_SIGN_IDENTITY }
      : undefined,
    osxNotarize:
      process.env.VAULT_BRIDGE_APPLE_ID && process.env.VAULT_BRIDGE_APPLE_TEAM_ID && process.env.VAULT_BRIDGE_APPLE_APP_PASSWORD
        ? {
            appleId: process.env.VAULT_BRIDGE_APPLE_ID,
            appleIdPassword: process.env.VAULT_BRIDGE_APPLE_APP_PASSWORD,
            teamId: process.env.VAULT_BRIDGE_APPLE_TEAM_ID
          }
        : undefined
  },
  rebuildConfig: {},
  hooks: {
    packageAfterCopy: async (_forgeConfig, buildPath, _electronVersion, platform) => {
      const { flipFuses, FuseV1Options, FuseVersion } = await import("@electron/fuses");
      const basePath = path.resolve(buildPath, "../..");
      const electronExecutable = ["darwin", "mas"].includes(platform)
        ? path.join(basePath, "MacOS", "Electron")
        : path.join(basePath, platform === "win32" ? "electron.exe" : "electron");
      await flipFuses(electronExecutable, {
        version: FuseVersion.V1,
        strictlyRequireAllFuses: true,
        [FuseV1Options.RunAsNode]: false,
        [FuseV1Options.EnableCookieEncryption]: true,
        [FuseV1Options.EnableNodeOptionsEnvironmentVariable]: false,
        [FuseV1Options.EnableNodeCliInspectArguments]: false,
        [FuseV1Options.EnableEmbeddedAsarIntegrityValidation]: true,
        [FuseV1Options.OnlyLoadAppFromAsar]: true,
        // Electron ships v8_context_snapshot.<arch>.bin, not the custom
        // browser_v8_context_snapshot.bin required by this fuse.
        [FuseV1Options.LoadBrowserProcessSpecificV8Snapshot]: false,
        [FuseV1Options.GrantFileProtocolExtraPrivileges]: false,
        [FuseV1Options.WasmTrapHandlers]: true
      });
    },
    postPackage: async (_forgeConfig, result) => {
      if (result.platform !== "darwin" || process.env.VAULT_BRIDGE_OSX_SIGN_IDENTITY) return;
      for (const outputPath of result.outputPaths) {
        const applications = outputPath.endsWith(".app")
          ? [outputPath]
          : (await readdir(outputPath, { withFileTypes: true }))
              .filter((entry) => entry.isDirectory() && entry.name.endsWith(".app"))
              .map((entry) => path.join(outputPath, entry.name));
        for (const application of applications) {
          await execFileAsync("/usr/bin/codesign", ["--sign", "-", "--force", "--deep", application]);
        }
      }
    }
  },
  makers: [
    { name: "@electron-forge/maker-dmg", config: { format: "ULFO" } },
    { name: "@electron-forge/maker-zip", platforms: ["darwin"] }
  ],
  plugins: []
};
