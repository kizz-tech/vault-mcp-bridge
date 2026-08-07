import { build } from "esbuild";

await build({
  entryPoints: ["src/main.ts"],
  bundle: true,
  platform: "node",
  format: "esm",
  target: "node24",
  conditions: ["development"],
  external: ["electron"],
  outfile: "dist/main.js",
  banner: {
    js: 'import { createRequire as __vaultBridgeCreateRequire } from "node:module"; const require = __vaultBridgeCreateRequire(import.meta.url);'
  }
});
