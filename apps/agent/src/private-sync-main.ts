import { resolve } from "node:path";
import { runPrivateSync } from "./private-sync.js";

const args = process.argv.slice(2);
const configIndex = args.indexOf("--config");
const configPath = configIndex >= 0 ? args[configIndex + 1] : undefined;
if (!configPath || args.length !== 2) throw new Error("usage: private-sync --config <absolute-path>");

const receipt = await runPrivateSync({ configPath: resolve(configPath) });
process.stdout.write(`${JSON.stringify(receipt)}\n`);
