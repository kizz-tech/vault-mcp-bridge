import { cp, mkdir, readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "..");
const source = resolve(root, "src/renderer");
const destination = resolve(root, "dist/renderer");
const assetDestination = resolve(root, "dist/assets");

await mkdir(destination, { recursive: true });
await cp(resolve(source, "index.html"), resolve(destination, "index.html"));
await cp(resolve(source, "styles.css"), resolve(destination, "styles.css"));

const rendererBundle = await readFile(resolve(destination, "app.js"), "utf8");
if (/^\s*import\s/mu.test(rendererBundle)) {
  throw new Error("Renderer bundle must be self-contained for the vaultbridge protocol");
}

await mkdir(assetDestination, { recursive: true });
await cp(resolve(root, "../../deploy/secure-tunnel/compose.example.yaml"), resolve(assetDestination, "secure-tunnel-compose.yaml"));
