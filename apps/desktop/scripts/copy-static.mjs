import { cp, mkdir } from "node:fs/promises";
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
await mkdir(assetDestination, { recursive: true });
await cp(resolve(root, "../../deploy/secure-tunnel/compose.example.yaml"), resolve(assetDestination, "secure-tunnel-compose.yaml"));
