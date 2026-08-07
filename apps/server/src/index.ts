import { createApp } from "./app.js";
import { loadConfig } from "./config.js";

const main = async (): Promise<void> => {
  const config = loadConfig();
  const runtime = await createApp({ config });
  const close = async (): Promise<void> => {
    await runtime.close();
    process.exit(0);
  };
  process.once("SIGINT", () => void close());
  process.once("SIGTERM", () => void close());
  await runtime.app.listen({ host: config.host, port: config.port });
};

if (import.meta.url === `file://${process.argv[1]}`) void main();
