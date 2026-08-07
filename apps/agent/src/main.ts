import { createAgentApp } from './app.js';

const host = process.env.BRIDGE_HOST || '127.0.0.1';
const port = Number(process.env.BRIDGE_PORT || 3210);
const app = await createAgentApp({ logger: true });

if (host !== '127.0.0.1' && host !== 'localhost' && process.env.BRIDGE_UNSAFE_DEV !== '1') {
  throw new Error('Refusing non-loopback BRIDGE_HOST; set BRIDGE_UNSAFE_DEV=1 only for local development');
}

await app.listen({ host, port });
app.log.info({ host, port, readOnly: true }, 'Vault MCP Bridge local agent ready');
