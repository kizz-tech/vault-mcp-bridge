# Vault Bridge desktop

The macOS desktop is the normal product surface. Its single setup screen owns
vault selection, SSH configuration, OpenAI Secure MCP Tunnel configuration,
deployment, synchronization, and lifecycle.

```sh
pnpm --filter @vault-mcp-bridge/desktop build
pnpm --filter @vault-mcp-bridge/desktop start
pnpm --filter @vault-mcp-bridge/desktop test
pnpm --filter @vault-mcp-bridge/desktop package
```

The renderer loads from `vaultbridge://app`. It has no localhost server, Node
integration, filesystem access, secret access, web navigation, or webviews.
The Electron main process owns the native picker, scanner, safeStorage,
OpenSSH/SFTP, Docker deployment, scheduler, and lifecycle.

Development accepts `VAULT_BRIDGE_SECURE_TUNNEL_IMAGE` with an explicit local
tag. Packaged production builds require a digest-pinned
`secure-tunnel-config.json` supplied through
`VAULT_BRIDGE_SECURE_TUNNEL_CONFIG_PATH`. This public file contains only the
image reference and sync interval. Tunnel IDs and runtime keys are entered by
the owner and stored outside the bundle.

The older `product-config.json` path selects the advanced public HTTPS/OAuth
backend. It is not required for the default private Secure Tunnel product.

Unsigned artifacts are for local testing. Public macOS distribution requires
Developer ID signing and notarization credentials supplied outside source
control.
