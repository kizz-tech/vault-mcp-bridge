# Vault Bridge desktop

The macOS desktop shell is one Electron application. The renderer is loaded
from the packaged `vaultbridge://app` origin; it does not start a localhost web
server and cannot access Node APIs.

```sh
pnpm --filter @vault-mcp-bridge/desktop build
pnpm --filter @vault-mcp-bridge/desktop dev
pnpm --filter @vault-mcp-bridge/desktop test
pnpm --filter @vault-mcp-bridge/desktop package
```

`DesktopBackend` is the narrow integration port for the setup orchestrator. The
default backend provides a local, read-only preview and a safe placeholder when
the orchestrator is not injected. The packaged app uses the system OpenSSH
client through `spawn` with fixed arguments; it never stores private keys or
passes command strings through a shell.

Unsigned artifacts are suitable for local testing only. Distribution requires
Developer ID signing and notarization credentials supplied through the Forge
environment; no credentials belong in this repository.
