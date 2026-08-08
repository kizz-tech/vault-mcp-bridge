# Vault Bridge

Vault Bridge gives ChatGPT read-only access to an Obsidian-compatible vault.
It is one macOS application: choose a vault, add an SSH server, add an OpenAI
Secure MCP Tunnel, and select **Set up**.

The Mac remains the only reader of the canonical vault. The VPS receives a
replaceable snapshot and exposes exactly two MCP tools:

- `search({ query })` — full-text search with opaque result IDs;
- `fetch({ id })` — one document by an opaque ID.

There is no write, delete, shell, arbitrary-path, or server-to-Mac command
surface in v1.

## How it works

```text
Obsidian vault on Mac
        │ local scan
        ▼
Vault Bridge.app ──SSH──► isolated Docker project on your VPS
        │                    │ SQLite snapshot + FTS5
        │                    │ no host ports
        │                    │ outbound polling only
        │                    ▼
        └──────────── OpenAI Secure MCP Tunnel ◄──────── ChatGPT
```

Phone-to-Mac freshness remains an iCloud/Obsidian responsibility. Vault Bridge
publishes only bytes that are visible on the Mac during a successful scan.

## First setup

Requirements:

- macOS on the computer that can read the vault;
- a Linux VPS reachable through SSH;
- Docker Engine with Docker Compose on the VPS;
- a ChatGPT/OpenAI workspace with Secure MCP Tunnels enabled.

OpenAI requires two account-owned values. Vault Bridge cannot create or consent
to them on your behalf:

1. Create a tunnel in [OpenAI Tunnels](https://platform.openai.com/settings/organization/tunnels).
2. Create a restricted runtime key in [OpenAI API keys](https://platform.openai.com/settings/organization/api-keys) with only **Tunnels Read + Use**.

Then open Vault Bridge:

1. Choose the vault folder.
2. Add the VPS address, SSH user, and port.
3. Add the tunnel ID and runtime key.
4. Select **Set up**.

The app verifies the OpenAI key, pins the SSH host identity, checks Docker,
starts one isolated Compose project, uploads the first snapshot, and schedules
sync. The runtime key is encrypted with Electron/macOS `safeStorage`; it is
never stored in renderer state, Markdown, logs, or the repository.

Finally, create or connect the custom plugin in ChatGPT Web, select the same
tunnel, and approve the connection. That consent is account-scoped; the remote
runtime does not need an open browser or a reachable home computer.

This is a developer custom plugin, not a “licensed MCP”. Publishing it in the
ChatGPT catalog is a separate optional review and distribution process.

## Product behavior

The normal interface contains only three setup rows:

```text
Vault      Not selected       Choose
Server     Not configured        Add
OpenAI     Not configured        Add

                              Set up
```

Setup progress stays on the same screen: checking server, starting container,
securing connection, synchronizing vault, ready. Journal and settings remain
secondary surfaces.

The desktop app supports:

- automatic sync every five minutes by default;
- manual **Synchronize**;
- pause/resume;
- start at login;
- disconnect while retaining the replica;
- explicit removal of the exact server copy.

## Security model

- Local files are canonical; the server replica is disposable.
- Only `.md`, `.canvas`, and `.base` text is included by default.
- Hidden directories, `.obsidian`, `.git`, `node_modules`, and symlinks are
  excluded by default.
- Document IDs are opaque; local absolute paths never reach ChatGPT.
- Snapshots are complete generations and activate atomically.
- The VPS service runs as a non-root UID with a read-only root filesystem,
  dropped capabilities, `no-new-privileges`, CPU/memory/PID/tmpfs/log limits,
  and no published host ports or Docker socket.
- The OpenAI runtime key is copied by a network-disabled init container into a
  private named volume and mounted read-only by the runtime.
- The official OpenAI tunnel client and build inputs are version and SHA-256
  pinned.
- Note content and MCP results are untrusted data, not instructions.

The VPS administrator and Docker daemon can inspect container data. Use a VPS
you trust; resource limits reduce accidental interference but are not a hostile
multi-tenant sandbox.

Read [architecture](docs/architecture.md), the [threat model](docs/threat-model.md),
and the [Secure Tunnel runbook](deploy/secure-tunnel/README.md) before using
sensitive data.

## Development

Requirements are Node.js 24+ and pnpm 10.

```sh
pnpm install --frozen-lockfile
pnpm check
pnpm dev
```

Use only synthetic fixtures during development. The Electron renderer loads
from `vaultbridge://app`, with sandboxing, context isolation, disabled Node
integration, blocked navigation/webviews, and an explicit IPC allowlist.

Useful focused checks:

```sh
pnpm --filter @vault-mcp-bridge/desktop test
pnpm --filter @vault-mcp-bridge/server test
pnpm docker:build:secure-tunnel
pnpm package:desktop:dir
```

The packaged desktop requires a public, digest-pinned
`secure-tunnel-config.json`. See
[`apps/desktop/secure-tunnel-config.example.json`](apps/desktop/secure-tunnel-config.example.json)
and [`docs/release-process.md`](docs/release-process.md).

## Repository layout

- `apps/desktop` — one-launch macOS product and SSH deployment owner;
- `apps/agent` — local scanner/snapshot sync implementation and legacy harness;
- `apps/server` — snapshot store, FTS5 search, HTTP MCP, and private stdio MCP;
- `deploy/secure-tunnel` — primary isolated Compose template;
- `packages/*` — scanner, contracts, deployment, and orchestration libraries;
- `apps/edge` and `deploy/runtime` — advanced public HTTPS/OAuth mode.

## Advanced public endpoint

The repository retains a managed/self-hosted public HTTPS + OAuth architecture
for teams that need a conventional public MCP URL instead of OpenAI Secure MCP
Tunnel. It requires an edge identity/control plane, Cloudflare resources,
separate publisher and MCP authentication, and more operational work. It is not
the default personal setup and is not required by the desktop Secure Tunnel
flow.

Legacy loopback commands exist only for synthetic protocol testing:

```sh
pnpm dev:legacy:server
pnpm dev:legacy:agent
pnpm dev:edge
```

## License and security reports

Vault Bridge is licensed under [Apache-2.0](LICENSE). Report vulnerabilities
through the private process in [SECURITY.md](SECURITY.md), not a public issue.
