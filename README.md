# Vault Bridge

Vault Bridge is a read-only bridge from one Obsidian-compatible Markdown vault
to an authenticated MCP endpoint. The product is one installed Electron
application. The Mac reads the canonical vault, signs complete snapshots, and
publishes them over an outbound connection to an installation-scoped server.
ChatGPT can then call only bounded `search` and `fetch` tools against the
replaceable remote replica.

The normal product path is deliberately small:

1. Open Vault Bridge and sign in to the owner account in the system browser.
2. Choose a vault folder.
3. Add a Linux server over SSH.
4. Select **Set up**. The app runs preflight, stages and starts the isolated
   stack, binds publisher credentials, uploads the first snapshot, and verifies
   the endpoint as one resumable operation.
5. Select **Copy URL & Open**. The app copies the exact HTTPS MCP resource,
   opens ChatGPT, and the owner completes the external account consent flow.

The user does not run the agent, server, pairing CLI, Docker Compose, tunnel,
key-generation, or synchronization commands. Those are internal implementation
stages. The legacy developer harness remains available for protocol tests (see
below), but it is not the product onboarding path.

## Product boundary

- The local vault is canonical. The server stores only a replaceable,
  read-only projection and SQLite FTS5 index.
- V1 has no write, delete, shell, arbitrary path, attachment download, or
  server-initiated control channel.
- The Mac is the only vault reader. The server cannot initiate a read or
  command on the Mac.
- A managed edge/control plane is required for the normal two-input experience
  (Vault + SSH) and owns
  owner sign-in, installation metadata, OAuth authorization, and a scoped
  tunnel reference, never note contents. A self-hosted edge/domain/OAuth
  configuration is an Advanced path with additional operator inputs.
- The VPS runtime has exactly two long-running containers for one installation:
  a non-root `server` and an outbound-only `tunnel`, plus two network-disabled
  one-shot secret-init jobs. The server and tunnel share an internal network;
  only the tunnel joins the egress network. Generated Compose publishes no
  host ports, host binds, Docker socket, or static `container_name`.

```text
Electron app (Mac)
  ├─ vault scanner + policy + snapshot signer
  ├─ setup orchestrator + SSH adapter + OS Keychain
  └─ outbound publisher (mTLS at edge + Ed25519 request signing)
                         │
                         ▼
                 managed or self-hosted edge
                  ┌──────────────┐
                  │ Worker routes│  MCP + private ingest hostnames
                  └──────┬───────┘
                         │
              ┌──────────▼──────────┐
              │ server + tunnel     │  isolated Compose project
              │ replica + FTS5      │  active + rollback generations
              └──────────┬──────────┘
                         │ OAuth/JWT
                         ▼
                    ChatGPT MCP
```

Read [`docs/architecture.md`](docs/architecture.md) for trust boundaries and
[`docs/threat-model.md`](docs/threat-model.md) before using personal data.

The generated Compose project has two long-running services and two
network-disabled, one-shot secret-init jobs. SSH/SFTP uploads each file-source
secret with deployment-user mode `0600`; an init job copies it into that
runtime's named volume, sets the exact non-root UID/GID and configured copy
mode (the default is `0440`), and the long-running container mounts only its
own volume read-only. No file-source secret is mounted directly into a
long-running service.

## Repository status

This checkout contains the current desktop, orchestrator, server, edge, tests,
and deployment contracts. The final local checks, unsigned macOS package, and
synthetic shared-VPS compatibility drills are recorded in
[`docs/verification-2026-08-07.md`](docs/verification-2026-08-07.md). They do
not prove a Developer ID-signed/notarized package, published image, production
VPS deployment, live Cloudflare/OIDC integration, or connected ChatGPT
account. Those states require the evidence described in
[`docs/evaluation-matrix.md`](docs/evaluation-matrix.md). The project is
licensed under [Apache-2.0](LICENSE); report vulnerabilities through GitHub's
private vulnerability reporting flow described in [SECURITY.md](SECURITY.md).

## Local checks

Requirements are Node.js 24 or newer and pnpm 10. The checked-in `.nvmrc` is
the reference Node version.

```sh
pnpm install --frozen-lockfile
pnpm check
```

`pnpm check` runs lint, typecheck, tests, builds, Compose-contract validation,
and release-hygiene validation. Individual checks are available as
`pnpm lint`, `pnpm typecheck`, `pnpm test`, `pnpm build`, `pnpm validate`, and
`pnpm validate:compose`.

## Desktop development

The normal local surface is the Electron shell:

```sh
pnpm dev                 # alias for the desktop app
pnpm dev:desktop
pnpm --filter @vault-mcp-bridge/desktop test
pnpm --filter @vault-mcp-bridge/desktop package:dir
```

Use only a synthetic fixture such as `fixtures/vault/`. The packaged renderer
is loaded from the `vaultbridge://app` origin with sandboxing,
`contextIsolation`, disabled Node integration, and an explicit IPC allowlist.
The main process owns filesystem access, SSH, Keychain-backed secrets, and
background lifecycle. For a managed installation the Mac also generates and
retains the publisher mTLS private key and PKCS#10 CSR locally; only the CSR
crosses the owner/edge boundary. Private keys and passphrases are never
displayed in the renderer or committed to the repository.

## Legacy developer harness (not product onboarding)

The repository still exposes the old loopback agent/server surfaces so that
protocol and migration tests can run without the Electron orchestrator. Use
them only with synthetic data and disposable credentials:

```sh
pnpm dev:legacy:server
pnpm dev:legacy:agent
pnpm dev:edge
```

The server harness accepts a development-only `MCP_DEV_TOKEN`; the agent
harness can be made loopback HTTP with `BRIDGE_ALLOW_LOOPBACK_HTTP=1` and
defaults to `BRIDGE_HOST=127.0.0.1`, `BRIDGE_PORT=3210`. The legacy pairing
commands are:

```sh
pnpm --filter @vault-mcp-bridge/server pairing-code -- --vault-id <synthetic-id>
pnpm --filter @vault-mcp-bridge/server revoke-device -- --device-id <opaque-id>
```

These commands model the bootstrap protocol only. They are not shown to a
normal owner and must never be enabled as production authentication. See
[`docs/local-development.md`](docs/local-development.md) for the complete
harness sequence and its limits.

## MCP and ChatGPT

V1 exposes exactly two read-only tools:

- `search`, with bounded text input and opaque result IDs;
- `fetch`, by one opaque result ID and a bounded response.

The public endpoint is HTTPS `/mcp`. Production requests use OAuth 2.1-style
authorization-code + PKCE (`S256`), a resource indicator, the `vault:read`
scope, issuer/audience checks, installation/vault/client claims, and an offline
JWKS bundle in the server container. The managed MCP hostname is a Cloudflare
Worker route: it strips caller-supplied edge-proof headers, performs an
uncached online introspection against the edge authorization state, and fails
closed with `503` when that edge decision is unavailable. After a successful
decision it adds a distinct MCP-edge HMAC attestation bound to the exact
request and bearer-token digest; the VPS verifies that proof before normal
OAuth/JWT checks. Publisher authentication is a separate plane: edge mTLS,
its own installation-scoped attestation, and the device's Ed25519 signed
request. Neither credential can be substituted for the other.

OpenAI's current MCP and authentication guidance is the authority for the
client-side contract: [MCP servers](https://developers.openai.com/api/docs/mcp),
[MCP server building](https://developers.openai.com/plugins/build/mcp-server),
and [app/plugin authentication](https://developers.openai.com/plugins/build/auth).
Vault Bridge does not ship a ChatGPT UI. The owner configures a custom MCP
connection through ChatGPT Web/the account surface when that feature is
available to the account and workspace. Availability, consent screens, and
mobile clients are account/version dependent; this repository makes no blanket
mobile guarantee. Verify the target account and client in the L4 evaluation.

## Configuration and credential gates

Values below are names and policy gates, not secrets. Supply values through the
OS Keychain, an edge credential vault, a deployment secret store, or a
Compose secret file under the private installation directory. Never place a
real vault path, token, key, certificate, or domain in source control.

| Surface | Required production settings / material | Development-only escape hatch |
| --- | --- | --- |
| Server identity | `JWT_ISSUER`, `JWT_AUDIENCE`, `JWT_JWKS_FILE` with matching offline bundle metadata, `JWT_SCOPE=vault:read`; keys-only `JWT_ALLOW_RAW_JWKS` or remote `JWT_ALLOW_REMOTE_JWKS` + HTTPS `JWT_JWKS_URL` are explicit exceptions | `MCP_DEV_TOKEN` only when `NODE_ENV` is not `production` |
| Installation binding | `MCP_VAULT_ID`, `MCP_INSTALLATION_ID`, `MCP_RESOURCE_URL`, `PUBLISHER_PUBLIC_URL`, `MCP_HOSTS`, `PUBLISHER_HOSTS`, `ALLOWED_HOSTS` | Loopback defaults from `.env.example` |
| Publisher edge | `PUBLISHER_MTLS_REQUIRED=true`, `PUBLISHER_EDGE_ATTESTATION_SECRET_FILE`, `PUBLISHER_EDGE_ATTESTATION_HEADER`, `PUBLISHER_EDGE_CERT_STATUS_HEADER`, `PUBLISHER_EDGE_TIMESTAMP_HEADER`, `PUBLISHER_EDGE_NONCE_HEADER`, and bounded attestation nonce retention | `PUBLISHER_MTLS_REQUIRED=false` is acceptable only for synthetic tests |
| MCP edge | `MCP_EDGE_ATTESTATION_SECRET_FILE`, `MCP_EDGE_ATTESTATION_HEADER`, `MCP_EDGE_TIMESTAMP_HEADER`, `MCP_EDGE_NONCE_HEADER`, and bounded `MAX_MCP_EDGE_ATTESTATION_ENTRIES`; the Worker performs uncached online introspection before forwarding | Synthetic local adapters may omit the MCP edge proof only outside production |
| Runtime safety | `MAX_BODY_BYTES`, `MAX_VAULT_BYTES`, `MAX_DATABASE_BYTES`, `MAX_INDEX_BYTES`, `MAX_TEMP_BYTES`, `MIN_FREE_BYTES`, `MAX_RETAINED_GENERATIONS` | Lower bounded values are safer for local tests |
| Edge owner auth and persistence | HTTPS `EDGE_ORIGIN`/`EDGE_ISSUER`; owner-browser OIDC `EDGE_OWNER_ISSUER`, `EDGE_OWNER_AUDIENCE`, `EDGE_OWNER_JWKS`, `EDGE_OWNER_AUTHORIZATION_URL`, `EDGE_OWNER_CLIENT_ID`, `EDGE_OWNER_TOKEN_ENDPOINT` (optional `EDGE_OWNER_SCOPE`); `EDGE_PROVIDER=cloudflare`; durable `EDGE_STATE_FILE`, `EDGE_CREDENTIAL_VAULT_FILE`, `EDGE_CREDENTIAL_MASTER_KEY_FILE`, stable signer in that vault; Cloudflare `EDGE_CLOUDFLARE_API_TOKEN_FILE`, `EDGE_CLOUDFLARE_ACCOUNT_ID`, `EDGE_CLOUDFLARE_ZONE_ID`, `EDGE_CLOUDFLARE_ZONE_NAME` | `EDGE_DEV_OWNER_TOKEN`, `EDGE_DEV_OWNER_ID`, deterministic provider |
| Desktop non-secret config | `VAULT_BRIDGE_EDGE_ORIGIN`, `VAULT_BRIDGE_OWNER_ISSUER`, `VAULT_BRIDGE_OWNER_AUTHORIZATION_ENDPOINT`, `VAULT_BRIDGE_OWNER_TOKEN_ENDPOINT`, `VAULT_BRIDGE_OWNER_JWKS_URI`, `VAULT_BRIDGE_OWNER_AUDIENCE`, `VAULT_BRIDGE_OWNER_CLIENT_ID`, optional `VAULT_BRIDGE_OWNER_SCOPE`, digest-pinned `VAULT_BRIDGE_SERVER_IMAGE_REPOSITORY`/`VAULT_BRIDGE_SERVER_IMAGE_DIGEST` and `VAULT_BRIDGE_TUNNEL_IMAGE_REPOSITORY`/`VAULT_BRIDGE_TUNNEL_IMAGE_DIGEST`; optional `VAULT_BRIDGE_RUNTIME_MODE`, `VAULT_BRIDGE_INSTALLATION_DIRECTORY`, `VAULT_BRIDGE_SYNC_INTERVAL_MINUTES` | Loopback URLs only when development is explicit |
| Desktop credentials | SSH Agent/Keychain identity and the owner sign-in session | `VAULT_BRIDGE_NO_BOOT=1` for headless tests |

Production startup fails closed when required authentication, installation
binding, trusted hosts, offline verification, or publisher attestation is
missing. The exact defaults and compatibility aliases are documented in
`.env.example`, `docs/production-deployment.md`, and
`deploy/runtime/README.md`.

The packaged desktop resolves non-secret configuration as environment variables
first, then `product-config.json` in Electron `userData`, then the packaged
`process.resourcesPath/product-config.json`. Forge embeds a public file only
when `VAULT_BRIDGE_PRODUCT_CONFIG_PATH` names a file ending in
`product-config.json`; it never embeds credentials or lease material. Without
real managed-edge/OIDC/image-digest inputs this release candidate is
intentionally unconfigured, and a clean-install one-launch claim requires a
configured packaged smoke rather than source tests alone.

Use [`apps/desktop/product-config.example.json`](apps/desktop/product-config.example.json)
as the public-only shape. Replace every example value, keep image references
digest-pinned, save the release input as `product-config.json`, and pass its
path through `VAULT_BRIDGE_PRODUCT_CONFIG_PATH` during packaging.

The production edge uses one file-backed state writer per `EDGE_STATE_FILE`;
the adapter is not a multi-process store. Edge and server request guards are
bounded per process; no global distributed rate-limit guarantee is made.

## Further reading

- [`docs/architecture.md`](docs/architecture.md) — components and data flow.
- [`docs/protocol.md`](docs/protocol.md) — HTTP, snapshot, MCP, and auth
  contracts; legacy pairing is explicitly marked.
- [`docs/production-deployment.md`](docs/production-deployment.md) — managed
  and self-hosted deployment gates.
- [`docs/local-development.md`](docs/local-development.md) — commands and
  synthetic harnesses.
- [`docs/operations-runbook.md`](docs/operations-runbook.md) — health, update,
  rollback, removal, and incident actions.
- [`docs/release-process.md`](docs/release-process.md) — artifact and manifest
  verification without implied publication.
- [`docs/evaluation-matrix.md`](docs/evaluation-matrix.md) — evidence levels.
- [`docs/product-spec.md`](docs/product-spec.md) — the current UX/product
  contract and implementation boundary.

Official references: [Obsidian storage](https://help.obsidian.md/Advanced+topics/How+Obsidian+stores+data), [Docker rootless mode](https://docs.docker.com/engine/security/rootless/), [Compose networking](https://docs.docker.com/compose/how-tos/networking/), and [Cloudflare Tunnel](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/).
