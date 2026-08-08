# Production deployment

> This document covers the advanced public HTTPS/OAuth deployment. The default
> personal product uses OpenAI Secure MCP Tunnel; see
> [`deploy/secure-tunnel/README.md`](../deploy/secure-tunnel/README.md).

This runbook is the contract for a real installation. The desktop app owns
the normal flow; the operator supplies an approved Linux/SSH target and the
managed or self-hosted edge inputs. A successful local build, Compose parse,
container start, or one ChatGPT call is not production evidence. Record each
promotion level in [`evaluation-matrix.md`](evaluation-matrix.md).

## Deployment modes

### Managed edge (normal product path)

Owner sign-in provisions one installation through the managed edge. This is the
required edge for the normal two-input product path. The production
implementation is Cloudflare-specific: in a dedicated zone it creates an
installation-scoped Tunnel, DNS records, a client certificate from the
Mac-generated CSR, and Worker routes. The publisher Worker enforces mTLS and
emits publisher attestation. The MCP hostname Worker strips proof headers,
performs uncached online edge introspection, emits the distinct MCP-edge HMAC
attestation to the VPS, and returns `503` without forwarding when edge
authorization is unavailable. The edge assigns separate MCP and publisher
hostnames, serves owner-browser OIDC and MCP OAuth discovery/PKCE, and keeps
owner/installation metadata. It does not store vault snapshots, note text,
search results, or indexes. Existing routes can continue while the control
plane is temporarily unavailable; new setup, recovery, OAuth linking, and MCP
requests requiring fresh introspection may not. Cloudflare in-place
installation rotation currently fails closed; use revoke and coordinated
reprovisioning instead.

The owner-facing inputs remain **Vault + SSH server + Set up**. Provider account
credentials stay in the control plane and are never copied to the Mac, VPS,
Compose file, renderer, or logs.

### Self-hosted edge (Advanced)

An operator may run `@vault-mcp-bridge/edge` under their own control. Other
edge implementations are outside the current production contract. This path
requires additional inputs that the managed path hides:

- HTTPS `EDGE_ORIGIN` and `EDGE_ISSUER`;
- owner-browser OIDC issuer, audience, authorization URL, client id, token
  endpoint, and offline `EDGE_OWNER_JWKS`;
- file-backed edge state and encrypted credential vault with a stable OAuth
  signing key;
- the concrete Cloudflare provider and installation-scoped credentials; and
- separate MCP/publisher hostnames and DNS/routing policy.

`EDGE_MODE=managed` selects the managed contract; `EDGE_MODE=self-hosted` runs
the same service under operator control. Production still requires
`EDGE_PROVIDER=cloudflare`; the deterministic provider is development/test
only, and other provider adapters are not a production claim.

## Preconditions

The app's non-mutating preflight checks the SSH host before staging:

- Linux host and supported `x64`/`arm64` architecture;
- Docker Engine and Compose v2 available to the deployment user;
- rootless Docker for the default shared-host mode, or an explicitly reviewed
  rootful compatibility exception;
- at least one CPU, 512 MiB memory, and the configured free-space reserve plus
  staging bytes;
- outbound HTTPS for tunnel and publisher traffic;
- no existing project name derived from the installation id; and
- filesystem quota status recorded (application quotas remain required when a
  hard quota is unavailable).

Rootless Docker is preferred because the daemon and containers run without
root privileges ([Docker rootless mode](https://docs.docker.com/engine/security/rootless/)). A rootful daemon is an explicit trust decision; Docker group/daemon control is host-level power. Vault Bridge does not install, restart, reconfigure, or upgrade Docker, the OS, a firewall, DNS, or a reverse proxy.

SSH uses the system OpenSSH client, SSH config/Agent, and a pinned host-key
fingerprint. The renderer cannot provide a command string or arbitrary Compose
document. A changed pinned key stops setup and requires explicit review.

## Generated runtime

`@vault-mcp-bridge/deployment` renders `compose.yaml` atomically below one
private installation directory. It uses an opaque installation id to derive a
project name such as `vmb-a1b2c3d4e5f6`; every service/network/volume/secret is
labelled with that id.

The generated project contains exactly two long-running containers plus two
network-disabled one-shot secret-init jobs:

1. `server`: non-root, read-only root filesystem, no direct egress, one named
   replica volume, SQLite/FTS5 and `/readyz` health check;
2. `tunnel`: non-root, read-only, on `app_internal` plus `tunnel_egress`, the
   only egressing service, with an installation-scoped tunnel token.
3. `server_secrets_init`: one-shot, `network_mode: none`, copies publisher-edge
   and offline OAuth source files into the server's named secret volume;
4. `tunnel_secrets_init`: one-shot, `network_mode: none`, copies the tunnel
   source file into the tunnel's named secret volume.

The contract forbids host ports, host network, host filesystem binds, Docker
socket, `privileged`, static `container_name`, broad cleanup, and `--remove-orphans`.
Images are `repository@sha256:<64-hex>` references. Both services have dropped
capabilities, `no-new-privileges`, bounded CPU/memory/PIDs/tmpfs, bounded JSON
logs, and `restart: unless-stopped`. The app network is `internal: true`.

The SSH/SFTP-uploaded file-source secrets are mode `0600` for the deployment user.
Each init job copies them into its per-runtime named volume, sets the exact
runtime UID/GID and configured copy mode (default `0440`), and exits before the
long-running service starts. Long-running services mount only their own secret
volume read-only. No host port means the stack does not claim 80, 443, 8787,
or any other port.
The tunnel provider routes the public MCP and private publisher hostnames to
the internal server service.

## Configuration gates (names only)

Provision values through the edge/deployment secret manager. The following
table intentionally gives names, not values:

The desktop resolves its non-secret product configuration in this order:
`VAULT_BRIDGE_*` environment variables, then `product-config.json` in the
Electron `userData` directory, then `product-config.json` in packaged
`process.resourcesPath`. Forge embeds a public file only when
`VAULT_BRIDGE_PRODUCT_CONFIG_PATH` names a file ending in
`product-config.json`. Without real managed-edge/OIDC/image-digest inputs the
current release candidate is intentionally unconfigured; a configured
packaged smoke is required before claiming clean-install one-launch behavior.

| Component | Required production configuration |
| --- | --- |
| Desktop non-secret config | `VAULT_BRIDGE_EDGE_ORIGIN`, `VAULT_BRIDGE_OWNER_ISSUER`, `VAULT_BRIDGE_OWNER_AUTHORIZATION_ENDPOINT`, `VAULT_BRIDGE_OWNER_TOKEN_ENDPOINT`, `VAULT_BRIDGE_OWNER_JWKS_URI`, `VAULT_BRIDGE_OWNER_AUDIENCE`, `VAULT_BRIDGE_OWNER_CLIENT_ID`, digest-pinned `VAULT_BRIDGE_SERVER_IMAGE_REPOSITORY`/`VAULT_BRIDGE_SERVER_IMAGE_DIGEST` and `VAULT_BRIDGE_TUNNEL_IMAGE_REPOSITORY`/`VAULT_BRIDGE_TUNNEL_IMAGE_DIGEST`; optional `VAULT_BRIDGE_OWNER_SCOPE`, `VAULT_BRIDGE_RUNTIME_MODE`, `VAULT_BRIDGE_INSTALLATION_DIRECTORY`, and `VAULT_BRIDGE_SYNC_INTERVAL_MINUTES` |
| Server listener | `NODE_ENV=production`, `SERVER_HOST=0.0.0.0`, `SERVER_PORT`, `SERVER_DATABASE_PATH` |
| Installation/resource binding | `MCP_VAULT_ID`, `MCP_INSTALLATION_ID`, `MCP_RESOURCE_URL` (`https://…/mcp`), `PUBLISHER_PUBLIC_URL` (`https://…/`), `MCP_HOSTS`, `PUBLISHER_HOSTS`, `ALLOWED_HOSTS` (distinct surface hosts) |
| MCP auth | `JWT_ISSUER`, `JWT_AUDIENCE`, `JWT_SCOPE=vault:read`, offline `JWT_JWKS_FILE` (mounted Compose secret) and optional `JWT_CLIENT_ID`; bundle metadata must match issuer/audience and lifetime. Keys-only `JWT_ALLOW_RAW_JWKS=true` and remote `JWT_ALLOW_REMOTE_JWKS=true` + HTTPS `JWT_JWKS_URL` are explicit exceptions |
| MCP edge | Distinct `MCP_EDGE_ATTESTATION_SECRET_FILE`, `MCP_EDGE_ATTESTATION_HEADER`, `MCP_EDGE_TIMESTAMP_HEADER`, `MCP_EDGE_NONCE_HEADER`, and bounded `MAX_MCP_EDGE_ATTESTATION_ENTRIES`; the MCP Worker performs uncached online introspection and fails closed with `503` on edge outage |
| Publisher edge | `PUBLISHER_MTLS_REQUIRED=true`, `PUBLISHER_EDGE_ATTESTATION_SECRET_FILE` (mounted Compose secret), `PUBLISHER_EDGE_ATTESTATION_HEADER`, `PUBLISHER_EDGE_CERT_STATUS_HEADER`, `PUBLISHER_EDGE_TIMESTAMP_HEADER`, `PUBLISHER_EDGE_NONCE_HEADER`, `PUBLISHER_EDGE_CERT_STATUS`, and bounded `MAX_PUBLISHER_EDGE_ATTESTATION_ENTRIES` |
| Runtime budgets | `MAX_BODY_BYTES`, `MAX_VAULT_BYTES`, `MAX_DATABASE_BYTES`, `MAX_INDEX_BYTES`, `MAX_TEMP_BYTES`, `MIN_FREE_BYTES`, `MAX_RETAINED_GENERATIONS` (at least 2), `REQUEST_RATE_PER_MINUTE`, `REQUEST_BURST`, `MAX_CONCURRENT_PER_PRINCIPAL`, `MAX_PRINCIPAL_BUCKETS`, `PRINCIPAL_BUCKET_TTL_SECONDS`, and `MAX_PUBLISHER_EDGE_ATTESTATION_ENTRIES` |
| Compose secrets | tunnel credential, offline OAuth verification bundle, distinct publisher-edge and MCP-edge HMAC secrets; SSH/SFTP source files arrive as deployment-user `0600` and are copied by network-disabled init jobs into per-runtime named volumes; publisher Mac mTLS private key remains off the VPS |
| Edge owner auth and persistence | `EDGE_ORIGIN`, `EDGE_ISSUER`, `EDGE_OWNER_ISSUER`, `EDGE_OWNER_AUDIENCE`, `EDGE_OWNER_JWKS`, `EDGE_OWNER_AUTHORIZATION_URL`, `EDGE_OWNER_CLIENT_ID`, `EDGE_OWNER_TOKEN_ENDPOINT` (optional `EDGE_OWNER_SCOPE`); `EDGE_PROVIDER=cloudflare`; `EDGE_STATE_FILE`, `EDGE_CREDENTIAL_VAULT_FILE`, `EDGE_CREDENTIAL_MASTER_KEY_FILE`; `EDGE_CLOUDFLARE_API_TOKEN_FILE`, `EDGE_CLOUDFLARE_ACCOUNT_ID`, `EDGE_CLOUDFLARE_ZONE_ID`, `EDGE_CLOUDFLARE_ZONE_NAME` |

`MCP_DEV_TOKEN`, `EDGE_DEV_OWNER_TOKEN`, `EDGE_DEV_OWNER_ID`, auto-approval,
HTTP origins, `JWT_JWKS_JSON` in an ad-hoc environment, and disabled mTLS are
development/test conveniences. Production startup fails closed when required
values or secret files are absent. Never place secret values in `.env`, YAML,
shell history, a ticket, or a release manifest.

`DurableEdgeStore` and `DurableCredentialVault` serialize their own writes and
survive a restart, but they are single-writer adapters. Run exactly one edge
process for each state file; there is no multi-process transaction or global
distributed rate-limit guarantee. Cloudflare hostname-association mutations
are serialized in that process. Each provider mutation is checkpointed in a
durable cleanup journal; retry reconciles the journal before allocating new
resources, treats delete-404 as already removed, and leaves other cleanup
failures visible instead of marking a route revoked prematurely. This does
not coordinate another edge process or out-of-band Cloudflare administrator.

## One-launch setup sequence

The app runs these internal stages as one resumable operation and records a
redacted receipt:

1. Owner signs in; the app receives an account session through the browser.
2. Native folder picker selects a vault and captures a bounded preview.
3. Server sheet records address/user/SSH port and confirms host key.
4. Preflight checks the host without mutation.
5. The Mac generates an installation-scoped publisher mTLS private key and
   PKCS#10 CSR in safe storage; only the CSR is sent to the edge.
6. Edge allocates installation metadata and secret references; Cloudflare
   issues the publisher certificate and creates the tunnel/MCP/publisher Worker
   routes. The MCP Worker performs uncached online introspection and emits a
   distinct MCP-edge HMAC proof before forwarding.
7. The app generates/atomically stages digest-pinned Compose and secret files.
8. SSH runs only the deployment allowlist: `config`, `pull`, `up --detach
   --no-build`, bounded `ps`/`logs`, and exact-project stop/down operations.
9. Dynamic health/readiness checks pass; the publisher device is bound (the
   legacy pairing adapter remains internal and invisible to the owner). If a
   crash occurs after pairing succeeds but before local state commits, retry
   with a fresh one-use code for the same identity and the server returns the
   existing device idempotently.
10. The Mac uploads the first complete, signed snapshot over the private ingest
   route; server validation activates it atomically.
11. The app verifies MCP resource metadata, OAuth discovery, and the endpoint,
   then shows **Ready**.

There is no user-visible pairing code, terminal, tunnel command, or key
generation step. A failed setup cleans only its own staging resources and can
resume from the last verified phase. When the record is ready, Electron keeps
background sync in the main process and never reopens SSH for that sync.

Credential leases are encrypted references, not bearer values in the UI. The
desktop redeems each lease with the implemented
`X25519-HKDF-SHA256-AES-256-GCM` envelope, writes plaintext only to a private
`0600` staging file for bounded upload (or keeps it ephemeral for a Keychain
write), and removes that file in a `finally` path. Lease kinds (`tunnel`,
`publisher-mtls`, `publisher-edge-attestation`, and `mcp-edge-attestation`)
remain distinct and revocable. Cloudflare's installation `rotate` call
currently fails closed; rotation is not a supported one-click operation.
OAuth client revocation increments that client's monotonic epoch and
invalidates its codes, refresh tokens, and access tokens without affecting
unrelated clients.

## Verification before handoff

Record, with secrets redacted:

- release commit/version and immutable server/tunnel image digests;
- Compose project name/installation label and `docker compose config` result;
- `/readyz` result through the tunnel and private publisher route;
- proof that `docker compose ps` shows only the two long-running services after
  the two one-shot init jobs complete, with no published ports or host binds;
- OAuth authorization-server and protected-resource metadata, PKCE flow,
  issuer/audience/scope/installation/vault/client checks, and revoke result;
- MCP Worker uncached introspection, `503` edge-outage behavior, distinct MCP
  HMAC attestation, direct-origin denial, and client-scope revocation-epoch
  invalidation;
- publisher mTLS handshake, edge attestation, device signature, nonce replay,
  and device revoke result;
- first snapshot receipt, active/rollback generation, quotas, and restart/
  rollback behavior; and
- the ChatGPT account-level custom MCP connection and a read-only `search`/
  `fetch` call using synthetic or approved data.

The ChatGPT connection is configured outside the repository through ChatGPT
Web/the account surface when offered to the workspace. A Web success does not
prove native mobile support; add a separate client/account observation if that
compatibility target matters.

## Updates and removal

Updates verify a signed release manifest and digest, check capacity, pull the
candidate image, restart only the exact project with `up --detach --no-build`,
run health/MCP contract checks, and automatically restore the prior digest on
failure. They do not change the host daemon or unrelated projects.

Removal has two explicit choices:

- **Remove service, keep replica** — stop/remove only the exact Compose project,
  remove revoked credential volumes/staged secret files, and retain only the
  recorded replica data volume;
- **Remove service and replica** — additionally remove its labelled data volume.

Neither action can delete or modify the local vault. Tunnel, OAuth, publisher,
and edge credentials are revoked independently. A broad `docker system prune`,
wildcard volume deletion, `--remove-orphans`, or host-wide command is outside
the product contract. The desktop Settings surface keeps **Disconnect** and
**Remove server copy** reachable; Disconnect is the non-destructive revoke/
stop path backed by a durable cleanup-only receipt, while the destructive
copy-removal path remains behind native confirmation and clears that receipt
only after exact absence is verified. New setup is blocked while a retained
receipt exists. Failed Cloudflare cleanup remains journaled and retryable rather
than being reported as complete.

## What this document does not claim

It does not claim that this checkout has a production edge account, a named
provider/tunnel, a configured identity provider, a deployed VPS, a signed or
notarized desktop package, a published image, or a connected ChatGPT/mobile
client. Those claims require the corresponding run receipt and evaluation
level.
