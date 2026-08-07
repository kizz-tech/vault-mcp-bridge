# Architecture

Vault Bridge is a single-owner, read-only projection of an
Obsidian-compatible vault. The Mac is the only canonical reader. Everything
past the desktop boundary is a derived replica and may be stopped, replaced,
or rebuilt. “Universal” means that the scanner does not depend on a LifeOS
folder layout, frontmatter taxonomy, or theme; it does not mean that every
plugin database is interpreted.

## Product path and trust boundaries

The normal user sees one Electron application:

```text
owner sign-in (system browser, OAuth code + PKCE)
             │
             ▼
Electron desktop
  ├─ renderer (sandboxed, no Node APIs, allowlisted IPC)
  ├─ setup orchestrator (durable, resumable state machine)
  ├─ vault scanner + export policy + snapshot signer
  ├─ SSH adapter (bounded provisioning/status/update/remove)
  ├─ OS Keychain/SSH Agent adapters
  └─ outbound publisher (HTTPS, device signature, edge mTLS)
             │ no inbound desktop port
             ▼
managed edge (default) or self-hosted edge (Advanced)
  ├─ owner/installations/OAuth control plane (no vault contents)
  └─ installation-scoped tunnel routes
             │
             ▼
VPS installation Compose project
  ┌───────────────────────────┐
  │ server  ◄── app_internal  │  non-root, read-only root, replica volume
  │ tunnel  ──► tunnel_egress │  only egressing service
  │ secret-init ×2 (none)     │  one-shot, network-disabled copy jobs
  └───────────────────────────┘
             │
             ├─ private publisher ingest (mTLS + edge attestation + Ed25519)
             └─ public MCP Worker → HMAC proof → `/mcp` (OAuth/JWT)
```

The managed edge is required for the normal two-input path and hides provider
and OAuth configuration behind owner sign-in. The production composition uses
the concrete Cloudflare provider: a dedicated zone receives per-installation
Cloudflare Tunnel/DNS resources, a publisher client certificate, and a
Worker-backed mTLS/attestation route. Cloudflare account authority stays in
the edge process; the desktop receives only installation-scoped leases.
The edge stores installation metadata, endpoint/issuer references, revocation
state, and scoped credential references, but never note text, snapshots,
search queries, or indexes. Self-hosted mode runs the same edge service under
operator control; its production gate still requires Cloudflare and the
owner-browser OIDC settings listed below. Other provider adapters and a
multi-process edge store are not production guarantees. Both modes share the
same server and publisher contracts.

Production edge composition is fail-closed unless these names are present:
`EDGE_STATE_FILE`, `EDGE_CREDENTIAL_VAULT_FILE`,
`EDGE_CREDENTIAL_MASTER_KEY_FILE`, `EDGE_CLOUDFLARE_API_TOKEN_FILE`,
`EDGE_CLOUDFLARE_ACCOUNT_ID`, `EDGE_CLOUDFLARE_ZONE_ID`,
`EDGE_CLOUDFLARE_ZONE_NAME`, `EDGE_OWNER_ISSUER`, `EDGE_OWNER_AUDIENCE`,
`EDGE_OWNER_JWKS`, `EDGE_OWNER_AUTHORIZATION_URL`, `EDGE_OWNER_CLIENT_ID`,
and `EDGE_OWNER_TOKEN_ENDPOINT` (with optional `EDGE_OWNER_SCOPE`). The edge
loads or creates one stable Ed25519 OAuth signer in the encrypted credential
vault; it does not generate a new signer on each restart.

The edge is a routing and authorization boundary, not a replacement for the
server's checks. Public MCP access and publisher ingest use separate
hostnames, credentials, rate limits, and revocation paths. The MCP hostname's
Cloudflare Worker strips caller-supplied proof headers, performs uncached
online introspection against edge authorization state, and returns `503`
without forwarding when that decision is unavailable. On success it signs the
exact request and bearer-token digest with the distinct MCP-edge HMAC secret;
the VPS verifies that proof before its normal OAuth/JWT checks. The publisher
Worker uses a separate mTLS/attestation secret.

## Desktop components

`apps/desktop` is the Electron shell. Its main process owns filesystem access,
the native folder picker, OpenSSH invocation, safe storage, and lifecycle. The
renderer loads from `vaultbridge://app`; it has sandboxing,
`contextIsolation`, disabled Node integration, no web navigation, and a fixed
IPC channel list. Renderer state intentionally excludes credentials, absolute
paths, raw command output, and note contents.

The setup orchestrator in `packages/orchestrator` persists metadata only. Secret
material is exchanged through injected adapters and platform stores, never in a
persisted setup record. Electron restores this record on launch and retries the
last verified phase; once the record is ready, the main process schedules
background sync without reopening SSH. Its resumable phases are:

```text
idle → preflight → staged → deployed → device-bound →
first-snapshot → endpoint-verified → ready
```

Failures become `needs-attention` with a resumable phase. Each transition is
idempotent and journal entries are bounded/redacted. The top-level UI states
are **Ready**, **Synchronizing**, and **Needs attention**; setup phase labels
are progress text, not a terminal workflow exposed to the owner.

Non-secret desktop configuration follows a fixed precedence: `VAULT_BRIDGE_*`
environment variables, then `product-config.json` in Electron `userData`, then
`product-config.json` in `process.resourcesPath`. Forge embeds a public file
only when `VAULT_BRIDGE_PRODUCT_CONFIG_PATH` names `product-config.json`.
Without real managed-edge/OIDC/image-digest inputs the release candidate is
intentionally unconfigured; a configured packaged smoke is required before a
clean-install one-launch claim.

Selecting **Set up** authorizes the orchestrator to:

1. resolve the selected vault and build a bounded preview;
2. verify the SSH host key and server connection;
3. check Linux, architecture, Docker/Compose mode, CPU, memory, disk,
   filesystem quota, and outbound HTTPS;
4. allocate opaque installation/vault identifiers and the local device signing
   identity;
5. generate the Mac publisher mTLS private key and PKCS#10 CSR in safe storage;
6. obtain edge installation metadata and secret references (the CSR, never the
   private key, is sent to Cloudflare through the edge);
7. render and atomically stage a digest-pinned Compose project with two
   long-running containers and two network-disabled one-shot secret-init jobs;
8. run the exact project's bounded Compose lifecycle;
9. bind the publisher device and upload the first complete snapshot;
10. verify `/readyz`, OAuth discovery, and MCP endpoint reachability; and
11. persist the ready receipt for restart and automatic synchronization.

The owner does not copy a pairing code, token, key, Compose file, or tunnel
credential. The old pairing operation remains an internal compatibility
adapter and legacy harness tool only; it is not a new owner-facing step. If a
desktop crash occurs after the server consumes a code but before local state
commits, retrying with a fresh one-use code and the same installation/vault/
public key returns the existing device idempotently; a different or revoked
identity is rejected.

Edge credential leases are references until the desktop redeems them. The
lease material is sealed with the implemented
`X25519-HKDF-SHA256-AES-256-GCM` envelope, bound to installation, lease, and
credential kind. The desktop materializer writes plaintext only to a private
`0600` staging file long enough to upload a declared remote secret (or keeps it
ephemeral for a Keychain write), then removes the staging file; plaintext is
not persisted in orchestrator state or renderer state. On the VPS, SSH/SFTP-uploaded
file-source secrets are `0600`; isolated network-disabled init jobs copy them
into per-runtime named volumes, set the exact runtime UID/GID and configured
copy mode (default `0440`), and the long-running service mounts only its own
volume read-only.

## Vault reader and one-way publisher

`packages/vault-core` and `packages/agent-core` resolve the user-selected root,
skip hidden/system directories and symlinks by default, include bounded UTF-8
`.md`, `.canvas`, and `.base` text, and enforce file/count/byte limits. A scan
produces a complete immutable snapshot with opaque document IDs and source
hashes. The Mac never sends iCloud credentials or mounts the live vault on the
VPS. For an iCloud-backed root, a successful scan proves only the bytes visible
on that Mac at scan time.

The publisher sends complete generations over outbound HTTPS. Each request
contains a device id, vault id, timestamp, nonce, digest, and Ed25519
signature. A trusted edge terminates publisher mTLS and adds an
installation-scoped attestation; the server verifies both before parsing the
body. Replay, clock-skew, device-revocation, body, and storage checks happen
before activation. The publisher cannot call MCP tools.

## Remote data plane

`apps/server` stores a replaceable active generation plus a bounded rollback
generation in SQLite. It validates schema, duplicate IDs, text/source hashes,
snapshot digest, quotas, and installation binding, builds FTS5 indexes, and
advances the active pointer atomically. A partial or invalid upload never
becomes searchable. The server never reads a host path outside its data
volume, receives no local-vault mount, and has no control channel to the Mac.

The public MCP service is stateless at the HTTP layer and registers only:

- `search({ query })` — bounded full-text search returning opaque IDs/titles;
- `fetch({ id })` — one allowlisted document by opaque ID and bounded text.

Both advertise read-only/non-destructive annotations. Sync status remains a
local UI and signed publisher status response, not an MCP tool. MCP input and
note text are untrusted data and must never be treated as policy or commands.

## Authentication planes

### Owner and ChatGPT OAuth

The managed edge authenticates the owner before installation actions. The
desktop's owner sign-in uses a system-browser authorization-code + PKCE flow,
random state/nonce, a short-lived one-use code, and a protected callback; no
bearer token is placed in a URL. The MCP authorization server advertises
authorization-code + PKCE (`S256`), public clients, a resource indicator, and
the single `vault:read` scope. Access tokens bind subject, installation, vault,
client, resource, issuer, audience, and expiry. The server verifies every
request against a provisioned offline JWKS bundle (`JWT_JWKS_FILE` by default).

Readiness is dynamic rather than a boot-only flag. The server rechecks storage
capacity and offline-authentication freshness on each `/readyz` request, while
the MCP Worker rechecks online edge introspection for each request and returns
`503` when edge authorization is unavailable. A liveness response does not
prove that either public route is usable.

OpenAI's client contract is documented in [MCP server guidance](https://developers.openai.com/api/docs/mcp), [MCP server building](https://developers.openai.com/plugins/build/mcp-server), and [authentication guidance](https://developers.openai.com/plugins/build/auth). A custom MCP connection is configured through ChatGPT Web/the account surface when the target account/workspace offers that capability. Mobile support is a client/account compatibility result, not an architecture guarantee; do not infer it from desktop Web setup.

### MCP edge

The public MCP hostname is a Cloudflare Worker route. The Worker performs an
uncached online introspection decision for each bearer token; edge outage,
stale authorization state, or a missing Worker secret returns `503` and never
forwards to the VPS. It strips incoming MCP-proof headers before adding a
fresh HMAC over method, path/query, host, bearer-token digest, timestamp, and
nonce. The server verifies this distinct MCP-edge attestation and then runs
its own issuer/audience/scope/installation/vault/client checks. The relevant
server settings are `MCP_EDGE_ATTESTATION_SECRET_FILE`,
`MCP_EDGE_ATTESTATION_HEADER`, `MCP_EDGE_TIMESTAMP_HEADER`,
`MCP_EDGE_NONCE_HEADER`, and `MAX_MCP_EDGE_ATTESTATION_ENTRIES`.

### Publisher

Publisher mTLS/service identity is edge-terminated and is distinct from MCP
OAuth. The edge signs the method/exact-URL/host/certificate-status tuple with
the installation-scoped attestation secret, timestamp, and nonce. The server expects
`PUBLISHER_MTLS_REQUIRED=true`, `PUBLISHER_EDGE_ATTESTATION_SECRET_FILE`, and
the configured attestation/status/timestamp/nonce headers (defaults are
`x-vmb-edge-attestation`, `x-vmb-edge-mtls-status`, `x-vmb-edge-timestamp`,
and `x-vmb-edge-nonce`, status `verified`). It then validates the device's
Ed25519 request signature and replay state. The
Mac-side mTLS private key is never copied to the VPS; the edge attestation
secret is not interchangeable with it. Cloudflare provisioning is revocable;
its in-place `rotate` operation currently fails closed until a coordinated
desktop/VPS migration exists. OAuth revocation is client-scoped: incrementing
the registered client's monotonic revocation epoch invalidates that client's
authorization codes, refresh tokens, and access tokens while leaving unrelated
clients active.

### SSH

SSH is a control-plane transport for install, update, status, rollback, and
removal. The app uses the system OpenSSH client with fixed argument arrays and
host-key pinning. Renderer input cannot supply a command or Compose document.
Background synchronization never opens an SSH session.

Settings keeps **Disconnect** and **Remove server copy** reachable. Disconnect
revokes remote access, stops the exact project, removes its revoked secret
volumes/staged files, and retains only the replica data volume with an exact
durable cleanup receipt;
the orchestrator invokes edge, publisher, and deployment cleanup independently
and records retryable failures. Remove server copy is a separate destructive
confirmation that deletes and verifies absence of that exact labelled replica
volume. Setup and server changes stay blocked while the receipt remains.

## Shared-host isolation

The deployment package generates one deterministic project name (`vmb-…`) from
the opaque installation id and labels every service, network, volume, and
secret with that id. The generated project contains exactly two long-running
services (`server` and `tunnel`) plus two network-disabled one-shot
secret-init jobs. It uses digest-pinned images, non-root UIDs, read-only root
filesystems, all capabilities dropped, `no-new-privileges`, bounded
CPU/memory/PIDs/tmpfs, bounded JSON logs, and an installation-local data
volume. `app_internal` is `internal: true`; only the tunnel also joins
`tunnel_egress`.

No host port is published. The stack does not install a reverse proxy, change
firewall/DNS/daemon settings, mount the Docker socket, bind the host vault, use
`container_name`, or run `--remove-orphans`/wildcard cleanup. Compose files and
source secret files are written atomically below the private installation
directory. File-source secrets are uploaded over SSH/SFTP with mode `0600`;
one-shot init jobs copy them to per-runtime named volumes, where configured runtime file mode
and UID/GID apply, and long-running services mount those volumes read-only.
Application-level quotas (`MAX_*`, `MIN_FREE_BYTES`, retained generations) are
required even when the host can add a filesystem quota; they are containment,
not a universal hard tenant-disk guarantee. Edge and server rate guards are
bounded per process; the design does not promise a global distributed rate
limit. The file-backed edge state and encrypted credential vault require one
writer/process per state file. Cloudflare hostname-association mutations are
serialized in that process, and each provider mutation is checkpointed in a
durable cleanup journal. A retry reconciles the journal before allocating new
resources; delete-404 is idempotent, while any other cleanup failure remains
visible and prevents a false “revoked” state. This does not coordinate a
second edge process or an out-of-band Cloudflare administrator.

## Legacy harness boundary

`apps/agent` and the local server pairing CLI predate the Electron flow. They
remain useful for synthetic protocol/e2e tests and expose loopback dashboard,
development bearer, and one-use pairing controls. They are not normal product
surfaces, must be labeled legacy in tooling, and must never be enabled by
production config. Changes to the harness do not authorize widening the V1
desktop/server contract.

## Evolution seams

- vault reader and export policy can add reviewed text formats without changing
  the remote contract;
- the snapshot repository can replace SQLite/FTS5 without changing MCP tools;
- the publisher transport can change relay/tunnel providers without opening an
  inbound desktop port;
- any future write or command feature needs a new authorization/audit design,
  not a widened `fetch` or an implicit control channel.
