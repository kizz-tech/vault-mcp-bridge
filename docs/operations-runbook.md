# Operations runbook

> This runbook covers the advanced public HTTPS/OAuth deployment. The default
> personal product uses OpenAI Secure MCP Tunnel; see
> [`deploy/secure-tunnel/README.md`](../deploy/secure-tunnel/README.md).

This runbook covers an operator-owned Linux host and one Vault Bridge
installation. The desktop orchestrator normally performs these actions through
SSH. If an operator must intervene, use only the exact installation project
and the generated Compose file. Never operate on unrelated projects.

## Identify the installation

The app records an opaque installation id and derives a project name such as
`vmb-a1b2c3d4e5f6`. Confirm both the project name and the installation label
before any command. Resolve the generated `compose.yaml` below the private
installation directory; do not use a copied example file.

The project must contain exactly two long-running services (`server` and
`tunnel`) plus the network-disabled one-shot `server_secrets_init` and
`tunnel_secrets_init` jobs; `app_internal` and `tunnel_egress`; the labelled
`replica_data`, `server_secrets`, and `tunnel_secrets` volumes; and
installation-local source secret files. It must publish no host ports and
mount no host path, vault, or Docker socket. The init jobs must complete before
their corresponding long-running service starts.

The production edge separately uses `EDGE_STATE_FILE`,
`EDGE_CREDENTIAL_VAULT_FILE`, and `EDGE_CREDENTIAL_MASTER_KEY_FILE`. Run one
edge process per state file; the file-backed adapters are not a multi-process
store. Rate guards are per process rather than a global distributed limiter.

## Allowed lifecycle

The deployment package allows only these bounded operations, always with the
exact project and file:

```text
docker compose --project-name <project> --file <installation>/compose.yaml --ansi never config --quiet
docker compose --project-name <project> --file <installation>/compose.yaml --ansi never pull --quiet
docker compose --project-name <project> --file <installation>/compose.yaml --ansi never up --detach --no-build
docker compose --project-name <project> --file <installation>/compose.yaml --ansi never stop --timeout 30
docker compose --project-name <project> --file <installation>/compose.yaml --ansi never ps --format json
docker compose --project-name <project> --file <installation>/compose.yaml --ansi never logs --no-color --tail 200 server
docker compose --project-name <project> --file <installation>/compose.yaml --ansi never logs --no-color --tail 200 tunnel
docker compose --project-name <project> --file <installation>/compose.yaml --ansi never down --timeout 30
docker compose --project-name <project> --file <installation>/compose.yaml --ansi never down --timeout 30 --volumes  # explicit replica removal only
```

The app invokes `docker` without a shell and bounds output/timeouts. Do not add
`--remove-orphans`, `docker system prune`, wildcard volume/network deletion,
host-wide `ps`, daemon reconfiguration, or unrelated service commands.

## Health and readiness

1. Check `docker compose … ps --format json` and confirm both long-running
   services are healthy/restarting only within their bounded policy and both
   secret-init jobs exited successfully.
2. Check `/readyz` through the tunnel/private route. The response is dynamic:
   `200 {"ok":true}` means the server currently has a usable store, required
   secret/configuration, and fresh offline authentication material; `503`
   means readiness is unavailable. It does not prove a public edge route or
   ChatGPT account.
3. Check the publisher `GET /v1/status` with the desktop's device-signed
   request. Confirm the expected vault id, active generation, document count,
   and digest without copying note contents.
4. Check Cloudflare tunnel/Worker status and separate MCP/publisher host
   routes. The managed MCP Worker performs uncached online edge introspection
   for each request and returns `503` when that decision is unavailable; this
   is distinct from the server's local `/readyz`. The provider is the concrete
   Cloudflare implementation; do not infer an account or route is live from
   source/config alone.
5. In the desktop app, confirm the last local scan/publication timestamp. It is
   not a claim about an iPhone/iCloud edit that has not reached this Mac.

Never expose `/healthz`, `/readyz`, or publisher status on a new host port just
to make a check easier; use the existing private route or SSH tunnel.

## Synchronization and failed ingest

The publisher is one-way: Mac scan → complete signed generation → private
ingest → validate/stage/index → atomic active pointer. A failed, partial,
replayed, over-limit, or out-of-order generation remains replaceable and never
becomes current.

When sync is blocked:

1. Pause sync in the desktop UI; do not disable signature/JWT/mTLS checks.
2. Record only the redacted request id/error class, current generation and
   image digest.
3. Check clock skew, device revocation, edge attestation, offline JWKS expiry,
   body/storage limits, free-space floor, and active/rollback generations.
4. Retry from the desktop after the cause is corrected; use a new snapshot id
   for a rejected generation.

## Update and rollback

1. Pause publication in the desktop app.
2. Verify the signed release manifest and immutable image digest; record the
   prior digest and active generation.
3. Run preflight/capacity checks and `config --quiet` for the generated file.
4. Run the exact project's `pull --quiet`, then `up --detach --no-build`.
5. Confirm `/readyz` (including a deliberately stale/missing offline-auth
   negative case where the environment permits), tunnel routes, OAuth
   discovery, and a synthetic
   read-only `search`/`fetch` contract call.
6. If any check fails, stop the candidate and restore the prior digest/config
   within the same project. Do not change the host daemon or unrelated stacks.
7. Resume publication only after the endpoint and publisher receipt are
   healthy.

Rollback restores the service image/configuration and, when needed, activates
the last known-good retained generation through the guarded server path. It
does not restore or delete the canonical local vault. Keep a corrupt generation
outside the active data directory only long enough for controlled forensic
work, then purge according to policy.

## Removal

The desktop Settings surface keeps two explicit operations reachable:

- **Disconnect:** revoke the installation's edge/publisher/OAuth material and
  stop the exact project, delete its revoked secret volumes and staged secret
  files, and retain only the remote replica plus an exact cleanup receipt;
- **Remove server copy:** a separate destructive operation that asks for
  confirmation before deleting the labelled replica.

The equivalent operator actions are:

- **Remove service, keep replica:** exact-project `down --timeout 30`, followed
  by exact removal of the two credential volumes and the installation staging
  directory; retain only the recorded replica volume;
- **Remove service and replica:** after separate native confirmation, remove
  the exact recorded replica volume and verify that no installation-labelled
  container, network, or unexpected volume remains.

The retained copy is cleanup-only in V1: it is not silently adopted or reused.
The app blocks a replacement setup until the owner removes it. Any failure
keeps the receipt retryable; a legacy disconnected record without trustworthy
scope is reported as unknown rather than granting fabricated delete authority.

Revoke the tunnel, OAuth installation/client/tokens, publisher device/mTLS,
and the distinct MCP/publisher edge attestations independently. Verify the
local vault remains untouched. Cloudflare cleanup is serialized per
installation and journaled after each external mutation; a failed cleanup is
visible and retryable, and delete-404 is treated as already clean. Do not
claim cleanup completed while a journal entry remains unresolved.
The Cloudflare provider's installation `rotate` operation is fail-closed; do
not call it as a one-click recovery. A new certificate/tunnel requires a
coordinated revoke and reprovisioning procedure.
Do not remove an unrelated labelled resource or use host-wide pruning.

## Incident handling

### Unexpected public exposure

Disable the MCP and/or publisher tunnel route, then set the matching server
kill switch (`MCP_READS_DISABLED` and/or `PUBLISHER_INGEST_DISABLED`) through
the controlled deployment path. Confirm no host ports, host binds, Docker
socket, or overlapping surface hosts exist. Revoke edge/tunnel credentials and
preserve only redacted metadata.

### OAuth/JWKS or owner compromise

Disable MCP reads, revoke OAuth clients/access/refresh tokens and the
installation, and take the edge offline while replacing compromised owner
credentials or the stable OAuth signer through the operator's secret-vault
recovery procedure. Provision a fresh offline JWKS bundle and verify
issuer/audience/resource/scope/client/installation/vault checks before
re-enabling. There is no supported in-place Cloudflare signer/tunnel rotation;
reprovision the installation when new material is required. Never replace a
missing JWKS with a development bearer token.

### Publisher replay or key compromise

Pause ingest, revoke the device, publisher mTLS credential, tunnel, and edge
attestation, then coordinate a fresh installation if new material is required.
Cloudflare `rotate` currently fails closed, so do not promise an in-place
secret swap. Verify nonce retention/clock skew and publish a new signed
generation only after edge and server checks pass. A valid MCP OAuth token
cannot substitute for publisher credentials.

### Disk or resource pressure

Pause publication. Inspect bounded active/rollback generations, SQLite/index
bytes, temporary bytes, free-space reserve, tmpfs, and rotated logs. Remove
only replaceable staging/log data through the installation's documented path;
never delete the active generation or run `docker system prune` on a shared
host. Add a filesystem/project quota or move to a dedicated host when
application limits are insufficient.

### Managed edge unavailable

Existing tunnel and publisher routes may continue, depending on provider
behavior. The MCP hostname intentionally fails closed with `503` when online
edge introspection is unavailable. Do not invent a fallback direct host port or
bypass publisher/MCP auth. Wait for control-plane recovery or move deliberately
to the self-hosted Advanced mode, with new owner/OAuth/provider credentials and
a fresh evaluation receipt.

## Evidence to retain

For each operation retain a short redacted receipt containing commit/release,
image digests, exact project id, command timestamps, `/readyz` and endpoint
verification results, generation/rollback ids, and evaluation level. Never
retain note text, raw queries, absolute vault paths, bearer tokens, pair codes,
private keys, certificate material, tunnel tokens, or raw logs.
