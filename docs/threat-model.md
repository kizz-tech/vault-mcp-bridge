# Threat model

This model covers the one-launch Vault Bridge product: an Electron desktop
app, a managed or self-hosted edge, and one installation-scoped Compose project
with two long-running containers plus two network-disabled one-shot
secret-init jobs. It does not treat a local unit test, a healthy container, or
a single ChatGPT tool call as proof of a production control. See
[`docs/evaluation-matrix.md`](evaluation-matrix.md) for evidence levels.

## Assets and authority

| Asset | Canonical authority | Derived copies / surfaces |
| --- | --- | --- |
| Vault files and local metadata | Owner's selected Mac folder | Electron preview, signed snapshots, remote generations/index |
| Owner identity and installation binding | Managed/self-hosted edge identity plane | Desktop session, OAuth client/token records |
| Publisher private key and mTLS material | OS Keychain/SSH Agent + edge credential store | Device public key, installation-scoped secret references |
| OAuth signing/verification material | Edge key store and server offline JWKS bundle | Access tokens, public JWKS |
| Tunnel credential and edge attestation | Edge/provider secret store | `0600` SSH/SFTP file-source secrets copied by network-disabled init jobs into read-only per-runtime named volumes |
| Availability and revocation state | Edge + server control records | Desktop status, `/readyz`, signed publisher status |

The local vault is the only source of truth for content. Remote snapshots,
SQLite/FTS5 indexes, journals, caches, tokens, and status are replaceable and
must never be synchronized back into the vault.

## Trust boundaries

1. **Renderer ↔ Electron main.** Renderer content is untrusted; it receives
   only redacted state through allowlisted, sender-checked IPC.
2. **Desktop ↔ local filesystem/SSH.** The main process reads only the selected
   root, invokes system OpenSSH with fixed argument arrays, and keeps private
   keys in Keychain/Agent. SSH is control-plane only.
3. **Desktop ↔ edge.** Owner-browser OIDC sign-in and credential leases are
   authenticated; publisher traffic is outbound and installation scoped. The
   Mac-generated publisher CSR crosses this boundary, never its private key.
   The edge may see routing metadata, but not note contents beyond the
   publisher payload that it forwards/terminates.
4. **Tunnel ↔ server.** The tunnel is the only egressing container. The server
   is on an `internal: true` network, has no host port, and cannot connect back
   to the Mac. Two network-disabled init jobs copy `0600` source secrets into
   separate named volumes; long-running services mount only their own copy
   read-only.
5. **ChatGPT/MCP ↔ public edge.** The Cloudflare Worker strips incoming proof
   headers, performs uncached online introspection, fails closed with `503` on
   edge outage, and adds a distinct MCP-edge HMAC bound to the request and
   bearer-token digest. The server verifies that HMAC, then verifies the token
   and installation/vault/client claims on every request. There is no global
   distributed rate-limit guarantee.
6. **Publisher edge ↔ server ingest.** mTLS/service identity and a keyed edge
   attestation precede device Ed25519 signatures, replay checks, and snapshot
   validation. This is a separate credential plane from MCP OAuth and MCP-edge
   HMAC.
7. **VPS host ↔ installation.** The host operator and Docker daemon remain a
   trust boundary. Resource limits and project labels reduce accidental
   interference; they do not make a shared rootful daemon a hostile-tenant
   sandbox.

## Actors

- **Owner** chooses the vault and SSH target and controls account/revocation.
- **ChatGPT/MCP client** is an authorized caller of read-only tools but its
  prompts and tool inputs are untrusted data.
- **Edge/provider operator** can route public traffic and observe provider
  metadata. The managed-edge choice is an explicit product trust boundary.
- **VPS/Docker operator** can inspect runtime plaintext and host resources.
- **Compromised network/client** can replay, forge, probe, or flood endpoints
  but lacks valid scoped keys under the stated assumptions.
- **Malicious note author** can place prompt-like instructions, links, or
  unexpected bytes in the vault. Note content is never policy.

## Security objectives

1. Never mutate the canonical vault from the remote side.
2. Never allow a server process to initiate a desktop read or command.
3. Expose only the selected, bounded, read-only projection.
4. Isolate one installation from unrelated Compose projects as far as the
   chosen Docker host permits.
5. Bind every publisher and MCP request to the intended installation, vault,
   principal/client, scope, and current authentication policy.
6. Make partial generations, replayed requests, missing credentials, and
   unsafe host changes fail closed.
7. Keep diagnostics useful without leaking note text, queries, paths, or
   credential material.

## Threats and controls

| Threat | Control | Residual / evidence boundary |
| --- | --- | --- |
| Renderer XSS or malicious vault text reaches Node APIs | Electron sandbox, context isolation, no Node integration, CSP, no navigation/webviews, sender-checked IPC; note text rendered as text | Electron packaging and adversarial renderer tests still required |
| Path traversal, symlink swap, hidden system export | Root resolution, allowlisted extensions, no-follow/stable reads, hidden/system exclusions, opaque IDs, no path field in snapshot | Real-vault interruption/adversarial scan evidence required |
| Remote write or command injection | Read-only MCP tools; no write/shell/raw SQL/arbitrary path; fixed SSH/Compose allowlist; server-initiated channel forbidden | New features require separate contract review |
| Snapshot tamper or partial visibility | Ed25519 device signature, digest/source hashes, schema/size/quota checks, staging and atomic active-pointer transaction | Key custody, recovery, and large-vault tests required |
| Publisher credential used as MCP auth (or vice versa) | Distinct edge mTLS/attestation, device signature, OAuth/JWT, host separation, scopes and claim bindings | Edge policy and revocation drill required |
| Direct bypass of edge mTLS | Server verifies keyed publisher attestation over method/path/host/cert-status; status header alone is rejected | Trusted Cloudflare edge deployment and revoke/reprovision evidence required; in-place provider rotation currently fails closed |
| MCP direct-origin bypass or stale edge decision | Server verifies a distinct MCP-edge HMAC over method/path/host/bearer digest/timestamp/nonce; Worker introspection is uncached and returns `503` on edge outage | Worker route, online introspection, direct-origin denial, and outage evidence required |
| OAuth token replay or confused deputy | PKCE S256, exact redirect/resource binding, short-lived access tokens, refresh rotation, client-scoped monotonic revocation epoch, issuer/audience/scope/subject/client/installation/vault checks, offline JWKS | Provider/client behavior and epoch invalidation must be tested at target account |
| JWKS/identity outage enables fail-open auth | Production requires offline JWKS; remote JWKS is explicit opt-in; missing issuer/audience/JWKS fails startup or request | Key rotation/expiry runbook required |
| Pairing code leakage/crash retry | Pairing is legacy/internal; one-use bounded TTL; same identity may retry with a fresh code idempotently after a crash; mismatched/revoked identity fails | Legacy CLI must remain inaccessible to normal UI; retry evidence required |
| Replay/duplicate publisher request | Timestamp skew, per-device nonce retention, canonical signed fields, idempotent snapshot receipts | Clock discipline and nonce-store persistence required |
| Noisy neighbor or disk exhaustion | Non-root/read-only containers, dropped caps, no-new-privileges, CPU/memory/PID/tmpfs/log limits, app storage quotas, free-space floor, two-generation cap | Portable named volumes are not hard disk quotas; dedicated VM for hostile tenants |
| Container escape/host takeover | No privileged mode, host network/binds, Docker socket, or host ports; digest-pinned images; project labels | Host kernel/daemon and operator remain trusted |
| Cross-project cleanup or accidental deletion | Deterministic project, exact Compose allowlist, no `--remove-orphans`, removal requires explicit `keep/remove replica` decision, Cloudflare cleanup journal and serialized mutations | Operator mistakes outside app allowlist or another edge process remain possible |
| Tunnel/provider compromise | Installation-scoped token, read-only secret mount, revocable routes, separate MCP/ingest hostnames, dedicated Cloudflare zone | Provider sees traffic metadata and can disrupt/route traffic; Cloudflare in-place rotation is not currently supported |
| Prompt injection in notes | Note text and MCP results are untrusted data; tool descriptions say not to follow embedded instructions; no execution tools | Client/model behavior is not a security boundary |
| Sensitive logs/diagnostics | Bounded redacted journal, no raw command output/headers/queries/tokens/paths/note text; diagnostics are owner-exported | Verify with redaction tests and access review |
| iCloud freshness misrepresentation | Ready timestamp is last local scan/publication; UI does not claim phone-side sync completeness | Cross-device freshness remains external/iCloud behavior |
| Mobile availability overclaim | Document Web/account connection as capability-dependent; evaluate target client separately | No product-wide native-mobile guarantee |

## Credential gates

The server's production gate requires `JWT_ISSUER`, `JWT_AUDIENCE`,
`MCP_RESOURCE_URL`, `PUBLISHER_PUBLIC_URL`, `MCP_VAULT_ID`,
`MCP_INSTALLATION_ID`, non-empty `ALLOWED_HOSTS`, `MCP_HOSTS`, and
`PUBLISHER_HOSTS`, an offline `JWT_JWKS_FILE`/`JWT_JWKS_JSON` bundle whose
issuer/audience/lifetime match configuration (or explicit raw/remote JWKS
opt-ins), `PUBLISHER_MTLS_REQUIRED=true`, and
`PUBLISHER_EDGE_ATTESTATION_SECRET_FILE`, attestation/status/timestamp/nonce
headers, and bounded `MAX_PUBLISHER_EDGE_ATTESTATION_ENTRIES`. MCP and
publisher hosts must not overlap and resource URLs must be HTTPS with exact
`/mcp`/`/` paths.

The managed MCP Worker additionally requires the distinct
`MCP_EDGE_ATTESTATION_SECRET_FILE`, `MCP_EDGE_ATTESTATION_HEADER`,
`MCP_EDGE_TIMESTAMP_HEADER`, `MCP_EDGE_NONCE_HEADER`, and bounded
`MAX_MCP_EDGE_ATTESTATION_ENTRIES`. The Worker performs uncached online edge
introspection and returns `503` rather than forwarding when that decision is
unavailable; the VPS verifies the HMAC before OAuth/JWT checks.

The edge production gate requires HTTPS `EDGE_ORIGIN` and `EDGE_ISSUER`, owner
browser OIDC `EDGE_OWNER_ISSUER`, `EDGE_OWNER_AUDIENCE`, `EDGE_OWNER_JWKS`,
`EDGE_OWNER_AUTHORIZATION_URL`, `EDGE_OWNER_CLIENT_ID`, and
`EDGE_OWNER_TOKEN_ENDPOINT` (optional `EDGE_OWNER_SCOPE`), plus
`EDGE_PROVIDER=cloudflare`,
`EDGE_STATE_FILE`, `EDGE_CREDENTIAL_VAULT_FILE`,
`EDGE_CREDENTIAL_MASTER_KEY_FILE`, `EDGE_CLOUDFLARE_API_TOKEN_FILE`,
`EDGE_CLOUDFLARE_ACCOUNT_ID`, `EDGE_CLOUDFLARE_ZONE_ID`, and
`EDGE_CLOUDFLARE_ZONE_NAME`. The state/vault adapters are durable across
restarts but single-writer and single-process; the OAuth signer is stable in
the encrypted vault. `EDGE_DEV_OWNER_TOKEN`, auto-approval, deterministic
providers, and HTTP origins are development-only.

The generated Compose project also requires digest-pinned server/tunnel images,
an offline OAuth verification secret, a tunnel secret, and distinct
publisher-edge and MCP-edge attestation secrets. SSH uploads source files as
SSH/SFTP source files are deployment-user `0600`; two network-disabled one-shot init jobs copy them into
per-runtime named volumes with exact UID/GID and configured runtime mode
(default `0440`), and long-running services mount only their own volume
read-only. The Mac's publisher mTLS private key is never copied to the VPS.

The desktop's non-secret product configuration uses
`VAULT_BRIDGE_EDGE_ORIGIN`, `VAULT_BRIDGE_OWNER_ISSUER`,
`VAULT_BRIDGE_OWNER_AUTHORIZATION_ENDPOINT`,
`VAULT_BRIDGE_OWNER_TOKEN_ENDPOINT`, `VAULT_BRIDGE_OWNER_JWKS_URI`,
`VAULT_BRIDGE_OWNER_AUDIENCE`, `VAULT_BRIDGE_OWNER_CLIENT_ID`, optional
`VAULT_BRIDGE_OWNER_SCOPE`, digest-pinned
`VAULT_BRIDGE_SERVER_IMAGE_REPOSITORY`/`VAULT_BRIDGE_SERVER_IMAGE_DIGEST` and
`VAULT_BRIDGE_TUNNEL_IMAGE_REPOSITORY`/`VAULT_BRIDGE_TUNNEL_IMAGE_DIGEST`, and
optional `VAULT_BRIDGE_RUNTIME_MODE`, `VAULT_BRIDGE_INSTALLATION_DIRECTORY`,
and `VAULT_BRIDGE_SYNC_INTERVAL_MINUTES`.
Validate these as HTTPS URLs and `sha256:` image digests; they are not a place
to put access tokens or private keys. Edge/server request and storage guards
are bounded per process; no global distributed rate-limit claim is made.
The desktop precedence is environment, then `userData/product-config.json`,
then packaged `process.resourcesPath/product-config.json`; Forge embeds only a
public file explicitly named `product-config.json`. A configured packaged
smoke is required before claiming clean-install one-launch behavior.

## Assumptions and non-goals

- The owner can protect the Mac login, OS Keychain, SSH Agent, and selected
  vault. A compromised Mac can read the vault before Vault Bridge does.
- The edge identity/tunnel provider, VPS kernel/daemon, and release supply
  chain are operated according to their own security policies. Vault Bridge
  cannot make a rootful shared Docker host a hostile multi-tenant boundary.
- Availability, backup confidentiality, account recovery, provider routing,
  iCloud propagation, and ChatGPT/mobile client behavior are not proven by a
  green local test.
- V1 intentionally omits vault writes, two-way sync, arbitrary attachments,
  OCR, raw directory listings, shell, and remote desktop control.

## Incident controls

Pause and disable MCP reads or publisher ingest independently, disable the
matching edge route, revoke OAuth clients/tokens, publisher devices, tunnel
credentials, mTLS certificates, and attestation secrets independently, then
rebuild the disposable replica from the canonical vault. Retain only redacted
evidence. See [`docs/operations-runbook.md`](operations-runbook.md) for the
ordered procedure and [`docs/production-deployment.md`](production-deployment.md)
for promotion gates.
