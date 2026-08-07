# Security policy

Vault Bridge is designed for private, read-only vault projections. This
repository contains an implementation slice and deployment contracts; it is
not, by itself, evidence of a production deployment or a signed/notarized
release.

## Reporting a concern

Do not open a public issue with note text, vault paths, hostnames, tokens,
cookies, OAuth codes, private keys, certificates, pairing codes, raw headers,
database files, or deployment logs. Use the repository's **Security** tab and
select **Report a vulnerability**. If GitHub private vulnerability reporting
is unavailable, contact the repository owner through an already-established
private channel. Send only the minimum synthetic, redacted reproduction.

If the concern may involve an active installation, stop sharing its endpoint
and follow the containment steps below before collecting diagnostics.

## Security boundary

- The selected local vault is canonical and is read only by the Electron main
  process/scanner. The renderer has no Node integration and talks through an
  allowlisted IPC bridge.
- The normal setup operation is resumed by the desktop orchestrator from its
  persisted metadata record. Once ready, the Electron main process schedules
  background outbound HTTPS sync while it remains running; the sync path never
  opens SSH and the server never initiates a desktop command.
- The remote projection is read-only and replaceable. The V1 MCP surface is
  `search` and `fetch`; no write, delete, shell, arbitrary path, raw SQL, or
  binary export exists.
- Public MCP OAuth/JWT, publisher mTLS plus edge attestation, owner/edge
  administration, and SSH credentials are separate. A credential from one
  surface must not authorize another.
- The VPS stack is an installation-scoped Compose project with two
  long-running containers (`server` and outbound-only `tunnel`) plus two
  network-disabled, one-shot secret-init jobs. The server has no host port or
  direct egress; the tunnel is the only egressing container. SSH/SFTP uploads
  file-source secrets as deployment-user `0600` files; each init job copies
  them into a per-runtime named volume, sets the exact runtime UID/GID and
  configured copy mode (default `0440`), and the long-running service mounts
  only its own volume read-only. No Docker socket, host bind, privileged mode,
  static container name, or broad cleanup command is allowed.

## Production fail-closed requirements

The server must not start in production unless issuer/audience, installation
and vault bindings, distinct MCP/publisher hosts, HTTPS resource URLs, and
offline token verification are configured. Use an offline `JWT_JWKS_FILE`
whose issuer/audience/lifetime matches configuration (or the explicitly
reviewed keys-only `JWT_ALLOW_RAW_JWKS=true` or remote
`JWT_ALLOW_REMOTE_JWKS=true` + HTTPS `JWT_JWKS_URL` exception).
`MCP_DEV_TOKEN` is development/test-only.

Publisher ingest additionally requires `PUBLISHER_MTLS_REQUIRED=true`, an
installation-scoped `PUBLISHER_EDGE_ATTESTATION_SECRET_FILE`, and the expected
edge certificate-status/attestation headers. That edge attestation secret is
not the Mac publisher mTLS private key. Both are provisioned through a secret
store and never placed in Compose YAML, the vault, a container image, source
control, or shell history.

The managed MCP hostname is a Cloudflare Worker route. It strips incoming
MCP-proof headers, performs uncached online introspection against the edge
authorization state, and returns `503` rather than forwarding when that edge
decision is unavailable. It then signs the exact request and bearer-token
digest with the distinct `MCP_EDGE_ATTESTATION_SECRET_FILE` credential. The
VPS verifies this MCP HMAC before OAuth/JWT validation; it is not the
publisher mTLS/attestation secret.

The managed edge implementation uses HTTPS owner-browser OIDC, the concrete
Cloudflare provider, a file-backed state store, an encrypted credential vault,
a stable OAuth signing key loaded from that vault, and an offline owner JWKS
bundle. Production requires one edge process per state file; this is not a
multi-process durable store. Development owner tokens, auto-approval,
deterministic providers, and HTTP origins are never production controls.

The Mac generates the publisher mTLS private key and PKCS#10 CSR. The CSR is
sent to Cloudflare for certificate issuance; the private key stays in desktop
safe storage and is never copied to the VPS. Cloudflare installation
`rotate` is intentionally fail-closed until a coordinated migration exists;
revoke and reprovision are the supported recovery boundary. OAuth revocation
is client-scoped: incrementing that client's monotonic revocation epoch
invalidates its authorization codes, refresh tokens, and access tokens while
leaving unrelated clients untouched.

## If an installation may be compromised

1. Disable the affected surface (`MCP_READS_DISABLED` for public reads and/or
   `PUBLISHER_INGEST_DISABLED` for publisher ingest) and disable its edge route.
2. Revoke the installation, OAuth clients/tokens, publisher device key, tunnel
   credential, and mTLS/edge attestation material independently.
3. Preserve only bounded, redacted evidence: installation id, generation id,
   request-id/error class, image digest, and timestamps. Do not collect note
   contents, queries, bearer tokens, signatures, or private paths.
4. Revoke affected installation credentials. If new material is required,
   coordinate a fresh installation/reprovisioning (the Cloudflare provider's
   in-place rotate operation fails closed), then rebuild the disposable remote
   replica from the canonical local vault on a clean host.
5. Verify host separation, offline JWKS, MCP/publisher HMAC attestation,
   quotas, client-epoch revoke behavior, and readiness before re-enabling each
   route separately.

The remote replica may be purged according to the owner's retention and
incident policy. Purging it never deletes or modifies the canonical local
vault.

Settings exposes reachable **Disconnect** and **Remove server copy** actions.
Disconnect revokes remote access and stops the exact installation while
retaining only the replica data volume and a cleanup-only receipt; revoked
credential volumes and staged secret files are removed. Removing the server
copy is a separate natively confirmed destructive operation. The receipt is
kept across failures/restarts and cleared only after exact absence is verified;
a replacement setup cannot overwrite it.

## Safe defaults

The desktop dashboard binds to loopback during development, snapshot
activation is atomic, hidden/system directories and symlinks are excluded by
default, request and storage limits are bounded per process, and journals
redact paths and credentials. Readiness is dynamic: server storage/auth
freshness and edge introspection failures fail closed with `503`. There is no
global distributed rate-limit guarantee. These are implementation safeguards,
not a claim that a real VPS, identity provider, Cloudflare account, tunnel, or
ChatGPT account has been hardened. See
[`docs/threat-model.md`](docs/threat-model.md),
[`docs/production-deployment.md`](docs/production-deployment.md), and
[`docs/evaluation-matrix.md`](docs/evaluation-matrix.md) for required evidence.
