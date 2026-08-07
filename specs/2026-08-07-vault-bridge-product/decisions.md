# Implementation decisions

- Keep `docs/product-spec.md` authoritative; do not fork product requirements here.
- Preserve outbound HTTPS/mTLS publisher and `search`/`fetch` MCP contracts.
- Use Electron for the macOS-first packaged web UI because it reuses the existing Node/TypeScript agent.
- Use native/system OpenSSH and SSH Agent; never expose a generic remote shell through renderer IPC.
- Normal remote deployment has an application-only internal network and a tunnel-only egress network, with no host ports.
- The production managed edge is the concrete Cloudflare provider in a
  dedicated zone. Deterministic provider fakes remain development/test only;
  source implementation is not a Cloudflare account or DNS runtime receipt.
- Owner administration uses browser OIDC with PKCE. Production edge state and
  encrypted credentials are file-backed, and one stable OAuth signing key is
  persisted in that vault. Each state file has one writer/process; no
  multi-process repository or global distributed rate limiter is promised.
- The Mac generates the publisher mTLS private key and PKCS#10 CSR. Only the
  CSR crosses to the edge; the private key remains in desktop safe storage.
- Managed MCP uses a separate Cloudflare Worker route that strips caller proof
  headers, performs uncached online introspection, fails closed with `503` on
  edge outage, and emits an MCP-edge HMAC distinct from publisher mTLS/
  attestation. The VPS verifies that proof before OAuth/JWT.
- OAuth revocation is a client-scoped monotonic epoch; incrementing one
  client's epoch invalidates that client's codes, refresh tokens, and access
  tokens without deleting unrelated client registrations.
- Pairing crash recovery is idempotent only for the same installation, vault,
  and public key; mismatched or revoked identities fail closed.
- Deployment source secret files transferred over SSH/SFTP are `0600` for the
  deployment user. Two network-disabled one-shot init jobs copy them into
  per-runtime named volumes
  with exact runtime UID/GID and default `0440` mode; long-running services
  mount only their own volume read-only.
- Desktop non-secret config resolves `env → userData/product-config.json →
  packaged resources/product-config.json`. Forge embeds only a public file
  named `product-config.json`; without real managed-edge/OIDC/image-digest
  inputs the RC remains unconfigured and a packaged smoke is still required.
- Cloudflare installation `rotate` fails closed until a coordinated
  desktop/VPS migration exists. Revoke and reprovision are the supported
  recovery boundary.
- No code signing, notarization, production deployment, commit, or push is implied by a successful local package build.
- Release workflows pin every external Action to a reviewed full commit SHA and
  pin privileged helper images by digest. Read-only matrix jobs build immutable
  OCI archives, scan both supported platforms, and publish those candidates only
  as workflow artifacts. A separate non-matrix job receives `packages: write`
  only after both scans pass, verifies the artifact and manifest digests, and
  copies the exact archives to GHCR with digest preservation.
- Lifecycle removal is explicit and evidence-bound: disconnect records a durable
  cleanup-only `ReplicaCleanupReceipt`, while **Remove server copy** is a
  distinct destructive action. A retained replica blocks new setup or server
  changes; credential volumes and staging files are always deleted. Probes use
  exact installation label/path ownership and fail closed on ambiguity. V1 makes
  no reconnect or replica-reuse promise.
