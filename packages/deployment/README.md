# Deployment package

`@vault-mcp-bridge/deployment` owns the remote data-plane boundary. It does not
accept arbitrary shell commands or image tags. A deployment spec is validated,
rendered into a deterministic per-installation Compose project, and executed
only through the fixed `docker compose` lifecycle allowlist.

The generated project has two long-running services: one read-only, non-root
server on an internal network and one non-root tunnel on the internal plus
egress networks. Two network-disabled, one-shot init jobs copy the SSH user's
`0600` file-source secrets into service-specific named volumes and set the
exact runtime ownership before either long-running service starts. This avoids
relying on Compose's unsupported `uid`/`gid` remapping for local secret files.
No host ports, host binds, build contexts, Docker socket, privileged mode, or
static container names are emitted. The server and tunnel mount only their own
secret volume read-only.

`publisherEdgeAttestationSecret` is deliberately distinct from the Mac-side
publisher mTLS credential. The latter is never represented by this package and
must never be copied to the VPS. OAuth verification uses an offline JWKS bundle
mounted as `JWT_JWKS_FILE`.

Use `evaluatePreflight()` before staging to fail closed on non-Linux, missing
Compose, rootless-mode, capacity, outbound-HTTPS, or project-collision failures.
