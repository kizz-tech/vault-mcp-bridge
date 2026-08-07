# Vault Bridge runtime

The deployment package is the only writer of the installation Compose file.
`generateComposeProject()` emits a project-scoped stack containing a read-only
`server`, an outbound-only `tunnel`, and two network-disabled one-shot secret
init jobs. The generated file is deterministic and must be written atomically
below the installation directory before running Compose.

Runtime invariants:

- image values are immutable `repository@sha256:<digest>` references;
- the server joins only the `app_internal` network;
- the tunnel joins `app_internal` and `tunnel_egress` and is the only egressing service;
- no host port, build context, `container_name`, host bind mount, privileged mode,
  Docker socket, or `--remove-orphans` is allowed;
- the tunnel token, offline OAuth verification bundle, and distinct publisher
  and MCP edge attestation secrets begin as `0600` Docker file-source secrets
  below the private installation directory; SSH/SFTP transfer preserves that
  deployment-user mode; isolated, network-disabled init
  jobs copy and chown them into separate named volumes, applying the configured
  runtime file mode (default `0440`), then the server and tunnel mount only
  their own volume read-only; the Mac publisher mTLS private key is never
  copied to or mounted in the VPS;
- every service, network, and volume carries the installation label;
- CPU, memory, PID, tmpfs, body, vault, database, index, temporary, retained-
  generation, and log budgets are explicit.
- Production server environment uses the exact bounded names `MAX_BODY_BYTES`,
  `MAX_VAULT_BYTES`, `MAX_DATABASE_BYTES`, `MAX_INDEX_BYTES`, `MAX_TEMP_BYTES`,
  `MIN_FREE_BYTES`, and `MAX_RETAINED_GENERATIONS`, plus offline `JWT_JWKS_FILE`,
  `PUBLISHER_EDGE_ATTESTATION_SECRET_FILE`, and distinct
  `MCP_EDGE_ATTESTATION_SECRET_FILE`/`MAX_MCP_EDGE_ATTESTATION_ENTRIES`. The
  managed MCP Worker performs uncached online introspection and returns `503`
  on edge outage before adding its request-bound HMAC. The edge attestation
  secret is distinct from the publisher's Mac-side mTLS credential.

The server image is built by the release pipeline. The VPS receives only the
digest-pinned image reference and generated Compose/YAML files; it never builds
from a checkout. The tunnel image is likewise pinned by digest and receives its
installation-scoped token through `/run/secrets/tunnel_credential`.

The deployment lifecycle exposes a fixed command allowlist (`config`, `pull`,
`up --detach --no-build`, `stop`, `ps`, bounded `logs`, and exact-project
`down`). Removal with `--volumes` is a separate confirmation and is never part
of update or rollback.
