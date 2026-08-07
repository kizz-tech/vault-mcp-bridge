# Contributing

Vault Bridge handles private vault text. Read `AGENTS.md`,
[`docs/architecture.md`](docs/architecture.md),
[`docs/protocol.md`](docs/protocol.md), and
[`docs/threat-model.md`](docs/threat-model.md) before changing code or
documentation.

## Product constraints

- Keep the normal experience as one Electron app: owner sign-in, vault folder,
  SSH server, **Set up**, then ChatGPT connection. Do not reintroduce a
  terminal-driven onboarding flow.
- Keep the legacy agent/server/pairing harness explicitly separate. It exists
  for tests and migration; it is not a normal-user API.
- V1 is read-only. Do not add vault writes, deletes, arbitrary path reads,
  shell commands, attachment downloads, or a server-initiated desktop channel
  without a separately approved contract and threat model.
- The local vault remains canonical. Remote snapshots, indexes, status, and
  caches are replaceable derivatives.
- Keep public MCP OAuth, publisher mTLS/edge attestation, owner control-plane
  auth, and SSH control credentials on separate trust surfaces.
- The managed production edge is the concrete Cloudflare provider. Owner
  browser OIDC is configured with the `EDGE_OWNER_*` settings; file-backed
  edge state, the encrypted credential vault, and the stable OAuth signer use
  the exact `EDGE_*_FILE` settings documented below. The edge store is a
  single-writer, single-process adapter, not a multi-process database.
- The Mac generates the installation-scoped publisher mTLS private key and
  PKCS#10 CSR. Only the CSR is sent to the edge; the private key remains in
  desktop safe storage. Cloudflare provisioning returns certificate material
  through a one-use credential lease.
- Preserve the runtime contract: two digest-pinned, non-root long-running
  containers (`server` plus outbound-only `tunnel`) and two network-disabled,
  one-shot secret-init jobs. SSH/SFTP uploads file-source secrets as deployment-user
  `0600` files; init jobs copy them into per-runtime named volumes with exact
  UID/GID and configured runtime mode (default `0440`), and services mount only
  their own volume read-only. Keep the internal application network, no host
  ports, no host mounts, no Docker socket, no privileged mode, and bounded
  resources.
- The managed MCP hostname is a Cloudflare Worker route. It must perform
  uncached online edge introspection and fail closed with `503` on edge
  unavailability, then add the distinct MCP-edge HMAC attestation expected by
  the VPS. Do not reuse publisher mTLS/attestation credentials for MCP.
- OAuth revocation is client-scoped: increment the registered client's
  monotonic revocation epoch to invalidate that client's codes, refresh
  tokens, and access tokens without revoking unrelated clients.

## Safe examples and secrets

Use only `fixtures/vault/` or another synthetic fixture. Do not commit real
vault names, paths, note text, domains, host fingerprints, OAuth values,
pairing codes, tunnel credentials, mTLS material, private keys, or deployment
logs. Environment names may be documented; values belong in an OS Keychain,
secret manager, or untracked local file. Development tokens such as
`MCP_DEV_TOKEN` and `EDGE_DEV_OWNER_TOKEN` must never be accepted when
`NODE_ENV=production`.

## Development commands

From a clean checkout with Node 24+ and pnpm 10:

```sh
pnpm install --frozen-lockfile
pnpm lint
pnpm typecheck
pnpm test
pnpm build
pnpm validate
```

For the product shell use `pnpm dev` or `pnpm dev:desktop`. For focused work,
use the package scripts (`pnpm --filter @vault-mcp-bridge/desktop test`,
`pnpm --filter @vault-mcp-bridge/server test`, or
`pnpm --filter @vault-mcp-bridge/edge test`). The legacy harness is
`pnpm dev:legacy:server`, `pnpm dev:legacy:agent`, and `pnpm dev:edge`; its
loopback and pairing commands are documented in
[`docs/local-development.md`](docs/local-development.md).

Add a focused test for every protocol, auth, filesystem-policy, deployment,
or renderer change. Run `pnpm check` before handoff when the change is broad;
otherwise report the focused command and its result. Do not claim that a local
build proves signing, notarization, image publication, VPS deployment, edge
availability, Cloudflare account state, or ChatGPT/mobile connectivity. The
Cloudflare provider's in-place `rotate` operation intentionally fails closed;
do not document or test it as a supported one-click rotation. Use revoke and
coordinated reprovisioning when that recovery procedure is explicitly owned.

Pairing is retry-safe after a desktop crash: a retry may consume a fresh
one-use code for the same installation/vault/public key and receives the
existing device id idempotently; mismatched or revoked identities must still
fail closed. Do not turn pairing into a user-visible step.

## Pull requests and documentation

Describe the owned files, the security boundary affected, and the exact
validation evidence. Keep normal product instructions separate from legacy
harness instructions. Update the relevant protocol, threat-model, deployment,
and evaluation documents when behavior or a credential gate changes. Link to
official OpenAI MCP/auth guidance rather than asserting undocumented client or
mobile behavior.

Contributions are accepted under the repository's Apache-2.0 license. Report
security findings only through the private process in `SECURITY.md`; never put
sensitive installation evidence in an issue or pull request.
