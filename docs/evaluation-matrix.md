# Evaluation matrix

Use this matrix to keep source, artifacts, runtime, provider, and account
claims separate. Every level needs evidence from that level; do not infer a
higher level from a lower one. Keep receipts short and redacted.

| Level | Scope | Minimum evidence | Does not prove |
| --- | --- | --- | --- |
| L0 | Static repository | `pnpm check`; release-hygiene; strict Compose contract; focused docs/config review | Docker daemon, VPS, edge, ChatGPT |
| L1 | Local product process | Electron renderer/main tests; synthetic vault scan; orchestrator phase/idempotency tests; signed snapshot, atomic activation, `search`/`fetch`; legacy harness tests labeled separately | Isolated containers, public route, real credentials |
| L2 | Container | Digest-pinned server and tunnel images for target platform; SBOM/provenance; vulnerability scan; generated Compose config; disposable smoke of the two long-running services plus both network-disabled secret-init jobs, with no published ports and dynamic readiness | Shared-VPS non-interference, provider auth, account consent |
| L3 | Installation/VPS | SSH host-key pin; preflight; exact project/labels; rootless or reviewed rootful mode; no host ports/binds/socket; `0600` source secrets copied by network-disabled init jobs into exact-UID/GID read-only named volumes; offline JWKS; edge mTLS/attestation; signed publisher first snapshot; dynamic `/readyz`; rollback/removal/revoke drill | ChatGPT account or target-client behavior |
| L4 | Edge/provider/account | Owner-browser OIDC sign-in; Cloudflare provider configuration/receipt for a dedicated zone; MCP Worker uncached online introspection plus distinct HMAC and `503` outage behavior; OAuth discovery + PKCE/resource/scope/claim checks; managed/self-hosted route; ChatGPT Web/account custom MCP consent; synthetic/approved `search` + `fetch`; publisher/OAuth revoke evidence | Long-term reliability, every ChatGPT client, mobile availability, or Cloudflare in-place rotation (currently fail-closed) |
| L5 | Observed operation | Repeated sync, restart, update/rollback, disk/limit, incident/kill-switch and restore evidence over the stated observation window | Future releases/provider guarantees |

## Required receipt fields

For each level retain:

- commit/release version and owner;
- command names, timestamps, and environment class (local, CI, disposable
  container, synthetic VPS, operator VPS, provider/account);
- artifact/package checksum or immutable image digest;
- exact installation/project id and endpoint verification result (redacted);
- pass/fail result, failure boundary, and next action; and
- for L3+, generation/rollback ids and credential-revocation result without
  secret values.

Never include note contents, raw search queries, OAuth access/refresh tokens,
authorization codes, pairing codes, tunnel tokens, mTLS/private keys,
attestation signatures, unredacted host paths, or raw command logs. Synthetic
fixtures are mandatory for L0–L2.

## Gates and product claims

- L0 is the merge/documentation gate.
- L1 is the local release-candidate gate and may include the legacy harness,
  but legacy pairing is never evidence of the normal one-launch product.
- L2 is required before an image is accepted for an installation.
- L3 is required before sharing an endpoint with any account.
- L4 is required before saying **Connect ChatGPT** succeeded for a target
  account/workspace.
- L5 is required before saying the installation is observed or operational for
  a stated period.
- L3/L4 receipts must identify the single edge state file and process owner;
  the current file-backed edge store is not multi-process and no global
  distributed rate-limit guarantee exists.

The following statements require explicit evidence and must not be inferred:

| Statement | Evidence needed |
| --- | --- |
| “Desktop app is installable” | local/package artifact and, separately, signing/notarization evidence if claimed; a one-launch clean-install claim also needs a packaged smoke with configured managed-edge/OIDC/image-digest inputs |
| “Server is deployed” | L3 SSH/Compose receipt and `/readyz`/endpoint checks |
| “MCP is connected” | L4 OAuth/PKCE and account-level tool call |
| “Mobile works” | target account/client observation; never a blanket guarantee |
| “Production-ready” | owner-defined L5 window plus threat-model, revoke, restore, and incident evidence |
