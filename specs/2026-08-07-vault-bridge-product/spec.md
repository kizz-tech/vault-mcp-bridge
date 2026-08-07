# Vault Bridge product implementation

The canonical product contract is [`docs/product-spec.md`](../../docs/product-spec.md).
This package exists only to track implementation ownership, evidence, and status.

The source implementation is present in this checkout. This SDD package tracks
what is implemented locally and what still needs external/runtime evidence; it
is not a proposal or a deployment receipt.

## Scope

- Package the local bridge as one macOS-first desktop application.
- Replace the developer dashboard with the approved one-page setup and ready UI.
- Add resumable SSH provisioning and automatic publisher enrollment.
- Deploy an isolated shared-VPS Compose stack with no host ports.
- Keep two long-running services (`server`, `tunnel`) separate from two
  network-disabled one-shot secret-init jobs; source secrets are `0600` and
  copied into exact-identity named volumes with default runtime mode `0440`.
- Implement the Cloudflare-backed managed edge, owner-browser OIDC, durable
  file-backed edge state, stable OAuth signer, and a runnable self-hosted edge
  service.
- Route managed MCP traffic through uncached online Worker introspection with a
  distinct request-bound HMAC and fail-closed `503` outage behavior.
- Preserve the existing HTTPS/mTLS signed-snapshot publisher and `search`/`fetch` MCP contracts.
- Add release, Docker, packaging, repository, and verification surfaces.

## Non-goals

- Vault writes or two-way synchronization.
- Deployment to a real external VPS, DNS/Cloudflare zone, ChatGPT account, or
  production identity provider without user-owned credentials and explicit
  deployment authorization.
- Code signing/notarization without Apple credentials.
- Public release, commit, push, or publication.

## Source lanes

- Product: `docs/product-spec.md`.
- Architecture/security: `docs/architecture.md`, `docs/protocol.md`, `docs/threat-model.md`, `docs/decisions/`.
- Code: `apps/desktop`, `apps/edge`, `apps/server`, `packages/agent-core`,
  `packages/contracts`, `packages/deployment`, `packages/orchestrator`,
  `packages/vault-core`, `deploy`.
- Runtime: local desktop/dev launch, Docker/Compose smoke, synthetic vault integration.
- External: official Electron, Docker, Cloudflare Tunnel, OpenAI MCP/OAuth contracts.

## Completion gates

- Focused tests for each owner layer.
- Repository-wide lint, typecheck, unit/integration tests, and build.
- Desktop renderer and orchestration E2E using synthetic data and fake SSH/edge adapters.
- Packaged desktop artifact smoke on the current platform.
- Docker image and Compose isolation smoke.
- Security and spec-conformance review with no known P0/P1.
- Exact disclosure of credentials/infrastructure still needed for a real production deployment.
- Packaged desktop configuration precedence (`env → userData/product-config.json
  → packaged resources/product-config.json`) and Forge's public-only config
  embedding are documented; a configured packaged smoke remains required for a
  clean-install one-launch claim.
