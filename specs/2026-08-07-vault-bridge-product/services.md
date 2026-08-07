# Owner layers

| Layer | Owner paths | Responsibility |
| --- | --- | --- |
| Desktop | `apps/desktop/**` | Electron lifecycle, native dialogs, safe IPC, renderer, packaging. |
| Local agent (legacy/internal adapter) | `apps/agent/**`, `packages/agent-core/**` | Vault scanning, snapshot construction, publisher scheduling; invoked behind the Electron backend in the normal path and retained as a legacy harness. |
| Orchestration | `packages/orchestrator/**` | Persisted setup state machine and adapter contracts. |
| Deployment | `packages/deployment/**`, `deploy/**` | SSH plan, generated Compose project, preflight, update/rollback/remove. |
| Edge | `apps/edge/**`, `packages/contracts/**` | Owner-browser OIDC, installation lifecycle, durable state/credential vault, stable signer, concrete Cloudflare tunnel/mTLS/publisher-attestation provisioning, and the distinct managed MCP Worker/introspection attestation contract. |
| Remote data | `apps/server/**` | Publisher ingest, atomic replica, OAuth resource server, MCP search/fetch. |
| Release | root config, `.github/**`, docs | Checks, artifact builds, container publishing, provenance documentation. |

One active writer owns each layer during an implementation wave. Cross-layer contracts land through `packages/contracts` before consumers.
