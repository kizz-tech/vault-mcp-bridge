# Changelog

All notable changes to Vault Bridge are documented here. The project follows
semantic versioning while the public product contract is still evolving.

## [0.1.0] - 2026-08-08

First public preview.

### Added

- One-launch macOS desktop application for selecting a vault, configuring an
  SSH server, and deploying an isolated read-only MCP runtime.
- Agent-first installation with a copyable Codex prompt, versioned runbook,
  strict non-secret plan schema, and redacted JSON command contract.
- Read-only MCP `search` and `fetch` tools backed by atomic SQLite/FTS5 snapshot
  generations.
- OpenAI Secure MCP Tunnel deployment with no published host ports.
- Automatic five-minute synchronization, manual sync, pause/resume, and a
  persistent full-screen Activity view with aggregate change summaries.
- Exact SSH fingerprint and host-key algorithm pinning, macOS encrypted secret
  storage, hardened Electron fuses, resource-bounded containers, and a public
  threat model.

### Distribution status

- Apple Silicon DMG and ZIP artifacts are integrity-checked and ad-hoc signed
  for packaging verification.
- The preview is **not** Developer ID signed or Apple notarized. It is not yet
  a normal double-click installation for non-technical macOS users.
- The supported current route is the Codex runbook or an inspected source
  build. Signed/notarized distribution is tracked in the public roadmap.

[0.1.0]: https://github.com/kizz-tech/vault-mcp-bridge/releases/tag/v0.1.0
