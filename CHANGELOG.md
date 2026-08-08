# Changelog

All notable changes to Vault Bridge are documented here. The project follows
semantic versioning while the public product contract is still evolving.

## [0.1.3] - 2026-08-08

### Fixed

- Keep the visible Overview and Activity surfaces reconciled with the backend
  after unattended synchronization, including a passive refresh and immediate
  refresh when the window regains focus.
- Isolate ephemeral CLI session data and avoid reopening Keychain from
  `doctor` on configured installs; live tunnel verification remains bounded.

## [0.1.2] - 2026-08-08

### Fixed

- Refresh the Overview vault note/byte totals from each accepted sync receipt,
  so the connection path and latest diff describe the same generation without
  requiring an app restart.

### Distribution status

- Apple Silicon DMG and ZIP artifacts remain ad-hoc signed and are not Apple
  notarized.

## [0.1.1] - 2026-08-08

### Changed

- Rebuilt the desktop interface as a compact system utility with flat
  connection rows, restrained status treatment, and a denser synchronization
  panel.
- Reworked Activity into a time-oriented operational log instead of a card and
  chip dashboard.
- Simplified settings, application icon, and project README.
- Fixed strict SSH synchronization for macOS application-data paths and SSH
  aliases, and converted early pipe closure into a handled sync failure.
- Added live redacted diagnostics for the vault, pinned SSH/runtime, OpenAI
  tunnel, and last sync; failed Activity entries now identify the failing
  component without retaining private output.
- Removed temporary deployment secrets after every setup attempt and made the
  start-at-login control reflect the real macOS setting.

### Distribution status

- Apple Silicon DMG and ZIP artifacts remain ad-hoc signed and are not Apple
  notarized.
- `v0.1.0` remains available as the immutable first public preview.

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

[0.1.3]: https://github.com/kizz-tech/vault-mcp-bridge/releases/tag/v0.1.3
[0.1.2]: https://github.com/kizz-tech/vault-mcp-bridge/releases/tag/v0.1.2
[0.1.1]: https://github.com/kizz-tech/vault-mcp-bridge/releases/tag/v0.1.1
[0.1.0]: https://github.com/kizz-tech/vault-mcp-bridge/releases/tag/v0.1.0
