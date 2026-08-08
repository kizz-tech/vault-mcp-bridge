# Threat model

This model covers the default private path: macOS desktop, SSH, one isolated
VPS Compose project, OpenAI Secure MCP Tunnel, and ChatGPT. The advanced public
HTTPS/OAuth edge has additional controls and risks outside this primary model.

## Assets and authority

| Asset | Authority | Derived surface |
| --- | --- | --- |
| Vault files | selected local Mac folder | snapshot, SQLite generation, FTS5 index |
| OpenAI tunnel | owner's OpenAI organization/workspace | tunnel ID, runtime polling session |
| Runtime API key | OpenAI runtime-key store + macOS safeStorage | read-only secret volume on VPS |
| SSH identity and host pin | system SSH agent/config + app-private pin | bounded deployment session |
| MCP access | ChatGPT workspace consent + OpenAI tunnel | `search` and `fetch` calls |

Remote copies never outrank the local vault and are never synchronized back.

## Trust boundaries

1. **Renderer → Electron main.** Renderer data is untrusted. The sandboxed
   renderer has no Node integration and reaches main only through typed,
   sender-checked, allowlisted IPC.
2. **Codex command → Electron main.** The installed command accepts a fixed
   grammar and strict non-secret plan. Credentials enter only through bounded
   stdin. Setup requires the exact separately approved SSH fingerprint.
3. **Desktop → vault.** The scanner is allowed to read only the selected root
   and reviewed text extensions. Symlinks, hidden/system entries, size limits,
   and stable no-follow reads constrain traversal and races.
4. **Desktop → VPS.** SSH host identity is pinned. Local processes use fixed
   argv with `shell: false`; remote actions and SFTP paths are validated.
5. **VPS runtime → OpenAI.** The runtime makes outbound HTTPS polls using a
   restricted runtime key. The VPS exposes no inbound MCP port.
6. **ChatGPT → notes.** Prompts, search queries, note text, and links are
   untrusted content. MCP results are data, never policy or executable commands.
7. **VPS host → container.** The VPS/Docker operator can inspect plaintext
   replica data and control containers. Container hardening protects against
   mistakes and common process compromise, not a hostile root operator.

## Security objectives

1. Never modify the canonical vault remotely.
2. Never allow the VPS to initiate a desktop read or command.
3. Export only the selected bounded projection.
4. Make partial, corrupt, stale, or wrong-vault snapshots fail closed.
5. Restrict ChatGPT to `search` and `fetch` with opaque IDs.
6. Prevent one installation lifecycle from touching unrelated VPS projects.
7. Keep credentials, paths, queries, and note text out of logs and repository
   artifacts.

## Threats and controls

| Threat | Control | Residual risk |
| --- | --- | --- |
| Renderer compromise | CSP, sandbox, context isolation, no Node/navigation/webviews, IPC allowlist | Electron/runtime vulnerabilities still matter |
| Malicious copied setup prompt or drifted instructions | short prompt pins the canonical repository/runbook; agent verifies owner; release-specific behavior lives with code | owner still chooses which prompt and repository to trust |
| Credential exposure through agent context/argv | setup plan forbids secrets; runtime key is bounded stdin only, then safeStorage; redacted JSON status | clipboard and local account remain trusted during handoff |
| Agent overreach on the VPS | command exposes only prepare/setup/status/journal; backend retains fixed SSH/Compose operations; deletion is unavailable | a separately compromised local agent may still use the owner's general shell authority |
| Agent auto-accepts an SSH MITM | prepare cannot deploy; setup requires the exact owner-approved fingerprint | independent first-use verification remains owner responsibility |
| Path traversal or symlink escape | canonical root, allowlisted extensions, no-follow reads, stable identity checks, hidden/system exclusions | compromised Mac already owns local data |
| Malformed frontmatter or canvas | non-executable parsers, bounded schemas, raw text treated as data | parser bugs remain supply-chain risk |
| Prompt injection in notes | tool descriptions mark results untrusted; no execution/write tools | model behavior is not a hard security boundary |
| Snapshot tamper or partial activation | schema, vault/generation/digest/source-hash/quota checks; SQLite transaction | VPS root can replace its own replica |
| Wrong/stale snapshot retry | durable pending snapshot, monotonically newer generations, exact receipt matching | manual state corruption requires recovery |
| SSH command injection | fixed argv/token allowlist, `shell: false`, strict paths, bounded output/timeouts | system SSH config and agent remain trusted |
| SSH MITM or host replacement | first-use fingerprint confirmation, app-private pin, and exact pinned host-key algorithm; drift hard-fails | first-use verification is owner responsibility |
| Runtime key leakage | restricted Tunnels Read + Use, safeStorage, SFTP `0600`, network-disabled init, `0400` read-only volume | VPS root can read container/volume secrets |
| OpenAI admin-key exposure | admin key is never accepted by normal runtime configuration or stored on VPS | owner must create correct restricted key |
| Public internet probing | no host ports; outbound Secure Tunnel control plane | OpenAI account/workspace authorization remains external |
| Container escape/noisy neighbor | non-root, read-only root, dropped caps, no-new-privileges, no Docker socket/binds, resource/log/storage limits | shared kernel/daemon is trusted |
| Cross-project deletion | opaque deterministic project, exact directory/volume names, validated lifecycle commands, explicit removal confirmation | out-of-band root actions are uncontrolled |
| Sensitive diagnostics | 200-entry redacted Activity journal and live doctor checks; only aggregate diffs and bounded component/error codes, no raw stdout/stderr, paths, keys, queries, titles, or note text | local crash/core dumps need OS protection |
| iCloud freshness overclaim | UI reports last Mac scan/publication only | phone-to-Mac delivery is outside Vault Bridge |
| Denial of service or bill impact | no public host port, bounded tool inputs/results, container resource limits | OpenAI/VPS/account quotas remain external |

## Secret lifecycle

The desktop accepts a tunnel ID and a runtime API key. It verifies the pair
with the OpenAI tunnel metadata endpoint before writing the key through
safeStorage. The persisted setup record contains only the tunnel ID and a
boolean renderer projection.

During deployment the source key is staged privately and uploaded with mode
`0600`. A network-disabled init job copies it into a named volume owned by UID
10001 with mode `0400`. The local staging directory is removed after every
setup attempt. The runtime mounts that volume read-only. Disconnect
stops the runtime, removes the remote source file, and removes the runtime
secret volume while retaining replica data. Reconnect recreates the secret
from the locally encrypted value.

Tunnel creation/deletion uses a separate OpenAI admin key and is not performed
by the long-lived runtime.

## Incident response

For suspected exposure:

1. disconnect or stop the exact Compose project;
2. revoke the affected OpenAI runtime key;
3. disconnect the ChatGPT plugin/tunnel association if required;
4. remove the server copy if replica confidentiality is in doubt;
5. create a new restricted runtime key and redeploy;
6. retain only redacted timestamps, identifiers, versions, and health evidence.

Do not paste keys, raw notes, queries, local paths, container dumps, or database
files into a public issue.

## Assumptions and non-goals

- The Mac login, filesystem, SSH agent, and safeStorage are protected.
- The owner trusts the VPS administrator and OpenAI workspace administrators.
- Availability, account recovery, iCloud propagation, and mobile client
  behavior are external dependencies.
- V1 intentionally omits writes, two-way sync, arbitrary attachments, shell,
  directory listing, OCR, and remote desktop control.
