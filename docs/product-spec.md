# Product specification

Status: implemented v1 contract
Target: macOS-first, read-only Obsidian access from ChatGPT

## Product decision

Vault Bridge is one installed application. The normal user never runs an agent,
server, pairing CLI, Docker Compose, tunnel client, scanner, or sync worker
directly. A bounded machine interface exists for Codex-driven installation; it
uses the same application backend and is not a second product runtime.

The first-use flow is one screen:

```text
Vault Bridge                              Overview Activity   ···

Connect vault

Vault       Not selected                             Choose
Server      Not configured                              Add
OpenAI      Not configured                              Add

                                                     Set up
```

There is no hero copy, wizard, step counter, preview page, pairing code, Vault
ID, device identity, filter form, or explanatory gray text.

## Inputs

### Vault

The native folder picker immediately scans the selected root. The row becomes
a compact acceptance receipt:

```text
Vault       My Vault · 1,248 notes · 32 MB              Change
```

### Server

The server sheet contains only address, SSH user, and port. The app uses the
system SSH agent/config and never asks the renderer for a private key. First
connection shows a native host-fingerprint confirmation; later identity drift
hard-fails.

### OpenAI

The OpenAI sheet contains tunnel ID and runtime API key plus direct buttons to
the official Tunnels and API-key pages. The runtime key must have Tunnels Read
+ Use. It is verified before encrypted storage and never returned to the
renderer.

OpenAI account actions and ChatGPT consent remain external because only the
account owner can perform them. This does not turn the MCP into a catalog or
licensed application.

## Setup

One **Set up** action performs all internal stages. Progress text replaces the
button in place:

```text
Checking server
Starting container
Securing connection
Synchronizing vault
Ready
```

Failures show one line and one next action. Raw stderr, paths, secrets, stack
traces, and note contents never appear in the main UI or Activity view.

## Ready state

```text
Vault Bridge                              Overview Activity   ···

My Vault                                                 Ready
1,248 notes · 32 MB · published 14:32

Server          deploy@vps.example.com                  Manage
ChatGPT         Connected                         Open ChatGPT
Sync            Every 5 minutes                         Pause

Synchronize
```

Top-level states are **Ready**, **Synchronizing**, and **Needs attention**.
Ready means the last local scan/publication and remote runtime succeeded. It
does not claim that iCloud has already delivered a newer phone-side edit.

Automatic sync means one check when the app starts, another after Resume, and a
check every configured interval while the app is running. The overview shows
last check, last actual publication, and next scheduled check separately.
Activity is a full application view, not a modal. Sync entries show safe
aggregate added/modified/removed/unchanged counts, generation, current bytes,
duration, and trigger. Failed entries identify only the bounded component and
error class. They never expose note titles, paths, content, or raw queries.

## Agent-first setup

The copyable prompt delegates to one versioned runbook. Codex installs the app
and its `vault-bridge` command, then uses a two-phase configuration:

1. `prepare` reads a strict non-secret plan and the runtime key from stdin,
   validates the vault/tunnel, and returns a candidate SSH fingerprint;
2. after exact owner approval, `setup` pins that fingerprint and performs the
   existing bounded deployment.

`doctor` performs live read-only checks of the configured vault, pinned SSH
runtime, OpenAI tunnel, and latest synchronization. `doctor`, `status`, and
`journal` return predictable redacted JSON. There is no
agent command for arbitrary shell, server commands, file reads, deletion, or
vault writes.

## V1 scope

Included:

- one vault per installation;
- `.md`, `.canvas`, and `.base` text;
- one isolated Docker project on an existing VPS;
- automatic and manual read-only snapshot sync;
- MCP `search` and `fetch`;
- pause, disconnect, reconnect, and exact server-copy removal;
- unsigned local macOS packages and an OSS release path.

Excluded:

- any write to the vault;
- arbitrary path access, directory browsing, shell, or raw SQL;
- two-way sync and conflict resolution;
- attachment/OCR/media extraction;
- multi-user sharing and ACLs;
- management of unrelated VPS apps or infrastructure;
- automatic OpenAI account consent or ChatGPT catalog publication.

## Product invariants

- The local vault is canonical.
- The server cannot initiate a Mac read or command.
- Remote state is disposable and never synchronized back.
- A shared VPS deployment publishes no host ports and touches no other Compose
  project.
- Credentials are main-process/Keychain concerns, never renderer state.
- A future write feature is a new product/security contract, not a v1 toggle.

## Advanced mode

The repository also contains a public HTTPS/OAuth/Cloudflare architecture for
operators who need a conventional endpoint or team identity plane. It is an
advanced mode with additional infrastructure and is not shown in the default
personal setup.
