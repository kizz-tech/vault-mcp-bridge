# Architecture

Vault Bridge is a one-way, read-only projection from one local
Obsidian-compatible vault to ChatGPT. The Mac owns canonical content. Every
remote database, index, cache, and generation is derivative and replaceable.

## Primary product path

```text
┌──────────────────────────── Mac ────────────────────────────┐
│ Vault Bridge.app                                             │
│  renderer: sandboxed UI, redacted state, allowlisted IPC     │
│  main: folder picker, scanner, scheduler, safeStorage        │
│  SSH: host-key pinning, fixed commands, bounded SFTP         │
└──────────────────────────┬───────────────────────────────────┘
                           │ complete snapshot over outbound SSH
                           ▼
┌──────────────────────── Linux VPS ───────────────────────────┐
│ one installation-scoped Docker Compose project               │
│  runtime: OpenAI tunnel-client + stdio MCP + SQLite/FTS5     │
│  secret init: network disabled, one-shot                     │
│  named volumes: replica data + runtime secret                │
│  no host ports, bind mounts, Docker socket, or reverse proxy │
└──────────────────────────┬───────────────────────────────────┘
                           │ HTTPS long poll, outbound only
                           ▼
                 OpenAI Secure MCP Tunnel
                           │ account/workspace consent
                           ▼
                        ChatGPT
```

The OpenAI tunnel is the authentication and reachability boundary for the
private MCP. The stdio server does not advertise a second OAuth scheme. The
long-lived runtime API key has only Tunnels Read + Use and is distinct from an
admin key used to create or manage tunnels.

## Desktop boundary

`apps/desktop` is the only normal user-facing process. Its renderer cannot read
files, run SSH, access secrets, or navigate the web. Main-process IPC handlers
validate sender identity and parse small typed inputs.

The setup screen accepts:

- a folder chosen by the native picker;
- SSH host, user, and port;
- an OpenAI tunnel ID and runtime API key.

The API key is verified against the selected tunnel before being encrypted by
Electron/macOS `safeStorage`. Renderer-safe state records only that OpenAI is
configured. It never contains the key, local root, note text, raw SSH output,
or a Compose secret.

Selecting **Set up** authorizes one bounded operation:

1. scan the selected vault and show note count/bytes;
2. resolve SSH config, read and explicitly confirm the first host fingerprint,
   then pin its fingerprint and exact host-key algorithm in an app-private
   `known_hosts` file;
3. verify Linux, Docker Compose, outbound HTTPS, and basic capacity;
4. stage a digest-pinned Compose template and one runtime secret through SFTP;
5. start the exact installation project and wait for its health check;
6. build and import the first complete snapshot;
7. persist a redacted ready receipt and schedule sync.

The app uses argument arrays with `shell: false` locally. Remote actions are a
fixed token allowlist; renderer input cannot become a shell command or Compose
document.

### Agent installation boundary

The packaged executable also exposes a bounded `--agent` mode, installed for
Codex as the `vault-bridge` command. It is not a daemon, TCP service, or second
backend. `doctor`, `status`, and `journal` return redacted JSON. `prepare`
accepts a strict plan containing only the vault root, SSH target, and tunnel ID;
the runtime key arrives on bounded stdin and is immediately handed to the same
safeStorage-backed backend as the GUI. `setup` proceeds only when its
`--approve-host-fingerprint` value exactly matches the newly observed key.

There is no agent command for deletion, arbitrary server commands, raw file
reads, changing projection policy, or vault writes. The desktop UI remains the
human-visible status and recovery surface.

## Vault reader

`packages/vault-core` and `packages/agent-core` resolve the selected root and
perform stable, no-follow reads. Default projection policy includes UTF-8
`.md`, `.canvas`, and `.base` files and excludes hidden entries, `.obsidian`,
`.git`, `node_modules`, and symlinks. Limits bound file count, individual file
size, total bytes, and metadata shape.

An installation has a locally generated HMAC key. It converts relative paths
to opaque document IDs; the remote snapshot contains no local absolute path.
Frontmatter is parsed as untrusted data under a non-executable YAML schema.

Each sync creates a complete immutable generation. A durable pending snapshot
is retried byte-for-byte after interruption. If the projection digest is
unchanged, nothing is uploaded.

The local sync state retains only opaque document IDs, source hashes, and byte
counts for the previous successful generation. This permits aggregate
added/modified/removed/unchanged reporting without logging titles, paths, or
content. The persistent Activity journal stores those aggregates plus trigger,
generation, duration, timestamps, and a redacted component/error code. It is
atomically rewritten and capped at 200 entries. Publication time changes only
after an uploaded generation; last-check time also advances for unchanged
scans.

## Private import and store

The snapshot is streamed to one fixed remote command:

```text
docker compose … exec -T runtime node dist/cli.js private-import …
```

The import command is available only when `PRIVATE_SNAPSHOT_IMPORT=1`. It
validates schema, vault identity, generation, document/source hashes, total
digest, quotas, and expected store identity before atomic activation. The
private pseudo-device cannot authenticate the public signed publisher route.

SQLite keeps the active read-only replica and FTS5 index in a named volume. An
invalid or partial generation never becomes searchable.

## MCP surface

The HTTP and stdio transports share the same tool registration:

- `search({ query })` returns bounded titles, snippets, and opaque IDs;
- `fetch({ id })` returns one bounded document.

Both tools advertise read-only and non-destructive annotations. There is no
tool for listing local paths, reading arbitrary files, SQL, shell execution,
sync control, writes, or deletion. Note text and queries are untrusted input.

## VPS isolation

The primary Compose project contains one long-running `runtime` service and one
network-disabled `runtime_secrets_init` job. The runtime:

- runs as UID/GID 10001;
- has a read-only root filesystem;
- drops all Linux capabilities and enables `no-new-privileges`;
- uses bounded memory, CPU, PIDs, tmpfs, database, index, generations, and logs;
- mounts only its replica and read-only runtime-secret volumes;
- publishes no host ports;
- makes outbound HTTPS calls only to operate the OpenAI tunnel.

It does not join networks owned by other services, change DNS/firewall/Docker
daemon settings, install a reverse proxy, mount the host vault, or use the
Docker socket. Compose project and volume names derive from one opaque
installation ID, so lifecycle commands target only that installation.

The VPS host and Docker daemon remain trusted. Container hardening is not a
hostile-tenant boundary.

## Lifecycle

**Disconnect** stops the runtime, removes its remote key file and runtime-secret
volume, and retains the replica. **Set up** can reconnect the same installation
with the locally encrypted key. **Remove server copy** is a separate confirmed
operation that runs `compose down --volumes` and deletes only the validated
installation directory. Neither action modifies the local vault.

## Advanced public HTTPS/OAuth mode

`apps/edge`, `packages/orchestrator`, and `deploy/runtime` retain the earlier
public endpoint architecture. It uses separate publisher and MCP hostnames,
edge mTLS/attestations, OAuth/JWT, Cloudflare routing, and two long-running VPS
services. That mode is useful when a conventional public MCP URL or team-owned
identity plane is required, but it is not part of the default Secure Tunnel
setup and is not required for personal ChatGPT access.

Any future vault write or remote command feature requires a new authorization,
conflict, audit, and recovery design. It must not be added by widening `fetch`.
