# Vault Bridge: product specification

Status: current implemented product contract (source remains the authority)
Scope: product and architecture contract; implementation status is tracked in
[`specs/2026-08-07-vault-bridge-product/status.md`](../specs/2026-08-07-vault-bridge-product/status.md)
Target: macOS-first, read-only Obsidian-compatible vault access from ChatGPT

## 1. Product decision

Vault Bridge is one installed desktop application, not a collection of commands.

The normal user flow is:

1. Open the app.
2. Sign in once on first use.
3. Choose a vault folder.
4. Add a server over SSH.
5. Select **Set up**.
6. Connect the generated MCP address to ChatGPT.

The user never sees or runs the local agent, remote server, pairing CLI, Docker Compose, preview command, key generation, tunnel command, or synchronization worker. Those remain internal stages of one resumable operation.

The existing scanner, signed snapshot, atomic replica, search, and MCP server remain the data core. The product gap is a desktop shell and orchestration layer around them.

## 2. Product promise

> Choose a Markdown vault and an SSH server once. Vault Bridge coordinates an isolated read-only MCP replica, publishes changes after they are visible and scanned on the Mac, and gives ChatGPT a stable address when the owner supplies the required edge and account credentials.

Success means:

- one application launch and no terminal;
- one primary setup screen rather than a wizard;
- the Mac remains the only reader of the canonical vault;
- the VPS stores only the selected derivative replica;
- the VPS cannot initiate reads or commands on the Mac;
- the remote stack can coexist with unrelated applications on the same VPS;
- ChatGPT receives read-only, authenticated MCP tools;
- normal operation is understandable from one status line.

## 3. Product boundaries

### V1 includes

- one local vault per installation;
- Markdown-oriented Obsidian-compatible scanning;
- automatic background synchronization;
- remote read-only MCP tools;
- SSH provisioning, health checks, updates, rollback, logs, and uninstall;
- a stable public HTTPS MCP endpoint;
- OAuth authorization for the owner;
- a managed edge account and per-installation tunnel in the normal product mode;
- macOS packaging and Keychain integration.

### V1 does not include

- writes from ChatGPT into the vault;
- two-way note synchronization;
- remote filesystem access by arbitrary path;
- an embedded ChatGPT widget;
- multi-user sharing or team ACL management;
- VPS monitoring unrelated to the Vault Bridge installation;
- management of existing Docker projects, reverse proxies, firewalls, or OS updates.

An MCP server does not require custom ChatGPT UI, so V1 remains data-only inside ChatGPT. OpenAI recommends focused tools and allows an MCP server to return useful structured/text results without a component: [Build an MCP server](https://developers.openai.com/plugins/build/mcp-server).

## 4. UX contract

### 4.0 Owner sign-in

First use has one account screen before server setup:

```text
Vault Bridge

Continue with owner account
```

Authentication uses authorization code + PKCE in the system browser. The app
creates a random `state` and nonce, binds a temporary loopback callback on an
ephemeral port, accepts one matching short-lived code exactly once, and
exchanges it over HTTPS. No bearer token or session credential appears in a
URL. The current implementation does not claim a universal-link callback or a
bare custom URL scheme as an authentication boundary.

No edge, tunnel, OAuth, or account-management explanation appears in normal onboarding. A returning signed-in user goes directly to the vault/server screen. Recovery and installation revocation live under the account menu.

### 4.1 First launch

One page, one column, approximately 600 px wide:

```text
Vault Bridge                                      Journal   ···

Connect vault

Vault       Not selected                             Choose
Server      Not configured                              Add

                                                     Set up
```

Rules:

- no hero paragraph;
- no feature cards;
- no step counter;
- no preview screen;
- no pairing or cryptography vocabulary;
- no Vault ID, Remote URL, include/exclude patterns, or device identity;
- no explanatory gray copy;
- one primary action;
- labels and status are direct nouns and verbs.

The native folder picker selects the vault and immediately runs the local scan. Before **Set up** becomes available, the row changes in place to a compact factual summary:

```text
Vault       My Vault · 1,248 notes · 32 MB              Change
```

This summary is the explicit preview receipt accepted by **Set up**. Detailed included/excluded paths remain behind a disclosure for review and are not a separate mandatory screen. The absolute path is available only there and in settings when needed for disambiguation.

### 4.2 Server sheet

```text
Server

Address       vps.example.com
User          deploy
SSH port      22

Cancel                                      Connect
```

Behavior:

- accept an alias from `~/.ssh/config` or `user@host`;
- use the system OpenSSH client, SSH Agent, and SSH config;
- never paste or display a private key in HTML;
- request a password/passphrase only through a native one-time prompt;
- pin the host key after the first explicit fingerprint confirmation;
- hard-stop if the pinned host key later changes.

Authentication controls appear only when automatic SSH discovery fails.

### 4.3 Setup in progress

The button is replaced in place by one status and one progress indicator:

```text
Checking server
Starting container
Securing connection
Synchronizing vault
Ready
```

These are transient statuses, not user-controlled steps. **Journal** remains available. The operation is resumable after app restart.

### 4.4 Ready state

```text
Vault Bridge                                      Journal   ···

My Vault                                                 Ready
1,248 notes · 32 MB · published 14:32

Server          deploy@vps.example.com                  Manage
ChatGPT         mcp.vaultbridge.app            Copy URL & Open
Sync            Automatic                               Pause

Synchronize
```

Only three top-level states exist:

- **Ready**
- **Synchronizing**
- **Needs attention**

No dashboard metrics, charts, security badges, or activity cards are shown.

**Ready** means the remote service and last publication are healthy. It never claims that iCloud contains no newer phone-side change; the timestamp is the last successful local scan and publication observed by the Mac.

### 4.5 Settings

Settings is one sheet with controls only:

- Vault: change folder;
- Server: reconnect, update;
- Sync: automatic on/off, optional interval under Advanced;
- Filters: under Advanced;
- Start at login: user-controlled setting;
- Security: inspect device identity, disconnect/revoke;
- Removal: stop service, remove service, remove service and replica.

Removing the remote replica is a separate confirmation. No removal action can delete or modify the local vault.

### 4.6 Journal

The journal is hidden by default and contains terse redacted events:

```text
14:02  SSH connected
14:02  Server checked
14:03  Container started
14:03  Vault synchronized
```

It never records:

- note contents;
- search queries;
- access tokens or tunnel credentials;
- private keys;
- raw request headers;
- absolute local paths;
- arbitrary stdout/stderr from remote commands.

`Copy diagnostics` produces a bounded redacted bundle.

### 4.7 Errors

Main-screen errors are one line plus one next action:

| State | Main UI | Actions |
| --- | --- | --- |
| Vault missing | `Vault not found` | `Choose` |
| SSH failed | `SSH authentication failed` | `Change connection`, `Journal` |
| Host key changed | `Server identity changed` | `Review fingerprint` |
| Docker unavailable | `Docker unavailable` | `Server setup`, `Cancel` |
| Insufficient capacity | `Server capacity is insufficient` | `Limits`, `Cancel` |
| Deployment failed | `Container did not start` | `Retry`, `Journal` |
| Sync blocked | `Sync blocked · 3 files unreadable` | `Retry`, `Journal` |
| Server offline | `Server offline` | `Retry` |
| Owner OAuth not linked | `Sign in to owner account` | `Sign in` |

Stack traces and remote command output exist only in redacted diagnostics.

## 5. One-launch desktop architecture

### 5.1 Packaging

The shortest path from the current TypeScript code is an Electron macOS application:

- Electron main process owns filesystem, SSH, Keychain, scheduler, and lifecycle;
- the renderer is a sandboxed web UI;
- `nodeIntegration` is disabled in the renderer;
- `contextIsolation` is enabled;
- renderer IPC is an explicit allowlist of product operations;
- the window can close while synchronization continues in the Electron main
  process; and
- the app reopens the same persisted setup state and resumes from the last
  verified phase when it launches. Start-at-login is a user-controlled
  Electron setting, not a claim that every package enables it by default.

The release may be signed/notarized only in a separately credentialed release
pipeline. This checkout's local package path is not signing/notarization
evidence. Development may use multiple internal processes, but the repository
exposes one normal development command and release users see none of them.

Non-secret product configuration is resolved as `VAULT_BRIDGE_*` environment
variables first, then `product-config.json` in Electron `userData`, then
`product-config.json` in packaged resources. Forge embeds a public config only
when `VAULT_BRIDGE_PRODUCT_CONFIG_PATH` names a file ending in
`product-config.json`; credentials and lease material are never packaged.
Without real managed-edge/OIDC/image-digest inputs the current release
candidate remains intentionally unconfigured, so a clean-install one-launch
claim requires a configured packaged smoke test.

### 5.2 Local components

```text
Desktop shell
  ├── Web renderer
  ├── Setup orchestrator
  ├── SSH adapter
  ├── Keychain adapter
  ├── Vault scanner and filter policy
  ├── Snapshot signer
  └── Background sync scheduler
```

The setup orchestrator is a persisted state machine, not UI page state:

```text
idle
→ preflight
→ staged
→ deployed
→ device-bound
→ first-snapshot
→ endpoint-verified
→ ready
```

Each transition is idempotent. Restart resumes from the last verified transition. A failed new installation removes only its staging resources.

### 5.3 Internal automation

Selecting **Set up** authorizes these bounded operations:

1. Resolve and validate the local vault.
2. Build the default read-only projection and automatic preview.
3. Verify the SSH host key and connection.
4. Check OS/architecture, Docker mode, Compose, disk, memory, CPU, and outbound access.
5. Generate the installation/device signing identity and the publisher mTLS
   private key plus PKCS#10 CSR on the Mac.
6. Store private credentials in Keychain/safe storage; send only the CSR to the
   owner/edge control plane.
7. Have the concrete Cloudflare provider issue the installation certificate,
   tunnel, and separate publisher/MCP Worker routes, returning scoped
   credential leases. The managed MCP Worker performs uncached online
   introspection and fails closed with `503` when the edge decision is
   unavailable before adding its distinct MCP-edge HMAC.
8. Stage version-pinned deployment files and lease material.
9. Pull images pinned by digest.
10. Start only the installation's Compose project.
11. Run health checks.
12. Bind the publisher device (the legacy pairing adapter may run internally,
    but no code is shown to the owner). If a crash occurs after acceptance but
    before local state commits, a fresh one-use code for the same
    installation/vault/public key returns the same device idempotently; a
    mismatched or revoked identity fails closed.
13. Publish the first signed snapshot over the authenticated outbound HTTPS
    ingest route.
14. Verify the public MCP endpoint and OAuth discovery.
15. Show the ready state.

Pairing remains a security property but disappears as a product concept. No code or token is copied by the user.

## 6. Shared-VPS non-interference contract

The remote installation is a guest, not the owner of the server.

### 6.1 Default runtime

Prefer a dedicated unprivileged user and rootless Docker runtime when the host supports it. Docker documents that rootless mode runs both daemon and containers without root privileges: [Rootless mode](https://docs.docker.com/engine/security/rootless/).

If rootless prerequisites are absent, setup stops before mutation and offers a narrowly described server-setup action. It does not silently install or restart the system Docker daemon.

Using an existing rootful Docker daemon is an Advanced compatibility mode because Docker daemon control grants host-level power. Docker explicitly warns that Docker group membership grants root-level privileges and that only trusted users should control the daemon: [Docker Engine security](https://docs.docker.com/engine/security/), [Linux post-installation](https://docs.docker.com/engine/install/linux-postinstall/).

### 6.2 Per-installation Compose project

Every vault gets an opaque instance ID and a unique Compose project name such as `vmb-a7k4m2`. Compose project names are specifically intended to isolate applications on shared hosts: [Compose project names](https://docs.docker.com/compose/how-tos/project-name/).

The project owns exactly:

- two long-running containers: non-root `server` and outbound-only `tunnel`;
- two network-disabled one-shot secret-init jobs (`server_secrets_init` and
  `tunnel_secrets_init`), which must complete before their dependent service;
- one internal application network;
- one egress network attached only to the tunnel container;
- one replica data volume and one named secret volume per long-running service;
- bounded logs and configuration in one installation directory.

No static `container_name` is used. Every resource also receives a reverse-DNS installation label containing the exact instance ID.

### 6.3 Container rules

- no `privileged`;
- no host network;
- no Docker socket in any container;
- no bind mount of the local or host filesystem;
- no host port by default;
- non-root process;
- read-only root filesystem;
- all capabilities dropped;
- `no-new-privileges`;
- tmpfs for temporary data;
- explicit CPU, memory, PID, response-body, log, and storage budgets;
- health check and bounded restart policy;
- images pinned by digest.

SSH/SFTP-uploaded file-source secrets are mode `0600` for the deployment user. A
network-disabled init job copies each source into the owning named secret
volume, sets the exact runtime UID/GID and configured runtime file mode
(default `0440`), and exits before the long-running service starts. Each
long-running service mounts only its own named secret volume read-only; no
file-source secret is mounted directly into a service.

Compose supports CPU, memory, and PID limits; these are required because isolation without resource ceilings does not prevent a noisy neighbor: [Compose deploy resources](https://docs.docker.com/reference/compose-file/deploy/).

A portable named volume does not provide a universal hard size quota. V1 therefore enforces disk safety at every writable layer:

- the manifest declares compressed and expanded bytes before upload;
- ingest rejects a generation above the configured per-vault quota;
- staging begins only when the host remains above a configured free-space reserve after worst-case expansion;
- SQLite page count, index size, temporary files, request bodies, and retained generations have application limits;
- tmpfs mounts have explicit sizes;
- Docker logs use bounded rotation;
- failed staging is removed before another attempt;
- a filesystem/project quota is added when the host supports it.

This is strong application-level containment, not a universal filesystem guarantee. If hard tenant disk isolation is required against a compromised runtime, the product recommends a dedicated VM/VPS.

### 6.4 Network rules

The application container joins only an `internal: true` network. The tunnel container joins that internal network and a second egress-capable network, makes the only outbound connection, and maps two separate hostnames to internal routes: the user-facing MCP resource and the publisher-only ingest resource. The application container has no direct internet egress. Runtime verification uses provisioned offline verification keys and does not fetch arbitrary remote dependencies. The managed MCP hostname is a Cloudflare Worker route that strips caller-supplied proof headers, performs uncached online edge introspection, returns `503` on edge outage, and adds a distinct request-bound HMAC before forwarding.

The stack does not claim ports 80, 443, or any arbitrary host port, and it never edits Nginx, Caddy, Traefik, firewall rules, or DNS on the VPS.

Compose creates a project-scoped network, and an internal network can be explicitly externally isolated: [Compose networking](https://docs.docker.com/compose/how-tos/networking/), [network reference](https://docs.docker.com/reference/compose-file/networks/).

### 6.5 SSH deployment boundary

SSH is a control-plane transport only:

- the app invokes the user's existing system SSH identity for install, update, status, rollback, and removal;
- the renderer cannot supply a command or Compose document;
- the orchestrator selects from a fixed allowlist of versioned operations;
- private keys stay in SSH Agent/Keychain and are never copied to the VPS or renderer;
- the normal background synchronization path does not use SSH.

After bootstrap, the Mac publishes snapshots through a separate outbound HTTPS ingest route authenticated with an installation-scoped mTLS credential and snapshot signature. The server never initiates a connection to the Mac.

### 6.6 Forbidden host mutations

Vault Bridge never:

- restarts Docker;
- runs `docker system prune`;
- uses `--remove-orphans` outside its exact project;
- lists or modifies unrelated containers, volumes, or networks;
- changes Docker daemon configuration;
- installs a shared reverse proxy;
- changes firewall, sysctl, SSH daemon, cron, or system updates;
- binds 80/443;
- runs `apt upgrade` or equivalent;
- uses a broad remote Docker TCP API.

## 7. Remote data plane

The Mac reads the canonical vault and produces a filtered immutable snapshot. The VPS never receives iCloud credentials and never mounts the live vault.

```text
Obsidian vault on Mac
  → local filter and stable read
  → signed immutable snapshot
  → authenticated outbound HTTPS upload
  → atomic SQLite/FTS replica on VPS
  → read-only MCP tools
```

The publisher route and the ChatGPT MCP route use separate authentication planes. The publisher credential cannot call MCP tools; a ChatGPT OAuth token cannot publish a snapshot. The remote service retains the active generation and one rollback generation. Publication is atomic; a partial upload cannot become searchable.

## 8. Public edge and the unavoidable product choice

SSH alone cannot produce a stable public HTTPS endpoint, domain, tunnel credentials, and OAuth identity. Therefore the exact two-input UX—Vault plus SSH server—requires a managed edge/control plane.

Recommended product model:

- open-source desktop app and VPS data plane;
- Vault Bridge managed edge is a required component of the normal two-input product mode;
- first launch has one owner-account sign-in backed by the configured browser OIDC provider;
- edge assigns the hostname, provisions a Cloudflare Tunnel/DNS/Worker route
  scoped to one installation, and supplies the OAuth/identity integration;
- the control plane stores the owner/installation binding, hostname, tunnel reference, revocation state, and audit metadata, but not note contents or search results;
- MCP and publisher traffic travel through separately authenticated tunnel routes to the user's VPS;
- each tunnel and edge-attestation credential is installation-scoped, stored under the dedicated deployment user's private directory with mode `0600`, copied by the network-disabled init jobs into named volumes with exact runtime UID/GID and default `0440` mode, mounted read-only by its owning service, and revoked on disconnect; Cloudflare in-place rotation currently fails closed and is not a supported one-click operation;
- the app and VPS store only the scoped credential, never the edge provider's account-wide credential;
- existing tunnels and remote replicas continue serving while the management control plane is unavailable, but new setup, recovery, and OAuth linking may be temporarily unavailable; in-place Cloudflare credential rotation is intentionally unavailable until a coordinated migration is implemented;
- account recovery happens through the identity provider, then requires explicit re-binding or revocation of installations;
- fully self-hosted edge/domain/OAuth is a separate Advanced mode with additional configuration fields.

This is the only honest way to preserve the requested normal UI:

```text
Vault + SSH server + Set up
```

The product trust boundary therefore includes the selected identity provider,
edge control plane, and Cloudflare tunnel provider. The tunnel provider
terminates/routes public HTTPS traffic; users who cannot accept that boundary
must use the current self-hosted Advanced mode with its Cloudflare
requirements, or wait for a separately reviewed provider adapter.

Without the managed edge, a fully self-hosted user must additionally provide a domain/tunnel authorization and OAuth provider configuration. That complexity can be hidden from the normal mode, but it cannot be eliminated by UI design.

The current managed edge implementation uses Cloudflare Tunnel because its
connector makes outbound connections and can run without publishing VPS host
ports. The provider also creates dedicated-zone DNS/Worker routes and issues
the publisher certificate from the Mac-generated CSR. Tunnel tokens and the
Cloudflare API token must be treated as secrets because anyone holding them can
operate the tunnel/account: [Tunnel configuration](https://developers.cloudflare.com/tunnel/configuration/), [tunnel tokens](https://developers.cloudflare.com/tunnel/advanced/tunnel-tokens/). A source implementation is not evidence that the account, zone, or route is deployed.

## 9. ChatGPT and MCP contract

The MCP endpoint is stable HTTPS at `/mcp` and exposes only private, read-only tools. On the managed hostname, a Cloudflare Worker performs uncached online introspection for every request and fails closed with `503` if that edge decision cannot be made. It strips caller-supplied attestation headers, then adds a distinct MCP-edge HMAC bound to method/path/query/host, timestamp/nonce, and a digest of the bearer token; the VPS verifies that proof before OAuth/JWT. Publisher mTLS/attestation remains a separate plane.

| Tool | Purpose |
| --- | --- |
| `search` | Find notes using the existing bounded search contract and return opaque result IDs. |
| `fetch` | Return one allowlisted note by opaque ID using the existing fetch contract. |

Both tools advertise `readOnlyHint: true`, `destructiveHint: false`, and `openWorldHint: false`. Sync status remains a local product surface, not an MCP tool. There is no `read_file(path)`, arbitrary glob/regex, shell, raw SQL, raw directory listing, or vault export tool.

Because the data is private and user-specific, every request is authorized by the MCP server. OpenAI's current contract expects OAuth 2.1 discovery, authorization-code + PKCE, resource indicators, and token verification on every request: [Authentication](https://developers.openai.com/plugins/build/auth).

OAuth revocation is client-scoped. Incrementing a registered client's
monotonic `revocationEpoch` invalidates that client's authorization codes,
refresh tokens, and access tokens while leaving unrelated clients valid; the
client registration remains for future authorization.

The ready-state action **Copy URL & Open** copies the exact HTTPS MCP resource
and opens ChatGPT Web/the account surface. The ready state shows the
installation host; it does not claim an external connection that the desktop
cannot observe. The user completes the account-level custom MCP connection and
OAuth consent there. Pairing the server to the desktop app is already complete
and is not repeated there.

Observed mobile availability after account-level setup is treated as a compatibility target and verified in the real-client test matrix; it is not implemented as a separate mobile synchronization path.

## 10. Security and abuse controls

- one `vault:read` scope in V1;
- verify signature, issuer, audience/resource, expiration, subject, client, and scope on every MCP request;
- apply bounded per-process rate guards by verified subject/client/vault and
  edge IP; no global distributed limiter is promised;
- bounded query length, result count, concurrency, page size, and response bytes;
- opaque cursors bound to the caller;
- apply export policy before indexing and searching;
- no note contents, search text, tokens, or raw local paths in logs;
- a local **Pause access** kill switch stops the public MCP service without deleting the replica;
- dynamic `/readyz` checks storage, required secret/configuration, and offline
  authentication freshness on each request; liveness is not readiness or
  public-route proof;
- revoke OAuth client/tokens using the client-scoped epoch and revoke the
  tunnel independently;
- revoke the publisher credential independently from ChatGPT OAuth. New
  Cloudflare material requires coordinated revoke/reprovisioning while the
  provider's in-place `rotate` operation fails closed;
- never pass an upstream access token through the MCP server.

## 11. Updates, rollback, and removal

### Update

1. Fetch a signed release manifest.
2. Verify the image digest and compatibility.
3. Check capacity.
4. Preserve current image digest, configuration, and active generation.
5. Start the candidate only inside the exact Compose project; both
   network-disabled init jobs must complete before their services run.
6. Run dynamic readiness, Worker-introspection/`503`, and MCP contract checks.
7. Activate it or roll back automatically.

Updates never change the host Docker daemon or unrelated projects.

### Removal

Two distinct actions:

- **Remove service, keep replica**
- **Remove service and replica**

Removal resolves resources only by exact project and installation labels. The local vault is outside the removal scope. Data-volume deletion requires a separate confirmation.
The desktop keeps **Disconnect** and **Remove server copy** reachable. Disconnect
revokes/stops the installation, removes revoked credential volumes and staged
secret files, and retains only the replica data volume plus a durable,
cleanup-only receipt. A new setup cannot overwrite that receipt. Reusing the
retained replica is not a V1 feature. **Remove server copy** is separately
confirmed, removes only the exact recorded replica volume, verifies its absence,
and clears the receipt only after success. Cloudflare cleanup is serialized per installation and journaled after
each external mutation, with retryable failures and idempotent delete-404
handling.

## 12. Target module boundaries

```text
apps/
  desktop/            Electron main process and renderer
  server/             Existing remote MCP/data service

packages/
  agent-core/         Existing local scanning/snapshot behavior
  orchestrator/       Persisted setup/update/remove state machine
  ssh/                OpenSSH adapter, host-key policy, bounded deployment operations
  deployment/         Generated per-instance Compose and release manifests
  vault-core/         Stable reads and export policy
  protocol/           Snapshot and MCP contracts

deploy/
  runtime/            Remote application + tunnel stack template
```

The current dashboard is not incrementally polished. It is replaced by the desktop renderer while the existing backend protocols are reused behind the orchestrator.

## 13. Implementation sequence after approval

### Milestone 1: one local launch

- package the existing local agent behind an Electron shell;
- add native folder selection and Keychain;
- replace the four-step dashboard with the approved setup/ready UI;
- expose one development launch command;
- persist state and resume/background-sync while the Electron process runs;
  expose start-at-login as a user-controlled host setting.

Exit: the app launches once, selects a real vault, and exercises scanning locally with no terminal-facing workflow.

### Milestone 2: SSH orchestrator

- system SSH config/agent discovery;
- host-key confirmation and pinning;
- persisted idempotent setup state machine;
- preflight and redacted journal;
- automatic device binding without visible pairing.

Exit: setup can safely resume after interruption and cannot run arbitrary remote commands from renderer input.

### Milestone 3: shared-VPS runtime

- per-instance rootless/isolated deployment;
- no-port tunnel sidecar;
- quotas, labels, health checks;
- signed/digest-pinned releases;
- update, rollback, and exact-scope removal.

Target exit (requires L3 evidence): collision and uninstall tests pass on a
VPS already running unrelated Compose projects.

### Milestone 4: edge, OAuth, and ChatGPT

- managed Cloudflare edge, owner-browser sign-in, recovery, and Advanced
  operator-managed mode (in-place provider rotation is deliberately deferred);
- OAuth 2.1 and public MCP verification;
- **Copy URL & Open** MCP handoff plus external ChatGPT consent flow;
- direct, indirect, negative, and extraction-resistance prompt tests;
- desktop/web/mobile compatibility matrix.

Target exit (requires L4 account/runtime evidence): a fresh user reaches a
working read-only ChatGPT connection from the packaged app without terminal
commands.

## 14. Acceptance criteria

The product design is satisfied only when:

- a release user starts one application and never opens Terminal;
- after one owner sign-in, normal setup has exactly two inputs: vault and SSH server;
- the selected vault is locally scanned and shows note count/bytes before **Set up** authorizes publication;
- pairing, preview, Docker, tunnel, and keys never become normal UI steps;
- a failed setup is resumable and does not alter unrelated VPS resources;
- no Vault Bridge service publishes a host port in the default shared-VPS mode;
- CPU, memory, PID, body, index, staging, retained-generation, temporary-file, and log ceilings are enforced, with a host free-space floor and host quota where available;
- all secrets are absent from Markdown, UI copy, process arguments, and logs;
- `0600` source secrets are copied by network-disabled init jobs into exact-identity named volumes and mounted read-only by long-running services;
- `/readyz` is dynamic and the managed MCP Worker fails closed with `503` when online edge introspection is unavailable;
- closing the window does not stop background synchronization;
- the VPS can be destroyed without losing the canonical vault;
- the Mac can be offline while ChatGPT reads the last successful replica;
- write tools do not exist in V1;
- connect, update, rollback, pause, and removal each have end-to-end tests.

## 15. Decisions to retain

- **One launch:** accepted.
- **One-page setup:** accepted.
- **Read-only V1:** accepted.
- **Packaged desktop web UI:** Electron, macOS first.
- **Shared VPS:** rootless/isolated runtime by default; existing Docker only as explicit compatibility mode.
- **Networking:** outbound tunnel, no host ports or proxy edits.
- **Synchronization:** signed snapshots over a separate outbound HTTPS publisher route; SSH remains deployment-only.
- **Public access:** managed edge and one owner sign-in are required for the exact two-input setup promise; fully self-hosted edge is Advanced mode.
- **ChatGPT UI:** data-only MCP in V1; no widget.
- **Current dashboard:** replace, do not polish.
