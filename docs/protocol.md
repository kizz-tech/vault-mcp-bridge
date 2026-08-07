# Protocol contract

This document describes the read-only wire contract implemented by the server,
edge, publisher, and MCP adapter. Internal implementation may change, but a
deployed installation must preserve the authorization boundaries and versioned
fields. Examples use synthetic values only. Timestamps in JSON are ISO-8601
UTC; signed-request `timestamp` values are Unix seconds.

## Surfaces and paths

The installation has three distinct HTTP surfaces. The edge maps them to
separate hostnames; they must not share credentials or route policy.

| Surface | Paths | Caller | Authentication |
| --- | --- | --- | --- |
| Public MCP | `POST /mcp`, `GET /.well-known/oauth-protected-resource[/mcp]` | ChatGPT/MCP client | Cloudflare Worker online introspection + distinct MCP-edge HMAC, then OAuth bearer token; `vault:read`; installation/vault/client binding |
| Publisher ingest/status | `POST /v1/snapshots`, `GET /v1/status`, internal bootstrap `POST /v1/pairing/consume` | Desktop publisher | edge mTLS + attestation, then device Ed25519 signature and nonce |
| Owner/edge control | `/v1/owner/session`, `/v1/installations…`, credential leases, OAuth discovery/authorization/token/revoke | Desktop/owner/ChatGPT consent | owner identity/session or OAuth code + PKCE |

`GET /healthz` is a liveness check. `GET /readyz` is a dynamic readiness check
and must return `503` when the active store, authentication configuration,
installation binding, required secret files, or current offline-authentication
freshness is unavailable. The MCP Worker separately returns `503` when its
uncached online edge-introspection decision cannot be made. A health response
is not evidence that a public endpoint or ChatGPT account is connected.

The preferred public transport is MCP Streamable HTTP over HTTPS. The server
uses the official MCP TypeScript SDK's stateless adapter and keeps the same
auth and limits for compatibility modes. See the [OpenAI MCP guidance](https://developers.openai.com/api/docs/mcp), [MCP server building](https://developers.openai.com/plugins/build/mcp-server), and the [MCP transport specification](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports).

## Normal setup versus legacy pairing

In the normal Electron flow, the owner signs in, chooses a vault, enters an
SSH target, and selects **Set up**. The orchestrator obtains installation
metadata and credential references, provisions the server, binds the publisher
device, uploads the first snapshot, and verifies the endpoint. No code or
token is copied by the owner.

The pairing route and CLI below are retained for the legacy developer harness
and migration tests. They are not owner-facing onboarding, are not MCP login,
and do not authorize a production deployment by themselves. Production setup
must provision edge mTLS/service identity and an offline OAuth verification
bundle in addition to the device binding. If the desktop crashes after a
successful consume response but before committing local state, it may retry
with a fresh one-use code for the same installation/vault/public key; the
server returns the existing device idempotently. A different or revoked key
remains a `409` conflict.

## Owner sign-in and MCP OAuth

The owner identity plane and MCP authorization server are separate concerns.
The desktop owner sign-in uses authorization-code + PKCE in the system browser:

1. create a random `state`, nonce, and code verifier;
2. bind a temporary protected loopback callback;
3. accept exactly one matching short-lived authorization code; and
4. exchange it over HTTPS, keeping bearer tokens out of URLs and renderer state.

The edge's OAuth metadata (`GET /.well-known/oauth-authorization-server`) advertises:

- authorization-code and refresh-token grants;
- public clients (`token_endpoint_auth_method=none`);
- `code_challenge_methods_supported: ["S256"]`;
- resource indicators bound to the installation's exact MCP URL; and
- one scope, `vault:read`.

The edge owner browser plane is exposed at `GET /owner/login` and
`GET /owner/callback`. It uses the configured owner OIDC issuer, authorization
URL, client id, token endpoint, and JWKS (`EDGE_OWNER_ISSUER`,
`EDGE_OWNER_AUTHORIZATION_URL`, `EDGE_OWNER_CLIENT_ID`,
`EDGE_OWNER_TOKEN_ENDPOINT`, `EDGE_OWNER_JWKS`) with authorization-code + PKCE;
the callback creates a bounded owner session. This owner-browser session is
distinct from MCP OAuth.

The client registration endpoint is `POST /oauth/register`. A registration is
bound to one installation and exact HTTPS (or loopback HTTP) redirect URI list.
The authorization endpoint is `GET /oauth/authorize`; it requires the owner
session, validates state/resource/redirect URI/PKCE inputs, and returns a
one-use code. The token endpoint is `POST /oauth/token` with either
`grant_type=authorization_code` or `grant_type=refresh_token`. Access tokens
are short-lived and refresh tokens rotate. `POST /oauth/revoke` is idempotent
for unknown values. Revocation is client-scoped: incrementing the registered
client's monotonic `revocationEpoch` invalidates every authorization code,
refresh token, and access token issued to that client, while leaving unrelated
clients active; the client registration itself remains available for a fresh
authorization.

The server validates every MCP bearer token with issuer, audience, algorithm,
expiry, scope, subject, installation, vault, and client claims. The default
production path mounts an offline verification bundle at `JWT_JWKS_FILE` (or
`JWT_JWKS_JSON` for a controlled test); the bundle must carry matching issuer,
audience, `issuedAt`, `expiresAt`, and public keys. A raw keys-only JWKS is an
explicit `JWT_ALLOW_RAW_JWKS=true` exception. Remote JWKS fetching is disabled
unless an operator separately enables `JWT_ALLOW_REMOTE_JWKS=true` with an
HTTPS `JWT_JWKS_URL`. An MCP JWT cannot publish a snapshot or call owner APIs.

OpenAI's authentication details are documented in [app/plugin authentication](https://developers.openai.com/plugins/build/auth). Vault Bridge does not embed ChatGPT. **Copy URL & Open** copies the exact HTTPS MCP resource and opens ChatGPT; the custom MCP connection is completed through ChatGPT Web/the account surface when that capability is available to the target account/workspace. Desktop Web setup does not prove native mobile availability; verify the target client/account separately.

## MCP edge authentication

The managed MCP hostname is a Cloudflare Worker route. It strips any incoming
MCP-proof headers, performs an uncached online introspection against the edge
authorization state for the presented bearer token, and returns `503` without
forwarding if the edge is unavailable or the decision is stale. After a
successful decision it adds a distinct HMAC attestation over method,
path/query, host, bearer-token digest, timestamp, and nonce. The VPS verifies
that proof before normal OAuth/JWT validation. The server-side settings are
`MCP_EDGE_ATTESTATION_SECRET_FILE`, `MCP_EDGE_ATTESTATION_HEADER`,
`MCP_EDGE_TIMESTAMP_HEADER`, `MCP_EDGE_NONCE_HEADER`, and bounded
`MAX_MCP_EDGE_ATTESTATION_ENTRIES`; this secret is not the publisher
mTLS/attestation secret.

## Publisher edge authentication

The managed production edge implementation is Cloudflare-specific. Provisioning
creates an installation-scoped Cloudflare Tunnel and DNS records in a dedicated
zone, issues the publisher client certificate from the Mac-generated CSR, and
deploys a Worker route that verifies that certificate and emits the keyed edge
attestation. The edge retains the Cloudflare account token and all resulting
credentials; the desktop receives only one-use installation leases. This is an
implementation contract, not evidence that a Cloudflare account or route is
currently live.

Publisher requests first pass through the private ingest hostname. The edge
must terminate an installation-scoped client certificate (mTLS/service
identity), set the configured certificate-status header, and add a keyed
attestation header. The server defaults are:

```text
PUBLISHER_MTLS_REQUIRED=true
PUBLISHER_EDGE_ATTESTATION_HEADER=x-vmb-edge-attestation
PUBLISHER_EDGE_CERT_STATUS_HEADER=x-vmb-edge-mtls-status
PUBLISHER_EDGE_CERT_STATUS=verified
PUBLISHER_EDGE_TIMESTAMP_HEADER=x-vmb-edge-timestamp
PUBLISHER_EDGE_NONCE_HEADER=x-vmb-edge-nonce
PUBLISHER_EDGE_ATTESTATION_SECRET_FILE=/run/secrets/<edge-attestation>
```

The edge attestation is an HMAC-SHA-256 over six newline-separated values:
HTTP method, exact request URL/path, lower-case Host, certificate status,
decimal Unix timestamp, and an edge nonce. The server checks timestamp skew,
constant-time signature equality, and bounded nonce replay
(`MAX_PUBLISHER_EDGE_ATTESTATION_ENTRIES`, default 10,000). A bare
client-supplied status header is not sufficient. The attestation secret is
distinct from the Mac publisher mTLS private key and from the tunnel token;
each is installation scoped and revocable. The concrete Cloudflare provider's
in-place installation `rotate` operation currently fails closed because it
needs a coordinated desktop/VPS migration; revoke and reprovision instead.

After edge verification, the server validates the device's Ed25519 signed
request. This two-layer check prevents a direct request from bypassing edge
mTLS and prevents a valid ChatGPT OAuth token from publishing.

Cloudflare provisioning and revocation are serialized per installation and
for dedicated-zone hostname-association replacement inside the single edge
writer. The provider checkpoints each external mutation in a durable cleanup
journal. A retry reconciles that journal before allocating new resources;
delete-404 is treated as already removed, but any other cleanup failure stays
visible and prevents the installation from being reported fully revoked.
This journal closes the normal crash/retry path but cannot coordinate another
edge process or an out-of-band Cloudflare administrator. These statements are
source/contract behavior, not evidence that an account or route is deployed.

## Legacy device bootstrap

The current server slice retains `POST /v1/pairing/consume` for synthetic and
migration use. The request schema is:

```json
{
  "version": 1,
  "pairCode": "synthetic-one-use-code",
  "agentId": "agent_synthetic_0001",
  "vaultId": "vault_synthetic_0001",
  "publicKey": "base64url-ed25519-spki",
  "label": "synthetic-dev-agent"
}
```

The response binds a generated device id to the vault and returns the publisher
origin. Pair codes are short-lived and single-use (default TTL 600 seconds).
They are generated only by the legacy CLI:

```sh
pnpm --filter @vault-mcp-bridge/server pairing-code -- --vault-id <synthetic-id>
```

Device revocation in the harness is:

```sh
pnpm --filter @vault-mcp-bridge/server revoke-device -- --device-id <opaque-id>
```

The private Ed25519 key never crosses the desktop boundary. The current
desktop adapter may invoke this pairing route internally to bind the device,
while mTLS/attestation material is obtained through edge credential leases and
Keychain adapters; the owner never receives or copies the pair code. Do not
turn the pair code into a normal-user step.

## Signed publisher requests

`POST /v1/snapshots` carries a complete generation in this envelope:

```json
{
  "deviceId": "device_synthetic_0001",
  "vaultId": "vault_synthetic_0001",
  "timestamp": 1786103970,
  "nonce": "synthetic-random-nonce-0001",
  "signature": "base64url-ed25519-signature",
  "snapshot": {
    "version": 1,
    "snapshotId": "32f9f08e-6c2c-4b42-9a0c-cc1d1c3cf7b2",
    "vaultId": "vault_synthetic_0001",
    "generation": 3,
    "createdAt": "2026-08-07T11:59:30.000Z",
    "documents": [],
    "digest": "base64url-sha256-digest"
  }
}
```

The exact signed UTF-8 payload is five newline-separated values:

```text
POST
/v1/snapshots
<timestamp>
<nonce>
<snapshot.digest>
```

`GET /v1/status` uses the same fields in headers and signs
`GET`, `/v1/status`, timestamp, nonce, and the SHA-256 digest of the requested
vault id. The server rejects unknown/revoked devices, vault mismatches,
invalid signatures, duplicate nonces, timestamps outside
`MAX_CLOCK_SKEW_SECONDS` (default 300 seconds), malformed fields, and bodies
over `MAX_BODY_BYTES`/`MAX_SNAPSHOT_BYTES`. Nonces are retained longer than
the acceptance window (`NONCE_RETENTION_SECONDS`, default 86,400 seconds).

## Snapshot and activation contract

The snapshot schema is version 1:

```json
{
  "version": 1,
  "snapshotId": "uuid",
  "vaultId": "opaque-id",
  "generation": 3,
  "createdAt": "2026-08-07T11:59:30.000Z",
  "documents": [
    {
      "id": "opaque-document-id",
      "title": "Synthetic example",
      "mediaType": "text/markdown",
      "text": "# Fixture text",
      "sourceHash": "base64url-sha256-of-text",
      "modifiedAt": "2026-08-07T11:59:20.000Z",
      "metadata": {"topic": "fixture"}
    }
  ],
  "digest": "base64url-sha256-of-canonical-snapshot"
}
```

Only allowlisted textual formats are accepted: Markdown, Obsidian Canvas JSON,
and Obsidian Bases YAML. There is no source-path field and no absolute vault
root. IDs are opaque; hidden/system directories, symlinks, NUL/absolute path
values, duplicate IDs, overlarge text, and unsupported media types are
rejected. User-authored relative links remain ordinary text and are not
instructions.

The server validates every document's `sourceHash` and the canonical snapshot
digest, checks storage limits, writes a staging generation and FTS5 index, and
advances the active pointer in one transaction. A partial upload cannot become
searchable. V1 retains the active generation and at least one rollback
generation. A retry with the same active snapshot id/digest/generation is
idempotent; a reused id with different content or a stale generation is
rejected.

Successful ingest returns `202` for a newly accepted generation and `200` for
an idempotent active retry:

```json
{
  "version": 1,
  "accepted": true,
  "idempotent": false,
  "snapshotId": "32f9f08e-6c2c-4b42-9a0c-cc1d1c3cf7b2",
  "vaultId": "vault_synthetic_0001",
  "generation": 3,
  "documentCount": 2,
  "digest": "base64url-sha256-digest",
  "receivedAt": "2026-08-07T11:59:32.000Z"
}
```

## MCP tools

`POST /mcp` exposes exactly two tools. The server registers the official SDK
annotations `readOnlyHint: true`, `destructiveHint: false`,
`idempotentHint: true`, and `openWorldHint: false`.

### `search`

Input is exactly `{ "query": "bounded text" }`. The query is UTF-8 bounded by
`MAX_SEARCH_QUERY_BYTES` (default 512 bytes and no more than 512 characters),
treated as search data rather than instructions, and limited to
`MAX_SEARCH_RESULTS` (default 10).

```json
{
  "results": [
    { "id": "opaque-document-id", "title": "Synthetic example", "url": "" }
  ]
}
```

### `fetch`

Input is exactly `{ "id": "opaque-document-id" }`. The response is bounded by
`MAX_FETCH_BYTES` (default 256 KiB) and contains no machine path:

```json
{
  "id": "opaque-document-id",
  "title": "Synthetic example",
  "text": "# Fixture text",
  "url": "",
  "metadata": {"topic": "fixture"}
}
```

An empty `url` means the deployment has no safe, user-openable HTTPS viewer;
it is not a promise that an absolute filesystem citation exists. Sync status
is available through the signed publisher `GET /v1/status` response and the
desktop journal, not as a third model-facing tool.

## Limits and errors

The exact server settings are loaded by `apps/server/src/config.ts` and are
also represented in `.env.example` and generated Compose. The production
deployment must set (at minimum) `MAX_BODY_BYTES`, `MAX_VAULT_BYTES`,
`MAX_DATABASE_BYTES`, `MAX_INDEX_BYTES`, `MAX_TEMP_BYTES`, `MIN_FREE_BYTES`,
and `MAX_RETAINED_GENERATIONS`; the deployment validator requires at least two
retained generations. Edge/request rate settings are
`REQUEST_RATE_PER_MINUTE`, `REQUEST_BURST`, `MAX_CONCURRENT_PER_PRINCIPAL`,
`MAX_PRINCIPAL_BUCKETS`, `PRINCIPAL_BUCKET_TTL_SECONDS`, and
`MAX_PUBLISHER_EDGE_ATTESTATION_ENTRIES`, plus the managed MCP-edge settings
`MCP_EDGE_ATTESTATION_SECRET_FILE`, `MCP_EDGE_ATTESTATION_HEADER`,
`MCP_EDGE_TIMESTAMP_HEADER`, `MCP_EDGE_NONCE_HEADER`, and
`MAX_MCP_EDGE_ATTESTATION_ENTRIES`.

These guards are bounded in each server/edge process; the protocol does not
promise a global distributed rate limiter. Production edge state is file-backed
and single-writer, so one edge process must own a given state file.

HTTP errors intentionally reveal only a safe class (`invalid request`,
`publisher authentication failed`, `authentication unavailable`,
`rate limit exceeded`, `snapshot exceeds …`). Logs and journals must not copy
tokens, note text, search queries, signatures, private paths, or raw upstream
headers.

## Compatibility and evolution

The MCP SDK/transport version is a deployment choice and must be verified
against the target client. Compatibility adapters may not bypass OAuth,
publisher attestation, rate limits, or the read-only tool list. Any future
write, export, or command capability requires a new versioned authorization
and audit contract; it must not be smuggled into `fetch` or the legacy pairing
surface.
