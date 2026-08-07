# Vault Bridge edge

`@vault-mcp-bridge/edge` is the control-plane boundary for one read-only Vault
Bridge installation. It owns installation metadata, OAuth authorization and
tunnel/provider references. It never stores or returns vault contents.

The service exposes only opaque `SecretReference` values in endpoint bundles.
Tunnel and publisher mTLS values stay in the injected `CredentialVault`; the
renderer and MCP client do not receive them.

## Local verification

The test provider is deterministic and is selected for `development`/`test`:

```sh
EDGE_ORIGIN=https://edge.example.test \
EDGE_ISSUER=https://edge.example.test \
EDGE_DEV_OWNER_TOKEN=local-owner-token \
EDGE_DEV_OWNER_ID=local-owner \
pnpm --filter @vault-mcp-bridge/edge dev
```

Use a TLS reverse proxy for any endpoint that leaves the machine. The contract
intentionally requires HTTPS endpoint and issuer URLs even when the provider is
the local deterministic adapter.

## Production boundary

Production startup fails closed unless all of the following are supplied by
the embedding control plane:

- HTTPS edge origin and issuer;
- owner IdP issuer, audience and an offline public JWKS bundle;
- a durable OAuth signing-key result (`oauthSigningKey` or an injected
  `OAuthService`), never an ephemeral process key;
- a concrete tunnel provider implementation. The built-in external adapter is
  credential-gated and performs no provider API calls.

OAuth metadata advertises authorization-code + PKCE (`S256`), exact redirect
URI allowlists, resource indicators, refresh-token rotation and public JWKS.
Authorization codes are short-lived and one-use. Access tokens carry the
installation, vault, client, resource, subject and `vault:read` bindings.

The desktop main process can request a one-use 60-second credential lease with
an ephemeral X25519 public key. Redemption returns only an
X25519/HKDF/AES-GCM envelope; the renderer is never given tunnel, mTLS or edge
attestation plaintext. Production also requires a durable edge-store adapter;
the in-memory store is test/development-only.

Installation provisioning accepts an opaque `Idempotency-Key` header. Replays
for the same owner and vault return the original installation; a key reused
for another vault is rejected without revealing the existing installation.
Control-plane state and request rates are bounded; expired codes, sessions,
leases and revoked-token entries are reclaimed before new state is accepted.
