# ADR-0004: Separate authentication planes

- **Status:** Accepted for v1
- **Date:** 2026-08-07
- **Decision owners:** Project owner and implementation team

## Context

MCP callers, the local publisher, and the owner’s browser/admin UI have different
capabilities and threat profiles. Reusing one bearer token or putting all
routes behind one middleware would make a leaked client credential an ingest
or admin credential.

## Decision

Use three independently configured trust surfaces, with a separate edge proof
for the public MCP hostname:

1. Public MCP: a managed Cloudflare Worker strips caller-supplied proof
   headers, performs uncached online introspection, fails closed with `503` on
   edge outage, and emits a distinct request-bound MCP-edge HMAC; the VPS then
   performs OAuth 2.1/JWT validation, read-only scopes and quotas.
2. Publisher ingest/status: mTLS/service identity plus device-bound signed
   requests, replay protection, and generation limits.
3. Owner admin: browser OIDC authorization-code + PKCE (or an equivalent
   owner identity provider), CSRF/origin checks, and redacted audit events.

The routes use distinct hostnames/policies in production and the app enforces
per-surface Host allowlists. Explicit development tokens/loopback HTTP are for
synthetic local use only and fail closed when production mode is set.

## Consequences

- Credential revocation is scoped to one surface. OAuth revocation increments
  only the registered client's monotonic epoch (invalidating that client's
  codes, refresh tokens, and access tokens); unrelated clients remain valid.
  The Cloudflare provider's in-place installation rotation currently fails
  closed and requires a future coordinated migration.
- Deployment has more configuration and more tests than a single shared token.
- OAuth, mTLS, tunnel, and keychain integrations are deployment work; examples
  in this repository do not configure them magically.
- Compose file-source secrets are uploaded over SSH/SFTP as deployment-user
  `0600`, copied
  by two network-disabled one-shot init jobs into per-runtime named volumes
  with exact UID/GID and default `0440` mode, and mounted read-only by the
  owning long-running service. The source file is never mounted directly.

## Rejected alternatives

- **One static API key for all routes:** excessive blast radius and poor
  revocation/audit semantics.
- **MCP JWT accepted by ingest:** conflates a model/client identity with a
  local-device signing identity.
