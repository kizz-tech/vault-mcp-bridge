# Release process

Release work must distinguish `prepared`, `validated`, `published`,
`deployed`, `connected`, and `observed`. A manifest or green CI job does not
collapse those states. The repository is Apache-2.0 licensed, and no artifact
is presumed signed, notarized, published, deployed, or connected until the
corresponding evidence exists.

## Local preflight

Run from a clean checkout with Node 24+ and pnpm 10:

```sh
pnpm install --frozen-lockfile
pnpm lint
pnpm typecheck
pnpm test
pnpm build
node scripts/validate-release.mjs
node scripts/validate-compose.mjs deploy/runtime/compose.contract.yaml --strict
node scripts/validate-secure-tunnel-compose.mjs
```

The aggregate `pnpm check` runs these repository checks plus release and
Compose validation. Compose validation is static when a Docker daemon is not
available; a warning about the daemon is not a runtime smoke test.

## Desktop artifact

The unsigned macOS path is always available for local review:

```sh
pnpm --filter @vault-mcp-bridge/desktop package:dir
pnpm --filter @vault-mcp-bridge/desktop package
```

The root pnpm policy permits lifecycle builds only for Electron and esbuild.
DMG-only `fs-xattr` and `macos-alias` remain explicitly ignored during install
and are rebuilt by `prepare:dmg-native` with an allowlisted environment. Do not
move them back to `onlyBuiltDependencies`; `pnpm validate:release` treats that
as a credential-log regression.

Forge writes artifacts under `apps/desktop/out/` (the make output is
`apps/desktop/out/make/`). Unsigned artifacts are not Gatekeeper evidence and
do not validate a ChatGPT account. Signing and notarization are optional,
credential-gated operations; the Forge configuration reads
`VAULT_BRIDGE_OSX_SIGN_IDENTITY`, `VAULT_BRIDGE_APPLE_ID`,
`VAULT_BRIDGE_APPLE_TEAM_ID`, and `VAULT_BRIDGE_APPLE_APP_PASSWORD` from the
CI secret store. The workflow also requires its certificate/password secrets.
Do not place any of those values in source, `.env`, manifests, or logs.

The absence of those credentials is an intentional fail-closed result, not a
reason to call an unsigned package signed or notarized.

Every packaged app must contain
`Contents/Resources/agent/install-agent-command.mjs`. After installing a test
artifact, run its installer, then execute `vault-bridge doctor --json` and
`vault-bridge status --json` from outside the checkout. The command must emit
one JSON object, must not expose paths/hostnames/credentials, and must retain
the `read-only-v1` help contract.

The default desktop loads non-secret Secure Tunnel configuration from
`VAULT_BRIDGE_SECURE_TUNNEL_IMAGE`, then `secure-tunnel-config.json` in
Electron `userData`, then the packaged resources directory. Production image
references must be digest-pinned. Forge embeds this public file only when
`VAULT_BRIDGE_SECURE_TUNNEL_CONFIG_PATH` points to a file named
`secure-tunnel-config.json`. The file contains no tunnel ID or API key.

`VAULT_BRIDGE_PRODUCT_CONFIG_PATH=product-config.json` remains the separate
advanced public HTTPS/OAuth build. Never embed both release modes in one
artifact. A clean-install claim requires a packaged smoke with the chosen
public configuration and synthetic data.

## Container artifacts

The default image combines the read-only stdio MCP server and the official
OpenAI tunnel client:

```sh
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  --file deploy/Dockerfile.secure-tunnel \
  --tag ghcr.io/<owner>/vault-mcp-bridge-secure-tunnel:<version> \
  --push .
```

Record the resulting multi-platform manifest digest and place only
`repository@sha256:<digest>` in `secure-tunnel-config.json`. The image build
pins the Node base, tunnel-client version, and per-architecture release archive
SHA-256. The primary Compose template has one long-running runtime, one
network-disabled secret-init job, no host ports, and two named volumes.

The `Release container` GitHub workflow is manual-only. It runs the repository
checks in one Ubuntu job, grants that job `packages: write`, publishes this one
multi-architecture Secure Tunnel image with provenance and a pinned SBOM
generator, then verifies the returned manifest digest. It has no push, pull
request, schedule, macOS, or legacy image jobs.

The sections below describe advanced public server + edge images that operators
may build themselves.

The server and edge images use their respective pinned base images and
Dockerfiles:

```sh
pnpm docker:build
docker build -f deploy/Dockerfile.edge -t vault-mcp-bridge-edge:local .
```

Advanced public-mode images are intentionally absent from the default workflow.
If a downstream operator publishes them, it must record each immutable
`sha256` digest; a tag or successful build is not a deployment.

The runtime accepts only digest-pinned image references. Generated Compose has
two long-running services plus two network-disabled one-shot secret-init jobs;
SSH/SFTP-uploaded source files are `0600`, copied into per-runtime named volumes
with exact UID/GID and default copy mode `0440`, and mounted read-only by the
owning service. Generated Compose must pass
`node scripts/validate-compose.mjs deploy/runtime/compose.contract.yaml --strict`
as an advanced-mode contract fixture. The primary template must also pass
`node scripts/validate-secure-tunnel-compose.mjs`. Neither validation starts a
container.

## Secret-free release manifest

After producing desktop artifacts, generate and verify the manifest from the
artifact directory:

```sh
node scripts/generate-release-manifest.mjs \
  --artifacts apps/desktop/out/make \
  --output apps/desktop/out/release-manifest.json \
  --version "$RELEASE_VERSION"
node scripts/verify-release-manifest.mjs \
  apps/desktop/out/release-manifest.json apps/desktop/out/make
```

The manifest contains only relative paths, byte counts, SHA-256 digests,
version, commit (when supplied by CI), and generation time. It is not an Apple
signature, notarization ticket, image attestation, or publication record. An
operator may separately verify a cosign signature:

```sh
node scripts/verify-release-manifest.mjs \
  apps/desktop/out/release-manifest.json apps/desktop/out/make \
  --signature apps/desktop/out/release-manifest.sig
```

That mode requires `cosign` and `COSIGN_PUBLIC_KEY_PATH`; the private signing
key never belongs in this repository.

## Promotion gates

| State | Evidence | Still not proven |
| --- | --- | --- |
| Prepared | local artifacts/manifests exist | CI, signing, image publication, runtime |
| Validated | `pnpm check`, manifest, image/Compose checks, SBOM/scan | VPS or edge |
| Published | immutable registry digest and release record | running service |
| Deployed | installation-scoped SSH/Compose receipt, no host ports, `/readyz` | ChatGPT consent/account |
| Connected | OAuth discovery/PKCE, account-level custom MCP, read-only call | long-term reliability/mobile |
| Observed | rollback/revoke/incident and target-client evidence | future changes or provider guarantees |

The evaluation level required for a release must be recorded in a redacted
receipt. Never include bearer tokens, OAuth codes, tunnel/mTLS material, private
keys, raw notes, search queries, or host paths.

## Publication and deployment separation

No release job is authorized to deploy a VPS, change DNS/firewall, link a
ChatGPT account, or publish credentials. The owner/operator performs those
actions through the production runbook and records the result at the relevant
evaluation level. A successful workflow run is repository evidence only.
