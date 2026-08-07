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

The desktop loads non-secret product configuration in this order: `VAULT_BRIDGE_*`
environment variables, then `product-config.json` in Electron `userData`, then
`product-config.json` in packaged resources. Forge embeds a public file only
when `VAULT_BRIDGE_PRODUCT_CONFIG_PATH` points to a file named
`product-config.json`; it must not contain tokens, private keys, or lease
material. Without real managed-edge/OIDC/image-digest inputs the current
release candidate is intentionally unconfigured. A clean-install one-launch
claim therefore requires a separately recorded configured packaged smoke.

## Container artifacts

The server and edge images use their respective pinned base images and
Dockerfiles:

```sh
pnpm docker:build
docker build -f deploy/Dockerfile.edge -t vault-mcp-bridge-edge:local .
```

The release workflow builds both `linux/amd64` and `linux/arm64`, emits SBOM
and provenance attestations, and scans each platform from an immutable OCI
archive with Trivy. Matrix build/scan jobs are read-only and upload the archives
plus checksums as workflow artifacts. A workflow dispatch must explicitly set
the `publish` input; only after both matrix scans pass does one non-matrix job
receive registry write authority, revalidate both archives and manifest digests,
and copy the exact candidates to GHCR with digest preservation. Record each
immutable `sha256` digest; a tag or successful build is not a deployment.

The runtime accepts only digest-pinned image references. Generated Compose has
two long-running services plus two network-disabled one-shot secret-init jobs;
SSH/SFTP-uploaded source files are `0600`, copied into per-runtime named volumes
with exact UID/GID and default copy mode `0440`, and mounted read-only by the
owning service. Generated Compose must pass
`node scripts/validate-compose.mjs deploy/runtime/compose.contract.yaml --strict`
as a contract fixture and the deployment package's tests. The fixture is not a
deployable production file.

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
