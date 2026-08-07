# Release-candidate verification — 2026-08-07

Status: implementation complete; local and synthetic VPS compatibility accepted.
L4 production acceptance remains a release gate.

## Evidence recorded

- The final root check passed lint, typecheck, 193 tests across 27 files,
  build, strict Compose validation, and release hygiene.
- macOS packaging produced one app, one DMG, and one ZIP. `hdiutil`/ZIP
  integrity, ad-hoc code-signature verification, locked Electron fuses, ATS,
  and a SHA-256 release manifest covering both distributables passed.
- Both GitHub workflows pass `actionlint`; external Actions and privileged
  helper images are immutable-pinned. A disposable two-registry drill proved
  that a multi-architecture manifest can be copied without changing its digest,
  and all local drill containers, volumes, and images were removed. The final
  workflow uses a stronger boundary: read-only matrix jobs upload scanned OCI
  archives, then one dependent job receives GHCR write authority, verifies both
  archives and their manifest digests, and publishes both exact candidates.
- A local transport smoke built a synthetic `linux/amd64` + `linux/arm64` OCI
  index with provenance/SBOM attestations and copied it through the pinned
  Skopeo image into an isolated registry with `--preserve-digests`. The source
  and destination index digest matched exactly; the builder, registry, network,
  helper images, and temporary archive were then removed.
- Synthetic Germany shared-VPS rootful compatibility acceptance passed server
  health/readiness, no host ports, nonroot/read-only mounts, the internal
  network boundary, and network-disabled secret-init jobs with expected
  permissions.
- A second retain→remove drill passed: the first operation retained only the
  replica; the follow-up removed that exact replica. Credential volumes and
  staging files were removed, and all task resources, images, and archive data
  were cleaned.

No real vault was used, and no persistent test resource remains.

## Release boundary

The following are intentionally not claimed or exercised: a live Cloudflare
account or OIDC provider; ChatGPT, mobile, or other L4 production acceptance;
Developer ID signing or notarization; a configured generic package; and a
rootless remote runtime. No commit, push, publication, or external deployment
receipt exists.

The generic package remains intentionally unconfigured until managed-edge,
OIDC, and image-digest inputs are supplied. A clean-install launch smoke is
still required before claiming verified one-launch installation on a fresh Mac.

## Follow-up — 2026-08-08

- The repository was relocated from the legacy workspace to the canonical Kizz
  project workspace. No source or documentation reference to the former path
  remains.
- A real `pnpm dev` startup exposed and fixed two failures not covered by the
  earlier artifact-structure checks: CommonJS dynamic requires inside the ESM
  main bundle, and renderer lookup relative to the wrong development app root.
  The live window was inspected and showed the Vault, Server, and Set up
  controls from `vaultbridge://app/index.html`.
- Packaged execution exposed an enabled browser-specific V8 snapshot fuse
  without the required custom snapshot. The fuse is now disabled and the
  artifact verifier launches each packaged `.app` in a bounded main-module
  smoke mode before accepting DMG/ZIP output.
- The follow-up root check again passed lint, typecheck, all 193 tests, build,
  Compose validation, and release hygiene. The rebuilt app, DMG, ZIP, ad-hoc
  signature, Electron fuses, ATS, packaged main smoke, and two-artifact release
  manifest passed.

This follow-up proves local source launch and packaged main-module launch on the
current Mac. It still does not prove a configured clean-install onboarding,
live ChatGPT connection, Developer ID signing, notarization, or production
deployment.
