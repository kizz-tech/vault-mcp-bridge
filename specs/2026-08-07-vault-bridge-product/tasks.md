# Tasks

| ID | Task | Owner layer | Dependencies | Status |
| --- | --- | --- | --- | --- |
| T01 | Establish execution package and repository hygiene | Release | — | complete (local) |
| T02 | Define orchestration, deployment, and edge contracts | Orchestration | T01 | complete (local) |
| T03 | Implement resumable setup orchestrator and SSH deployment adapter | Orchestration, Deployment | T02 | complete (local) |
| T04 | Implement isolated generated Compose stack, two network-disabled secret-init jobs, and lifecycle commands | Deployment | T02 | complete (local) |
| T05 | Implement owner/installation edge service, owner-browser OIDC, durable files, stable signer, Cloudflare provider, and distinct managed MCP Worker attestation | Edge | T02 | complete (local) |
| T06 | Integrate Mac publisher identity, automatic enrollment, and background sync | Desktop / publisher | T02, T03, T05 | complete (local) |
| T07 | Build one-page desktop UI and safe Electron shell | Desktop | T02, T06 | complete (local) |
| T08 | Add desktop packaging, Docker images, CI, and operator documentation | Release | T04, T05, T07 | complete (local) |
| T09 | Run full verification, spec audit, and security review | All | T03–T08 | complete (local + synthetic VPS compatibility; L4 production acceptance remains a release gate) |

## Parallelization

- T03, T04, T05 can proceed after T02 with disjoint paths.
- T07 can build against contract fakes while T03/T05 finish.
- One verifier owns repository-wide checks after implementation lanes finish.

## T09 verification boundary

- The final root check passed lint, typecheck, 193 tests across 27 files,
  build, strict Compose validation, and release hygiene.
- macOS packaging produced one app, DMG, and ZIP. Artifact integrity, ad-hoc
  code signature, Electron fuses, ATS, and the release manifest passed. A
  clean-install launch was not performed.
- Synthetic Germany shared-VPS rootful compatibility passed server
  health/readiness, no-host-port, nonroot/read-only, internal-network, and
  network-disabled secret-init checks with exact cleanup.
- A second retain→remove drill proved that only the replica was retained first,
  then removed exactly; credential volumes, staging, task resources, images,
  and archive were cleaned. No real vault or persistent test resource was
  used.
- L4 production acceptance is still a release gate: live Cloudflare/OIDC,
  ChatGPT/mobile, signing/notarization, configured-package, and rootless-remote
  evidence is absent.
