# ADR-0001: Read-only one-way immutable snapshots

- **Status:** Accepted for v1
- **Date:** 2026-08-07
- **Decision owners:** Project owner and implementation team

## Context

The local Obsidian vault is the owner’s canonical data and may be open in
Obsidian/iCloud on more than one device. A remote MCP integration needs a
replaceable projection without gaining the ability to modify or delete source
files. Incremental remote mutations would create conflict resolution,
authorship, and recovery semantics before the read path is proven.

## Decision

The local agent scans allowlisted vault files and publishes complete, signed
generations. The server validates and indexes a staged generation, then
atomically activates one generation. The server cannot write, delete, rename,
or arbitrarily read a local file. The local vault remains canonical; remote
generations and indexes are disposable.

## Consequences

- A partial upload cannot become the active result.
- Search/fetch responses can carry one generation id and provenance metadata.
- Initial syncs use more bandwidth than mutation deltas, but retries are
  idempotent and the consistency model is explicit.
- Future write support requires a new ADR covering conflict resolution,
  approvals, audit, and recovery; it must not be added by widening v1 tools.

## Rejected alternatives

- **Server writes directly to the vault:** violates ownership and requires an
  inbound desktop channel.
- **Unbounded file-by-file remote mutations:** can leave a mixed generation and
  makes rollback difficult.
