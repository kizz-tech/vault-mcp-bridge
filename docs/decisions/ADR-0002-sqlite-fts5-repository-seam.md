# ADR-0002: SQLite FTS5 behind a repository seam

- **Status:** Accepted for v1
- **Date:** 2026-08-07
- **Decision owners:** Project owner and implementation team

## Context

The first deployment is a single-owner VPS replica. It needs bounded full-text
search and simple backup/restore without operating a separate database cluster.
The index is derived from immutable generations and may be rebuilt.

## Decision

Use SQLite with FTS5 for v1 indexing. Keep MCP and service code dependent on a
`SnapshotRepository`/search interface rather than SQLite-specific SQL. Store
generation metadata and active-pointer state transactionally; rebuild indexes
from the canonical snapshot when necessary.

## Consequences

- Small operational footprint and straightforward local tests.
- FTS query syntax must be validated/escaped and bounded to avoid expensive
  queries.
- Write concurrency and horizontal scaling are intentionally limited.
- A future Postgres or dedicated search implementation can replace the adapter
  without changing `search`, `fetch`, or provenance fields.

## Rejected alternatives

- **Postgres first:** useful at scale, but adds operations and a new failure
  surface before the single-owner contract is validated.
- **In-memory index only:** loses durability and makes restart behavior
  surprising.
