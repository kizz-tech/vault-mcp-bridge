# ADR-0003: No server-initiated control channel in v1

- **Status:** Accepted for v1
- **Date:** 2026-08-07
- **Decision owners:** Project owner and implementation team

## Context

The user wants current data from a phone, desktop, and ChatGPT, but an inbound
WebSocket or long-lived server connection to a personal computer would enlarge
the attack surface and invite remote command ambiguity. Read-only snapshots do
not require it.

## Decision

The local agent makes outbound publisher requests and may poll for status. The
server never initiates commands, sends arbitrary paths, or executes a callback
on the agent. The dashboard runs on loopback. If a later feature needs
bidirectional control, it must introduce a separate, explicitly authorized
protocol with user approval, capability allowlists, audit, expiry, and a new
threat model.

## Consequences

- No open inbound port is needed on the owner’s computer.
- Mobile/ChatGPT access uses the remote projection, not a live desktop tunnel.
- A user may need to wait for the next outbound publish to see changes.
- “Bidirectional” in product language currently means data/status flows in
  both directions at separate trust boundaries, not remote execution.

## Rejected alternatives

- **WebSocket command bus:** unnecessary for read-only sync and difficult to
  secure against replay, authorization drift, and compromised servers.
- **Reverse SSH/control tunnel:** overpowered for the product boundary and
  creates a credential with broad blast radius.
