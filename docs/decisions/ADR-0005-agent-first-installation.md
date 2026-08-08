# ADR-0005: Agent-first installation is a bounded product API

Status: accepted
Date: 2026-08-08

## Context

The desktop UI is useful for status and recovery, but requiring non-developers
to understand terminals, Docker, SSH, JSON, and ChatGPT MCP configuration makes
self-hosting inaccessible. A copied Codex prompt can remove that burden, but a
long prompt containing shell commands and secrets would drift across releases
and create an unsafe remote-instruction channel.

## Decision

Vault Bridge publishes three coordinated surfaces:

1. a short copyable prompt that authorizes one canonical versioned runbook;
2. a machine-readable local command with predictable redacted JSON;
3. the desktop UI as the owner-visible status, activity, consent, and recovery
   surface.

Configuration is two-phase. `prepare` accepts a strict non-secret plan and a
runtime key only on stdin, validates local inputs, and returns the candidate SSH
fingerprint. `setup` accepts only the exact owner-approved fingerprint and then
uses the same application backend as the GUI. The command exposes no arbitrary
shell, path-read, server-command, vault-write, or destructive operation.

The app remains the single owner of encrypted credentials, host pins,
deployment invariants, and sync state. The agent command does not reimplement
those rules. Public release installation prefers signed/notarized artifacts;
source build is an explicit fallback approval.

## Consequences

- Non-developers can delegate routine setup without delegating account consent
  or server identity decisions.
- Prompts stay small while the runbook and command contract evolve with code.
- Agents can diagnose with `doctor`, `status`, and `journal` from any directory.
- Runtime keys do not enter prompts, argv, setup JSON, Markdown, or logs.
- The current product remains macOS-first and read-only; cross-platform
  packaging and write support require separate decisions.
