import { createHash } from "node:crypto";
import { CONTRACT_VERSION, normalizeVaultId, type InstallationState, type SetupStage } from "@vault-mcp-bridge/contracts";
import type { ServerCopyDisposition, SetupRecord } from "./types.js";

const OPAQUE_ID_RE = /^[A-Za-z0-9_-]{16,256}$/u;

/** Convert rich local orchestration state to the renderer-safe product state. */
export function toInstallationState(record: SetupRecord): InstallationState {
  const stage = publicStage(record);
  const status = publicStatus(record);
  const result: InstallationState = {
    version: CONTRACT_VERSION,
    installationId: normalizeOpaqueId(record.installationId, "installation"),
    vaultId: normalizeVault(record.request.vault.vaultId),
    stage,
    status,
    serverCopy: serverCopyDisposition(record),
    sshTarget: {
      host: record.request.server.host,
      user: record.request.server.user,
      port: record.request.server.port ?? 22,
      ...(record.request.server.hostKeyFingerprint === undefined
        ? {}
        : { hostKeyFingerprint: record.request.server.hostKeyFingerprint })
    },
    updatedAt: record.updatedAt
  };
  if (record.edge?.endpointBundle !== undefined && record.endpoint !== undefined) result.endpoint = record.edge.endpointBundle;
  if (record.snapshot !== undefined) {
    result.lastPublishedAt = record.snapshot.publishedAt;
    result.lastGeneration = record.snapshot.generation;
  } else if (record.sync.last !== undefined) {
    result.lastPublishedAt = record.sync.last.publishedAt;
    result.lastGeneration = record.sync.last.generation;
  }
  if (record.attention !== undefined) {
    result.failure = {
      code: mapFailureCode(record.attention.code),
      retryable: record.attention.retryable,
      occurredAt: record.attention.at
    };
  }
  return result;
}

/** Derive old prerelease records conservatively; never invent cleanup scope. */
export function serverCopyDisposition(record: SetupRecord): ServerCopyDisposition {
  if (record.replicaCleanup !== undefined) return "retained";
  if (record.edge !== undefined || record.staged !== undefined || record.deployment !== undefined) return "active";
  if (record.serverCopy !== undefined) return record.serverCopy;
  if (record.journal.some((entry) => entry.event === "server-copy-removed")) return "none";
  const disconnected =
    record.phase === "idle" &&
    record.resumePhase === undefined &&
    record.attention === undefined &&
    record.preview === undefined &&
    record.preflight === undefined &&
    record.edge === undefined &&
    record.staged === undefined &&
    record.deployment === undefined &&
    record.device === undefined &&
    record.snapshot === undefined &&
    record.endpoint === undefined &&
    record.journal.some((entry) => entry.event === "disconnected");
  return disconnected ? "unknown" : "none";
}

function publicStage(record: SetupRecord): SetupStage {
  if (record.phase !== "needs-attention") return record.phase;
  return record.resumePhase ?? "idle";
}

function publicStatus(record: SetupRecord): InstallationState["status"] {
  if (record.phase === "needs-attention") return "needs-attention";
  if (record.sync.paused) return "paused";
  if (record.phase === "ready") return "ready";
  return "idle";
}

function normalizeVault(value: string): string {
  try {
    return normalizeVaultId(value);
  } catch {
    return normalizeOpaqueId(value, "vault");
  }
}

export function normalizeOpaqueId(value: string, prefix: string): string {
  const candidate = value.trim();
  if (OPAQUE_ID_RE.test(candidate)) return candidate;
  const digest = createHash("sha256").update(prefix + ":" + candidate).digest("base64url");
  return prefix + "_" + digest;
}

function mapFailureCode(value: string): NonNullable<InstallationState["failure"]>["code"] {
  const allowed = new Set<NonNullable<InstallationState["failure"]>["code"]>([
    "vault-missing",
    "ssh-failed",
    "host-key-changed",
    "docker-unavailable",
    "insufficient-capacity",
    "deployment-failed",
    "sync-blocked",
    "server-offline",
    "oauth-not-linked",
    "cancelled",
    "internal"
  ]);
  return allowed.has(value as NonNullable<InstallationState["failure"]>["code"])
    ? (value as NonNullable<InstallationState["failure"]>["code"])
    : "internal";
}
