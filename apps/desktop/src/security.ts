import { isAbsolute, relative, resolve, sep } from "node:path";

export const IPC_CHANNELS = Object.freeze([
  "state:get",
  "state:changed",
  "vault:choose",
  "server:configure",
  "tunnel:configure",
  "setup:start",
  "sync:now",
  "sync:set-paused",
  "journal:list",
  "settings:get-start-at-login",
  "settings:set-start-at-login",
  "chatgpt:connect",
  "owner:connect",
  "deployment:update",
  "security:disconnect",
  "security:remove-server-copy",
  "external:open"
] as const);

export type IpcChannel = (typeof IPC_CHANNELS)[number];

export function isIpcChannel(value: string): value is IpcChannel {
  return (IPC_CHANNELS as readonly string[]).includes(value);
}

export function isAllowedAppUrl(value: string): boolean {
  try {
    const url = new URL(value);
    return url.protocol === "vaultbridge:" && url.hostname === "app" && !url.username && !url.password;
  } catch {
    return false;
  }
}

export function isAllowedExternalUrl(value: string): boolean {
  try {
    const url = new URL(value);
    return url.protocol === "https:" && !url.username && !url.password && !url.hash && !url.search;
  } catch {
    return false;
  }
}

export function isAllowedMcpResourceUrl(value: string): boolean {
  try {
    const url = new URL(value);
    return url.protocol === "https:" && !url.username && !url.password && url.pathname === "/mcp" && !url.search && !url.hash;
  } catch {
    return false;
  }
}

export function isTrustedSender(senderId: number, frameUrl: string, expectedSenderId: number): boolean {
  return senderId === expectedSenderId && isAllowedAppUrl(frameUrl);
}

export function assertTrustedSender(senderId: number, frameUrl: string, expectedSenderId: number): void {
  if (!isTrustedSender(senderId, frameUrl, expectedSenderId)) throw new Error("Untrusted IPC sender");
}

export function safeIpcError(error: unknown): { code: string; message: string } {
  if (error && typeof error === "object" && "code" in error && typeof error.code === "string") {
    return { code: error.code.slice(0, 64), message: "Operation failed" };
  }
  return { code: "operation-failed", message: "Operation failed" };
}

export function isWithinDirectory(root: string, candidate: string): boolean {
  if (!isAbsolute(root) || !isAbsolute(candidate)) return false;
  const candidateSegments = candidate.replaceAll("\\", "/").split("/");
  if (candidateSegments.includes("..")) return false;
  const normalizedRoot = resolve(root);
  const normalizedCandidate = resolve(candidate);
  const pathFromRoot = relative(normalizedRoot, normalizedCandidate);
  return pathFromRoot === "" || (pathFromRoot !== ".." && !pathFromRoot.startsWith(`..${sep}`) && !isAbsolute(pathFromRoot));
}
