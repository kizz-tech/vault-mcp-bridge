import { hmacSha256Base64Url } from "@vault-mcp-bridge/contracts";
import type { IdKey } from "./types.js";

function normalizeRelativePath(relativePath: string): string {
  const normalized = relativePath.replaceAll("\\", "/").replace(/^\.\/+/, "");
  if (!normalized || normalized.startsWith("/") || normalized.split("/").some((part) => part === "..")) {
    throw new TypeError("Relative path escapes the vault root");
  }
  return normalized.normalize("NFC");
}

/** Stable opaque id. The relative path is never included in the returned value. */
export function stableDocumentId(idKey: IdKey, relativePath: string): string {
  const normalized = normalizeRelativePath(relativePath);
  return hmacSha256Base64Url(idKey, `vault-document:v1:${normalized}`);
}

export { normalizeRelativePath };
