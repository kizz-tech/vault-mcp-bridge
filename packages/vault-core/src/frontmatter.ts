import { parseDocument } from "yaml";
import type { Metadata } from "@vault-mcp-bridge/contracts";

const FRONTMATTER_OPEN = /^---[ \t]*(?:\r?\n|$)/;
const FRONTMATTER_CLOSE = /^(?:---|\.\.\.)[ \t]*(?:\r?\n|$)/gm;

function isSafeScalar(value: unknown): value is string | number | boolean | null {
  return value === null || typeof value === "string" || typeof value === "number" || typeof value === "boolean";
}

function isSafeValue(value: unknown): value is Metadata[string] {
  if (isSafeScalar(value)) return true;
  return Array.isArray(value) && value.length <= 64 && value.every(isSafeScalar);
}

export interface FrontmatterResult {
  metadata?: Metadata;
  warnings: string[];
}

/** Parse optional YAML frontmatter without evaluating tags or preserving objects. */
export function parseFrontmatter(text: string): FrontmatterResult {
  if (!FRONTMATTER_OPEN.test(text)) return { warnings: [] };
  const openingEnd = text.match(FRONTMATTER_OPEN)?.[0].length ?? 0;
  FRONTMATTER_CLOSE.lastIndex = openingEnd;
  const closing = FRONTMATTER_CLOSE.exec(text);
  if (!closing || closing.index < openingEnd) {
    return { warnings: ["Malformed frontmatter: opening delimiter has no closing delimiter"] };
  }
  const body = text.slice(openingEnd, closing.index);
  try {
    const document = parseDocument(body, { schema: "core", strict: true });
    if (document.errors.length > 0) {
      return { warnings: ["Malformed frontmatter: YAML parse error"] };
    }
    const value: unknown = document.toJS({ maxAliasCount: 0 });
    if (!value || typeof value !== "object" || Array.isArray(value)) {
      return { warnings: ["Malformed frontmatter: expected a mapping"] };
    }
    const metadata: Record<string, Metadata[string]> = {};
    const warnings: string[] = [];
    for (const [key, entry] of Object.entries(value)) {
      if (key === "__proto__" || key === "constructor" || key === "prototype") {
        warnings.push(`Ignored unsafe frontmatter key: ${key}`);
        continue;
      }
      if (key.length === 0 || key.length > 128 || [...key].some((character) => character.charCodeAt(0) < 32)) {
        warnings.push(`Ignored unsafe frontmatter key: ${key.slice(0, 32)}`);
        continue;
      }
      if (isSafeValue(entry)) metadata[key] = entry;
      else warnings.push(`Ignored non-scalar frontmatter key: ${key}`);
    }
    return Object.keys(metadata).length > 0 ? { metadata, warnings } : { warnings };
  } catch {
    return { warnings: ["Malformed frontmatter: YAML parse error"] };
  }
}
