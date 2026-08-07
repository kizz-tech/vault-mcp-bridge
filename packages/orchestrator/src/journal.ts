import { JOURNAL_LEVELS, type JournalEntry, type JournalLevel, type JournalOptions, type RedactedJournal } from "./types.js";

const DEFAULT_MAX_ENTRIES = 100;
const DEFAULT_MAX_EVENT_CHARS = 96;
const DEFAULT_MAX_DETAIL_CHARS = 160;

// Unknown keys are intentionally redacted. This prevents an adapter from
// accidentally copying remote stdout, note contents, paths, or credentials to
// the durable journal just because a new field was added to its result.
const SAFE_DETAIL_KEYS = new Set([
  "phase",
  "from",
  "to",
  "code",
  "operation",
  "status",
  "host",
  "provider",
  "project",
  "release",
  "generation",
  "documentCount",
  "noteCount",
  "byteCount",
  "count",
  "attempt",
  "retryable",
  "keepReplica"
]);

const ABSOLUTE_PATH_RE = /(?:^|\s)(?:\/(?:[^\s/]+\/)+[^\s]*|[A-Za-z]:\\[^\s]+)/u;
const BEARER_RE = /\b(?:bearer|token|secret|password)\s*[:=]\s*[^\s]+/iu;
const JWT_RE = /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/u;

export class BoundedJournal implements RedactedJournal {
  private readonly maxEntries: number;
  private readonly maxEventChars: number;
  private readonly maxDetailChars: number;
  private readonly buffer: JournalEntry[] = [];

  constructor(options: JournalOptions = {}) {
    this.maxEntries = clampPositive(options.maxEntries ?? DEFAULT_MAX_ENTRIES, DEFAULT_MAX_ENTRIES);
    this.maxEventChars = clampPositive(options.maxEventChars ?? DEFAULT_MAX_EVENT_CHARS, DEFAULT_MAX_EVENT_CHARS);
    this.maxDetailChars = clampPositive(options.maxDetailChars ?? DEFAULT_MAX_DETAIL_CHARS, DEFAULT_MAX_DETAIL_CHARS);
  }

  append(input: Omit<JournalEntry, "at"> & { at?: string }): JournalEntry {
    const level = normalizeLevel(input.level);
    const entry: JournalEntry = {
      at: normalizeTimestamp(input.at),
      level,
      event: redactText(input.event, this.maxEventChars)
    };
    const detail = redactDetails(input.detail, this.maxDetailChars);
    if (Object.keys(detail).length > 0) entry.detail = detail;
    this.buffer.push(entry);
    while (this.buffer.length > this.maxEntries) this.buffer.shift();
    return cloneEntry(entry);
  }

  entries(): readonly JournalEntry[] {
    return this.buffer.map(cloneEntry);
  }

  replace(entries: readonly JournalEntry[]): void {
    this.buffer.length = 0;
    for (const entry of entries) {
      this.append({
        at: entry.at,
        level: entry.level,
        event: entry.event,
        ...(entry.detail === undefined ? {} : { detail: entry.detail })
      });
    }
  }

  clear(): void {
    this.buffer.length = 0;
  }
}

function normalizeLevel(value: JournalLevel): JournalLevel {
  return (JOURNAL_LEVELS as readonly string[]).includes(value) ? value : "info";
}

function normalizeTimestamp(value: string | undefined): string {
  if (value !== undefined && Number.isFinite(Date.parse(value))) return new Date(value).toISOString();
  return new Date().toISOString();
}

function redactDetails(
  detail: Readonly<Record<string, string | number | boolean>> | undefined,
  maxChars: number
): Record<string, string | number | boolean> {
  if (detail === undefined) return {};
  const result: Record<string, string | number | boolean> = {};
  for (const [key, value] of Object.entries(detail)) {
    if (!SAFE_DETAIL_KEYS.has(key)) {
      result[key.slice(0, 64)] = "[redacted]";
      continue;
    }
    if (typeof value === "string") result[key] = redactText(value, maxChars);
    else if (typeof value === "number" && Number.isFinite(value)) result[key] = value;
    else if (typeof value === "boolean") result[key] = value;
    else result[key] = "[redacted]";
  }
  return result;
}

function redactText(value: string, maxChars: number): string {
  const normalized = value.replace(/[\r\n\t]+/gu, " ").trim();
  if (ABSOLUTE_PATH_RE.test(normalized) || BEARER_RE.test(normalized) || JWT_RE.test(normalized)) return "[redacted]";
  return normalized.length > maxChars ? normalized.slice(0, Math.max(0, maxChars - 1)) + "…" : normalized;
}

function cloneEntry(entry: JournalEntry): JournalEntry {
  return entry.detail === undefined
    ? { ...entry }
    : { ...entry, detail: { ...entry.detail } };
}

function clampPositive(value: number, fallback: number): number {
  return Number.isInteger(value) && value > 0 ? value : fallback;
}
