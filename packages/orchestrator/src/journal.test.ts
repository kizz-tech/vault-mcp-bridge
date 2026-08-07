import { describe, expect, it } from "vitest";
import { BoundedJournal } from "./journal.js";

describe("BoundedJournal", () => {
  it("redacts unknown and secret-like details and bounds entries", () => {
    const journal = new BoundedJournal({ maxEntries: 2, maxEventChars: 20, maxDetailChars: 12 });
    journal.append({ level: "info", event: "ssh connected", detail: { host: "server.example.invalid" } });
    journal.append({ level: "info", event: "path /Users/alice/private/note.md", detail: { token: "super-secret" } });
    journal.append({ level: "error", event: "third", detail: { stdout: "note contents" } });

    const entries = journal.entries();
    expect(entries).toHaveLength(2);
    expect(JSON.stringify(entries)).not.toMatch(/super-secret|note contents|\/Users\/alice/iu);
    expect(entries[1]?.detail?.stdout).toBe("[redacted]");
  });

  it("clones returned entries", () => {
    const journal = new BoundedJournal();
    journal.append({ level: "info", event: "ready", detail: { status: "ok" } });
    const entries = journal.entries();
    (entries as unknown as Array<{ event: string }>)[0]!.event = "tampered";
    expect(journal.entries()[0]?.event).toBe("ready");
  });
});
