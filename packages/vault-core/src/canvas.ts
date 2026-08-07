/** Extract human-readable strings from Canvas JSON for local search previews. */
export function extractCanvasText(raw: string): { searchableText?: string; warning?: string } {
  try {
    const value: unknown = JSON.parse(raw);
    const strings: string[] = [];
    const visit = (entry: unknown): void => {
      if (typeof entry === "string") {
        const trimmed = entry.trim();
        if (trimmed) strings.push(trimmed);
        return;
      }
      if (Array.isArray(entry)) {
        for (const child of entry) visit(child);
        return;
      }
      if (entry && typeof entry === "object") {
        for (const child of Object.values(entry)) visit(child);
      }
    };
    visit(value);
    return strings.length > 0 ? { searchableText: [...new Set(strings)].join("\n") } : {};
  } catch {
    return { warning: "Malformed Canvas JSON; raw text preserved" };
  }
}
