import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { describe, expect, it } from "vitest";

import { LocalDesktopBackend, scanVault } from "../src/backend.js";

describe("desktop backend port", () => {
  it("scans only supported visible vault files", async () => {
    const root = await mkdtemp(join(tmpdir(), "vault-bridge-vault-"));
    try {
      await mkdir(join(root, "sub"));
      await mkdir(join(root, ".obsidian"));
      await writeFile(join(root, "note.md"), "hello");
      await writeFile(join(root, "sub", "canvas.canvas"), "{}");
      await writeFile(join(root, "ignored.txt"), "ignored");
      await writeFile(join(root, ".obsidian", "settings.json"), "ignored");
      await expect(scanVault(root)).resolves.toMatchObject({ noteCount: 2, bytes: 7 });
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it("keeps onboarding state until both vault and server are configured", async () => {
    const root = await mkdtemp(join(tmpdir(), "vault-bridge-vault-"));
    try {
      await writeFile(join(root, "note.md"), "hello");
      const backend = new LocalDesktopBackend();
      expect((await backend.getState()).mode).toBe("onboarding");
      await backend.selectVault(root);
      expect((await backend.getState()).vault?.noteCount).toBe(1);
      await backend.configureServer({ host: "host.example.invalid", user: "deploy", port: 22 });
      expect((await backend.getState()).server?.label).toBe("deploy@host.example.invalid");
      expect((await backend.setup()).attention?.code).toBe("orchestrator-unavailable");
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});
