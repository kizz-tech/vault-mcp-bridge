import { constants as fsConstants } from "node:fs";
import { lstat, mkdtemp, mkdir, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { sha256Base64Url } from "@vault-mcp-bridge/contracts";
import { buildSnapshot, readStableFile, scanVault, stableDocumentId, type OpenStableReadHandle } from "./index.js";

const key = "synthetic-local-id-key";
const vaultId = "0123456789abcdefghijklmnopqrstuv";
const readLimits = { maxFiles: 10, maxFileBytes: 1024, maxTotalBytes: 4096, maxReadRetries: 0 };

async function fixtureRoot(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "vault-mcp-bridge-test-"));
  await mkdir(join(root, "nested"));
  await mkdir(join(root, ".obsidian"));
  await writeFile(join(root, "note.md"), "---\ntitle: Тест\ntags: [demo]\n---\n\nТекст [[nested/canvas]].\n", "utf8");
  await writeFile(join(root, "nested", "canvas.canvas"), JSON.stringify({ nodes: [{ type: "text", text: "Canvas синтетика" }] }), "utf8");
  await writeFile(join(root, "nested", "view.base"), "views:\n  - type: table\n", "utf8");
  await writeFile(join(root, ".obsidian", "secret.md"), "synthetic secret", "utf8");
  return root;
}

describe("vault-core scanner", () => {
  it("scans supported files and excludes hidden configuration", async () => {
    const root = await fixtureRoot();
    const result = await scanVault(root, { idKey: key, vaultId });
    expect(result.documents).toHaveLength(3);
    expect(result.documents.map((doc) => doc.relativePath)).not.toContain(".obsidian/secret.md");
    expect(result.exclusionCounts.hidden).toBeGreaterThan(0);
    const markdown = result.documents.find((doc) => doc.mediaType === "text/markdown");
    expect(markdown?.metadata?.title).toBe("Тест");
    expect(markdown?.text).toContain("[[nested/canvas]]");
    const canvas = result.documents.find((doc) => doc.mediaType.includes("canvas"));
    expect(canvas?.searchableText).toContain("Canvas синтетика");
    const snapshot = buildSnapshot(result, { generation: 7 });
    expect(snapshot.documents[0]).not.toHaveProperty("relativePath");
    expect(snapshot.documents[0]).not.toHaveProperty("absolutePath");
  });

  it("uses stable opaque ids and defends against traversal", () => {
    expect(stableDocumentId(key, "nested/note.md")).toBe(stableDocumentId(key, "nested\\note.md"));
    expect(() => stableDocumentId(key, "../outside.md")).toThrow();
    expect(() => stableDocumentId(key, "/outside.md")).toThrow();
  });

  it("reports malformed frontmatter while preserving source text", async () => {
    const root = await mkdtemp(join(tmpdir(), "vault-mcp-bridge-malformed-"));
    const content = "---\ntitle: [unterminated\n---\nBody";
    await writeFile(join(root, "bad.md"), content, "utf8");
    const result = await scanVault(root, { idKey: key, vaultId });
    expect(result.documents[0]?.text).toBe(content);
    expect(result.warnings.some((warning) => warning.includes("Malformed frontmatter"))).toBe(true);
  });

  it("enforces file and total byte limits", async () => {
    const root = await mkdtemp(join(tmpdir(), "vault-mcp-bridge-limits-"));
    await writeFile(join(root, "small.md"), "12345", "utf8");
    await writeFile(join(root, "large.md"), "123456789", "utf8");
    const result = await scanVault(root, {
      idKey: key,
      vaultId,
      limits: { maxFileBytes: 8, maxTotalBytes: 5 }
    });
    expect(result.documents).toHaveLength(1);
    expect(result.exclusionCounts["file-too-large"] + result.exclusionCounts["total-bytes-limit"]).toBeGreaterThan(0);
  });

  it("rejects a symlink root and excludes symlink entries", async () => {
    const root = await mkdtemp(join(tmpdir(), "vault-mcp-bridge-symlink-"));
    const target = await mkdtemp(join(tmpdir(), "vault-mcp-bridge-target-"));
    await writeFile(join(target, "note.md"), "safe", "utf8");
    await symlink(join(target, "note.md"), join(root, "link.md"));
    const result = await scanVault(root, { idKey: key, vaultId });
    expect(result.documents).toHaveLength(0);
    expect(result.exclusionCounts.symlink).toBe(1);
    const linkRoot = join(root, "root-link");
    await symlink(target, linkRoot);
    await expect(scanVault(linkRoot, { idKey: key, vaultId })).rejects.toThrow(/symlink/);
  });

  it("rejects a symlink before the injected opener can read it", async () => {
    const root = await mkdtemp(join(tmpdir(), "vault-mcp-bridge-open-seam-"));
    const target = join(root, "outside.md");
    const link = join(root, "note.md");
    await writeFile(target, "synthetic outside", "utf8");
    await symlink(target, link);
    let opens = 0;
    const opener: OpenStableReadHandle = async () => {
      opens += 1;
      throw new Error("the opener must not be reached for a symlink");
    };
    await expect(readStableFile(link, root, readLimits, opener)).rejects.toThrow("symlink entry");
    expect(opens).toBe(0);
  });

  it("rejects a symlinked ancestor before opening the descendant", async () => {
    const root = await mkdtemp(join(tmpdir(), "vault-mcp-bridge-ancestor-seam-"));
    const target = join(root, "target");
    await mkdir(target);
    await writeFile(join(target, "note.md"), "synthetic target", "utf8");
    const alias = join(root, "alias");
    await symlink(target, alias);
    await expect(readStableFile(join(alias, "note.md"), root, readLimits)).rejects.toThrow("symlink ancestor");
  });

  it("rejects a descriptor/path identity swap before consuming descriptor bytes", async () => {
    const root = await mkdtemp(join(tmpdir(), "vault-mcp-bridge-identity-seam-"));
    const filePath = join(root, "note.md");
    await writeFile(filePath, "synthetic safe", "utf8");
    const pathStat = await lstat(filePath);
    let reads = 0;
    let closes = 0;
    const opener: OpenStableReadHandle = async (_path, flags) => {
      if (typeof fsConstants.O_NOFOLLOW === "number") expect(flags & fsConstants.O_NOFOLLOW).not.toBe(0);
      return {
        stat: async () => ({
          ...pathStat,
          ino: pathStat.ino + 1,
          isFile: () => true
        }) as never,
        readFile: async () => {
          reads += 1;
          return Buffer.from("synthetic attacker content", "utf8");
        },
        close: async () => {
          closes += 1;
        }
      };
    };
    await expect(readStableFile(filePath, root, readLimits, opener)).rejects.toThrow("file changed while reading");
    expect(reads).toBe(0);
    expect(closes).toBe(1);
  });

  it("hashes source text before the snapshot is built", async () => {
    const root = await mkdtemp(join(tmpdir(), "vault-mcp-bridge-hash-"));
    const content = "hash me";
    await writeFile(join(root, "note.md"), content, "utf8");
    const result = await scanVault(root, { idKey: key, vaultId });
    expect(result.documents[0]?.sourceHash).toBe(sha256Base64Url(content));
  });
});
