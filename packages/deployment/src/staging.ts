import { createHash, randomUUID } from "node:crypto";
import { mkdir, open, rename, unlink, chmod } from "node:fs/promises";
import { basename, dirname, resolve } from "node:path";
import type { ComposeProject } from "./types.js";
import { assertInstallationFile, assertSafeRelativePath } from "./validation.js";

export interface StagedCompose {
  readonly path: string;
  readonly sha256: string;
  readonly bytes: number;
}

/**
 * Atomically stage generated Compose YAML below one installation directory.
 * Existing files are replaced as a single rename; a crash cannot expose a
 * partial document to Docker Compose.
 */
export async function stageComposeProject(installationDirectory: string, project: ComposeProject): Promise<StagedCompose> {
  assertSafeRelativePath(project.fileName, "Compose file name");
  const target = assertInstallationFile(installationDirectory, resolve(installationDirectory, project.fileName));
  if (basename(target) !== "compose.yaml" && basename(target) !== "compose.yml") {
    throw new TypeError("Generated Compose file must be compose.yaml or compose.yml");
  }
  await mkdir(dirname(target), { recursive: true, mode: 0o700 });
  const temporary = resolve(dirname(target), `.${basename(target)}.${randomUUID()}.tmp`);
  const body = Buffer.from(project.yaml, "utf8");
  const digest = createHash("sha256").update(body).digest("hex");
  let handle: Awaited<ReturnType<typeof open>> | undefined;
  try {
    handle = await open(temporary, "wx", 0o640);
    await handle.writeFile(body);
    await handle.sync();
    await handle.close();
    handle = undefined;
    await rename(temporary, target);
    await chmod(target, 0o640);
    return { path: target, sha256: digest, bytes: body.byteLength };
  } finally {
    if (handle) await handle.close().catch(() => undefined);
    await unlink(temporary).catch(() => undefined);
  }
}
