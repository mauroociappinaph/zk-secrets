import { randomBytes } from "node:crypto";
import type { Stats } from "node:fs";
import { lstat, mkdir, open, rename, unlink } from "node:fs/promises";
import { basename, dirname, join } from "node:path";
import { SinkError } from "./types.ts";

/** lstat that returns null for a missing path; never follows a symlink. */
export async function lstatOrNull(path: string): Promise<Stats | null> {
  try {
    return await lstat(path);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw new SinkError("file_write_failed", `cannot inspect ${path}`);
  }
}

function symlinkRefused(path: string): SinkError {
  return new SinkError("symlink_refused", `${path} is a symlink; zks writes only to real files and directories`);
}

/**
 * A directory only its owner can enter: created with mode 700 when missing; an existing one must
 * be a real directory (not a symlink) without group or other permissions.
 */
export async function privateDirectory(dir: string): Promise<void> {
  const stats = await lstatOrNull(dir);
  if (stats === null) {
    await mkdir(dir, { recursive: true, mode: 0o700 }).catch(() => {
      throw new SinkError("file_write_failed", `cannot create ${dir}`);
    });
    return;
  }
  if (stats.isSymbolicLink()) throw symlinkRefused(dir);
  if (!stats.isDirectory()) throw new SinkError("not_a_directory", `${dir} is not a directory`);
  if ((stats.mode & 0o077) !== 0) throw new SinkError("insecure_dir", `${dir} is accessible by other users; run chmod 700 ${dir}`);
}

/** The existing file at path when it is a regular file; null when missing; symlinks and others are refused. */
export async function regularFileOrNull(path: string): Promise<Stats | null> {
  const stats = await lstatOrNull(path);
  if (stats === null) return null;
  if (stats.isSymbolicLink()) throw symlinkRefused(path);
  if (!stats.isFile()) throw new SinkError("not_a_file", `${path} is not a regular file`);
  return stats;
}

/**
 * Replaces path with data atomically: a new mode-600 file in the same directory, fsynced, then
 * renamed over path. The temporary file is removed when anything fails, so no copy is left behind.
 */
export async function writeFileAtomic(path: string, data: Buffer): Promise<void> {
  await regularFileOrNull(path);
  const temp = join(dirname(path), `.${basename(path)}.zks-${randomBytes(6).toString("hex")}.tmp`);
  let created = false;
  try {
    const handle = await open(temp, "wx", 0o600);
    created = true;
    try {
      await handle.chmod(0o600);
      await handle.writeFile(data);
      await handle.sync();
    } finally {
      await handle.close();
    }
    // Checked again right before the rename: a symlink planted meanwhile is refused, not replaced.
    await regularFileOrNull(path);
    await rename(temp, path);
    created = false;
  } catch (error) {
    if (error instanceof SinkError) throw error;
    throw new SinkError("file_write_failed", `cannot write ${path}`);
  } finally {
    if (created) await unlink(temp).catch(() => undefined);
  }
}
