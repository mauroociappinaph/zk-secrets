import { constants } from "node:fs";
import { lstat, mkdir, open } from "node:fs/promises";
import { basename } from "node:path";
import type { ZksPaths } from "./paths.ts";

export interface PermissionFix {
  /** The equivalent shell command of every change made. */
  fixed: string[];
  /** Paths left alone: a symlink, the wrong kind of file, or a chmod that failed. */
  failed: Array<{ path: string; reason: string }>;
}

const DIR_MODE = 0o700;
const FILE_MODE = 0o600;

/**
 * `zks doctor --fix`: creates ~/.config/zks and ~/.local/state/zks with 700 and puts config.json,
 * trust.json and audit.db (+ -wal, -shm) at 600. Only modes change: contents, integrity.json, the
 * audit chain and the Keychain are never touched, and no symlink is ever followed.
 */
export async function fixPermissions(paths: ZksPaths): Promise<PermissionFix> {
  const report: PermissionFix = { fixed: [], failed: [] };
  const dirs: Array<[string, string[]]> = [
    [paths.configDir, [paths.configFile, paths.trustFile]],
    [paths.stateDir, ["", "-wal", "-shm"].map((suffix) => paths.auditDb + suffix)],
  ];
  for (const [dir, files] of dirs) {
    if (!(await fixEntry(dir, "directory", report))) continue;
    for (const file of files) await fixEntry(file, "file", report);
  }
  return report;
}

/** Returns false when the entry is not usable (a symlink, the wrong kind, or an error). */
async function fixEntry(path: string, kind: "directory" | "file", report: PermissionFix): Promise<boolean> {
  const want = kind === "directory" ? DIR_MODE : FILE_MODE;
  let stats;
  try {
    stats = await lstat(path);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") return fail(report, path, error);
    if (kind === "file") return true;
    try {
      await mkdir(path, { recursive: true, mode: want });
      await chmodNoFollow(path, kind, want);
    } catch (mkdirError) {
      return fail(report, path, mkdirError);
    }
    report.fixed.push(`mkdir -m 700 ${path}`);
    return true;
  }
  if (stats.isSymbolicLink()) return fail(report, path, "symlink");
  if (kind === "directory" ? !stats.isDirectory() : !stats.isFile()) return fail(report, path, `not_a_${kind}`);
  if ((stats.mode & 0o777) === want) return true;
  try {
    await chmodNoFollow(path, kind, want);
  } catch (error) {
    return fail(report, path, error);
  }
  report.fixed.push(`chmod ${want.toString(8)} ${path}`);
  return true;
}

/** chmod through a descriptor opened with O_NOFOLLOW, so a symlink swapped in after lstat is not followed. */
async function chmodNoFollow(path: string, kind: "directory" | "file", mode: number): Promise<void> {
  const flags = constants.O_RDONLY | constants.O_NOFOLLOW | (kind === "directory" ? constants.O_DIRECTORY : 0);
  const handle = await open(path, flags);
  try {
    const stats = await handle.stat();
    if (kind === "directory" ? !stats.isDirectory() : !stats.isFile()) throw Object.assign(new Error(basename(path)), { code: `not_a_${kind}` });
    await handle.chmod(mode);
  } finally {
    await handle.close();
  }
}

function fail(report: PermissionFix, path: string, error: unknown): false {
  const reason =
    typeof error === "string"
      ? error
      : (error as NodeJS.ErrnoException).code === "ELOOP"
        ? "symlink"
        : String((error as NodeJS.ErrnoException).code ?? "error");
  report.failed.push({ path, reason });
  return false;
}
