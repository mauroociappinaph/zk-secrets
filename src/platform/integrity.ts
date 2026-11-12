import { createHash } from "node:crypto";
import { lstatSync, readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative } from "node:path";

export interface IntegrityManifest {
  version: string;
  root: string;
  digest: string;
  files: number;
}

/** Walks root and returns one SHA-256 over every file path and content, in sorted order. */
export function digestTree(root: string): { digest: string; files: number } {
  const paths: string[] = [];
  const walk = (dir: string) => {
    for (const entry of readdirSync(dir).sort()) {
      const full = join(dir, entry);
      const stat = statSync(full);
      if (stat.isDirectory()) walk(full);
      else if (stat.isFile()) paths.push(full);
    }
  };
  walk(root);
  const hash = createHash("sha256");
  for (const path of paths) {
    hash.update(relative(root, path));
    hash.update("\0");
    hash.update(createHash("sha256").update(readFileSync(path)).digest());
  }
  return { digest: hash.digest("hex"), files: paths.length };
}

export function checkIntegrity(manifestPath: string, appRoot: string): Record<string, unknown> {
  let manifest: IntegrityManifest;
  try {
    manifest = JSON.parse(readFileSync(manifestPath, "utf8")) as IntegrityManifest;
  } catch {
    return { status: "not-installed", detail: "no integrity manifest; run ./install.sh" };
  }
  if (manifest.root !== appRoot) return { status: "not-installed", detail: `running from ${appRoot}, installed at ${manifest.root}` };
  const current = digestTree(appRoot);
  return {
    status: current.digest === manifest.digest ? "ok" : "mismatch",
    files: current.files,
    expectedFiles: manifest.files,
  };
}

export type OwnershipIssue = { path: string; code: "not_root_owned" | "writable_by_group_or_other" | "symlink" | "unreadable" };

interface OwnershipFs {
  lstat: (path: string) => { uid: number; mode: number; isDirectory(): boolean; isSymbolicLink(): boolean };
  readdir: (path: string) => string[];
}

/**
 * For a system install: every entry under root must be owned by root, not writable by group or
 * other, and not a symlink (which could point into a user-writable place).
 */
export function checkOwnership(root: string, fs: OwnershipFs = { lstat: lstatSync, readdir: (p) => readdirSync(p) }): {
  ok: boolean;
  issues: OwnershipIssue[];
} {
  const issues: OwnershipIssue[] = [];
  const visit = (path: string) => {
    const rel = relative(root, path) || ".";
    let stat: ReturnType<OwnershipFs["lstat"]>;
    try {
      stat = fs.lstat(path);
    } catch {
      issues.push({ path: rel, code: "unreadable" });
      return;
    }
    if (stat.isSymbolicLink()) issues.push({ path: rel, code: "symlink" });
    else if (stat.uid !== 0) issues.push({ path: rel, code: "not_root_owned" });
    else if ((stat.mode & 0o022) !== 0) issues.push({ path: rel, code: "writable_by_group_or_other" });
    if (stat.isDirectory() && !stat.isSymbolicLink()) for (const entry of fs.readdir(path).sort()) visit(join(path, entry));
  };
  visit(root);
  return { ok: issues.length === 0, issues };
}
