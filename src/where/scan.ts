import { constants } from "node:fs";
import { open, opendir } from "node:fs/promises";
import { basename, join, relative, sep } from "node:path";
import type { Exec } from "../platform/exec.ts";

/** `zks where` reads at most this many files; the rest is reported as truncated. */
export const WHERE_MAX_FILES = 20_000;
/** Files larger than 1 MiB are skipped unread. */
export const WHERE_MAX_FILE_BYTES = 1024 * 1024;
export const GIT = "/usr/bin/git";

/** Directories never scanned, at any depth. */
const SKIPPED_DIRS = new Set(["node_modules", ".git", "dist", "build"]);
/** Built indirectly: dotenv file names start with a dot and "env". */
const DOTENV_PREFIX = "." + "env";
const DOTENV_TEMPLATE = /\.(example|sample|template)$/;

export const REFERENCE_KINDS = [
  "github-workflow",
  "compose",
  "dockerfile",
  "railway",
  "vercel",
  "netlify",
  "dotenv",
  "ci-other",
  "script",
  "code",
] as const;
export type ReferenceKind = (typeof REFERENCE_KINDS)[number];

/** One place a name appears: never the line text, which may hold the value. */
export interface Reference {
  path: string;
  line: number;
  kind: ReferenceKind;
}

export interface ScanResult {
  references: Reference[];
  scanned: number;
  truncated: boolean;
}

/** True when a relative path (`/`-separated) runs through node_modules, .git, dist or build. */
export function isSkippedPath(path: string): boolean {
  return path.split("/").slice(0, -1).some((segment) => SKIPPED_DIRS.has(segment));
}

/** The kind of a project file from its relative path (`/`-separated). */
export function classify(path: string): ReferenceKind {
  const name = basename(path);
  const lower = name.toLowerCase();
  if (/(^|\/)\.github\/workflows\/[^/]+\.ya?ml$/i.test(path)) return "github-workflow";
  if (
    /(^|\/)\.(circleci|buildkite)\//.test(path) ||
    /^(\.gitlab-ci|bitbucket-pipelines|azure-pipelines|\.travis|\.drone)\.ya?ml$/i.test(name) ||
    name === "Jenkinsfile"
  ) {
    return "ci-other";
  }
  if (/compose.*\.ya?ml$/i.test(name)) return "compose";
  if (lower === "dockerfile" || lower.startsWith("dockerfile.") || lower.endsWith(".dockerfile")) return "dockerfile";
  if (name === "railway.toml" || name === "railway.json") return "railway";
  if (name === "vercel.json") return "vercel";
  if (name === "netlify.toml") return "netlify";
  if (name.startsWith(DOTENV_PREFIX)) return "dotenv";
  if (name.endsWith(".sh") || name === "Makefile" || name === "package.json") return "script";
  return "code";
}

/** A dotenv file that only documents names (`*.example`, `*.sample`, `*.template`). */
export function isDotenvTemplate(path: string): boolean {
  return DOTENV_TEMPLATE.test(basename(path));
}

const isWordByte = (b: number | undefined): boolean =>
  b !== undefined && ((b >= 0x30 && b <= 0x39) || (b >= 0x41 && b <= 0x5a) || (b >= 0x61 && b <= 0x7a) || b === 0x5f);

/**
 * 1-based numbers of the lines holding name as a whole word (`[A-Za-z0-9_]` boundaries), each
 * line once. Works on the bytes: no line is ever turned into a string.
 */
export function matchingLines(data: Buffer, name: string): number[] {
  const needle = Buffer.from(name, "latin1");
  const lines: number[] = [];
  let line = 1;
  let counted = 0;
  for (let at = data.indexOf(needle); at >= 0; at = data.indexOf(needle, at + 1)) {
    for (let i = counted; i < at; i++) if (data[i] === 0x0a) line++;
    counted = at;
    if (isWordByte(data[at - 1]) || isWordByte(data[at + needle.length])) continue;
    if (lines[lines.length - 1] !== line) lines.push(line);
  }
  return lines;
}

/** Relative paths from git when cwd is in a Git work tree, else null (git missing or failing). */
async function gitFiles(cwd: string, exec: Exec): Promise<string[] | null> {
  try {
    const inside = await exec(GIT, ["-C", cwd, "rev-parse", "--is-inside-work-tree"]);
    if (inside.code !== 0 || inside.stdout.toString("utf8").trim() !== "true") return null;
    const listed = await exec(GIT, ["-C", cwd, "ls-files", "--cached", "--others", "--exclude-standard", "-z"]);
    if (listed.code !== 0) return null;
    return listed.stdout.toString("utf8").split("\0").filter((p) => p !== "");
  } catch {
    return null;
  }
}

/** Relative paths of the regular files below cwd, without entering skipped directories or symlinks; stops after limit. */
async function walkFiles(cwd: string, limit: number): Promise<string[]> {
  const out: string[] = [];
  const visit = async (dir: string): Promise<void> => {
    let entries: { name: string; isDirectory(): boolean; isFile(): boolean }[];
    try {
      entries = [];
      for await (const entry of await opendir(dir)) entries.push(entry);
    } catch {
      return;
    }
    entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    for (const entry of entries) {
      if (out.length > limit) return;
      const path = join(dir, entry.name);
      if (entry.isDirectory()) {
        if (!SKIPPED_DIRS.has(entry.name)) await visit(path);
      } else if (entry.isFile()) {
        out.push(relative(cwd, path).split(sep).join("/"));
      }
    }
  };
  await visit(cwd);
  return out;
}

/**
 * The files `zks where` reads: git ls-files inside a Git work tree, else a walk of cwd. Skipped
 * directories are dropped; at most limit paths, in byte order, with truncated when there were more.
 */
export async function listProjectFiles(cwd: string, exec: Exec, limit: number): Promise<{ files: string[]; truncated: boolean }> {
  const listed = (await gitFiles(cwd, exec)) ?? (await walkFiles(cwd, limit));
  const files = listed.filter((p) => !isSkippedPath(p));
  files.sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  return { files: files.slice(0, limit), truncated: files.length > limit };
}

/** The bytes of a regular file that is not a symlink, at most 1 MiB and without a NUL byte; null otherwise. */
export async function readTextFile(path: string): Promise<Buffer | null> {
  let handle;
  try {
    handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  } catch {
    return null;
  }
  try {
    const stats = await handle.stat();
    if (!stats.isFile() || stats.size > WHERE_MAX_FILE_BYTES) return null;
    const data = await handle.readFile();
    if (data.length > WHERE_MAX_FILE_BYTES || data.includes(0)) return null;
    return data;
  } catch {
    return null;
  } finally {
    await handle.close().catch(() => undefined);
  }
}

/** Every whole-word reference to name in the project files (skip lists applied), sorted by path and line. */
export async function scanProject(
  cwd: string,
  name: string,
  options: { exec: Exec; limit: number; exclude?: Set<string> },
): Promise<ScanResult> {
  const { files, truncated } = await listProjectFiles(cwd, options.exec, options.limit);
  const references: Reference[] = [];
  let scanned = 0;
  for (const path of files) {
    const absolute = join(cwd, path);
    if (options.exclude?.has(absolute)) continue;
    const data = await readTextFile(absolute);
    if (data === null) continue;
    scanned++;
    const kind = classify(path);
    for (const line of matchingLines(data, name)) references.push({ path, line, kind });
  }
  return { references, scanned, truncated };
}
