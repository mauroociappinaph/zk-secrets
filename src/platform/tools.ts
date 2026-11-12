import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { SAFE_PATH, type Exec } from "./exec.ts";

/** Absolute paths of the external tools zks runs; null when the tool is not available. */
export interface ToolPaths {
  egoBrowser: string | null;
  gh: string | null;
  op: string | null;
  /** docker-swarm sink; recorded only when install.sh finds it on SAFE_PATH. */
  docker: string | null;
}

/** sha256 (lowercase hex) of each tool binary recorded by install.sh; null when unpinned. */
export type ToolPins = Record<keyof ToolPaths, string | null>;

/** Written by install.sh into the read-only install, so the integrity digest covers it. */
export const TOOLS_FILE = "tools.json";
export const NO_TOOLS: ToolPaths = { egoBrowser: null, gh: null, op: null, docker: null };
export const NO_PINS: ToolPins = { egoBrowser: null, gh: null, op: null, docker: null };
const SHA256 = /^[0-9a-f]{64}$/;

export const TOOL_NAMES: Record<keyof ToolPaths, string> = { egoBrowser: "ego-browser", gh: "gh", op: "op", docker: "docker" };
const MAX_PATH = 1024;

function absolutePath(value: unknown): string | null {
  if (typeof value !== "string" || value.length > MAX_PATH || !value.startsWith("/")) return null;
  // Spaces are allowed ("/Applications/ego lite.app/..."); control characters are not.
  return /^[\x20-\x7E]+$/.test(value) ? value : null;
}

type ToolEntry = { path: string | null; pin: string | null };

/**
 * One tools.json entry: a legacy path string (unpinned), or {"path": p, "sha256": hex}. A
 * malformed pin makes the whole entry unavailable rather than silently unpinned.
 */
function parseEntry(value: unknown): ToolEntry {
  if (typeof value === "string") return { path: absolutePath(value), pin: null };
  if (typeof value !== "object" || value === null || Array.isArray(value)) return { path: null, pin: null };
  const entry = value as Record<string, unknown>;
  const path = absolutePath(Object.hasOwn(entry, "path") ? entry.path : null);
  const pin = Object.hasOwn(entry, "sha256") ? entry.sha256 : null;
  if (path === null || typeof pin !== "string" || !SHA256.test(pin)) return { path: null, pin: null };
  return { path, pin };
}

function parseEntries(text: string): Record<keyof ToolPaths, ToolEntry> | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return null;
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) return null;
  const file = parsed as Record<string, unknown>;
  const own = (name: string) => parseEntry(Object.hasOwn(file, name) ? file[name] : null);
  return { egoBrowser: own(TOOL_NAMES.egoBrowser), gh: own(TOOL_NAMES.gh), op: own(TOOL_NAMES.op), docker: own(TOOL_NAMES.docker) };
}

/** Parses tools.json paths. Anything malformed is null. */
export function parseToolsFile(text: string): ToolPaths {
  const entries = parseEntries(text);
  if (entries === null) return { ...NO_TOOLS };
  return { egoBrowser: entries.egoBrowser.path, gh: entries.gh.path, op: entries.op.path, docker: entries.docker.path };
}

/** Parses tools.json sha256 pins; legacy string entries and missing tools are null. */
export function parseToolPins(text: string): ToolPins {
  const entries = parseEntries(text);
  if (entries === null) return { ...NO_PINS };
  return { egoBrowser: entries.egoBrowser.pin, gh: entries.gh.pin, op: entries.op.pin, docker: entries.docker.pin };
}

/** sha256 of a file's bytes (following symlinks, so an upgraded Homebrew binary changes it). */
export function sha256File(path: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const hash = createHash("sha256");
    createReadStream(path)
      .on("data", (chunk) => hash.update(chunk))
      .on("error", reject)
      .on("end", () => resolve(hash.digest("hex")));
  });
}

export class ToolChangedError extends Error {
  readonly code = "tool_changed";
}

/**
 * Wraps exec so a pinned tool runs only while its binary still has the sha256 install.sh
 * recorded. A mismatch (or an unreadable binary) is refused with one stderr warning; callers
 * already treat a rejected exec as "tool unavailable". Hashes once per tool per process.
 */
export function pinnedExec(
  exec: Exec,
  tools: ToolPaths,
  pins: ToolPins,
  io: { hashFile: (path: string) => Promise<string>; warn: (line: string) => void },
): Exec {
  const verdicts = new Map<string, Promise<boolean>>();
  const pinOf = new Map<string, { name: string; pin: string }>();
  for (const key of Object.keys(TOOL_NAMES) as (keyof ToolPaths)[]) {
    const path = tools[key];
    const pin = pins[key];
    if (path !== null && pin !== null) pinOf.set(path, { name: TOOL_NAMES[key], pin });
  }
  return async (command, args, options) => {
    const pinned = pinOf.get(command);
    if (pinned) {
      let verdict = verdicts.get(command);
      if (!verdict) {
        verdict = io.hashFile(command).then(
          (hash) => hash === pinned.pin,
          () => false,
        );
        verdict.then((ok) => {
          if (!ok) io.warn(`zks: ${pinned.name} changed since install (sha256 mismatch); rerun ./install.sh to pin the new binary\n`);
        });
        verdicts.set(command, verdict);
      }
      if (!(await verdict)) throw new ToolChangedError(`${pinned.name} changed since install`);
    }
    return exec(command, args, options);
  };
}

/** First executable named `name` in a SAFE_PATH directory; the caller's PATH is never used. */
export function findOnSafePath(name: string, isExecutable: (path: string) => boolean): string | null {
  for (const dir of SAFE_PATH.split(":")) {
    const path = `${dir}/${name}`;
    if (isExecutable(path)) return path;
  }
  return null;
}

/**
 * The installed tools.json when there is one (an installed zks never looks tools up at run time);
 * otherwise, for a development run, a SAFE_PATH lookup.
 */
export function resolveTools(toolsFileText: string | null, isExecutable: (path: string) => boolean): ToolPaths {
  if (toolsFileText !== null) return parseToolsFile(toolsFileText);
  return {
    egoBrowser: findOnSafePath(TOOL_NAMES.egoBrowser, isExecutable),
    gh: findOnSafePath(TOOL_NAMES.gh, isExecutable),
    op: findOnSafePath(TOOL_NAMES.op, isExecutable),
    docker: findOnSafePath(TOOL_NAMES.docker, isExecutable),
  };
}
