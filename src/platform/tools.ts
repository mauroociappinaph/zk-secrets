import { SAFE_PATH } from "./exec.ts";

/** Absolute paths of the external tools zks runs; null when the tool is not available. */
export interface ToolPaths {
  egoBrowser: string | null;
  gh: string | null;
  op: string | null;
}

/** Written by install.sh into the read-only install, so the integrity digest covers it. */
export const TOOLS_FILE = "tools.json";
export const NO_TOOLS: ToolPaths = { egoBrowser: null, gh: null, op: null };

const TOOL_NAMES: Record<keyof ToolPaths, string> = { egoBrowser: "ego-browser", gh: "gh", op: "op" };
const MAX_PATH = 1024;

function absolutePath(value: unknown): string | null {
  if (typeof value !== "string" || value.length > MAX_PATH || !value.startsWith("/")) return null;
  // Spaces are allowed ("/Applications/ego lite.app/..."); control characters are not.
  return /^[\x20-\x7E]+$/.test(value) ? value : null;
}

/** Parses tools.json: {"ego-browser": path|null, "gh": path|null, "op": path|null}. Anything malformed is null. */
export function parseToolsFile(text: string): ToolPaths {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return { ...NO_TOOLS };
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) return { ...NO_TOOLS };
  const file = parsed as Record<string, unknown>;
  const own = (name: string) => (Object.hasOwn(file, name) ? file[name] : null);
  return {
    egoBrowser: absolutePath(own(TOOL_NAMES.egoBrowser)),
    gh: absolutePath(own(TOOL_NAMES.gh)),
    op: absolutePath(own(TOOL_NAMES.op)),
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
  };
}
