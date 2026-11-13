import { constants } from "node:fs";
import { open } from "node:fs/promises";
import type { DotenvTarget } from "../policy/types.ts";
import { regularFileOrNull, writeFileAtomic } from "./files.ts";
import { SinkError, type Sink } from "./types.ts";

/** `KEY="value"` with `\`, `"`, newline, carriage return and `$` escaped. */
export function dotenvLine(key: string, value: string): string {
  const escaped = value.replace(/[\\"\n\r$]/g, (c) => (c === "\n" ? "\\n" : c === "\r" ? "\\r" : `\\${c}`));
  return `${key}="${escaped}"`;
}

type Line = { text: string; eol: string };

/** Splits text into lines that keep their own ending; the last line gets `eol` when it has none. */
function splitLines(text: string): Line[] {
  const lines: Line[] = [];
  const parts = text.split(/(\r?\n)/);
  for (let i = 0; i < parts.length; i += 2) {
    const body = parts[i] as string;
    const eol = parts[i + 1] ?? "";
    if (i === parts.length - 1 && body.length === 0) break;
    lines.push({ text: body, eol });
  }
  return lines;
}

/** Index of the last line of a quoted value that starts on line `start` after `=`; `start` when it is not multi-line. */
function valueEnd(lines: Line[], start: number, rest: string): number {
  const quote = rest[0];
  if (quote !== '"' && quote !== "'") return start;
  const closes = (text: string, from: number): boolean => {
    for (let i = from; i < text.length; i++) {
      if (quote === '"' && text[i] === "\\") i++;
      else if (text[i] === quote) return true;
    }
    return false;
  };
  if (closes(rest, 1)) return start;
  for (let i = start + 1; i < lines.length; i++) if (closes((lines[i] as Line).text, 0)) return i;
  return start;
}

const DEFINITION = /^(\s*)(export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/;

/**
 * Sets key to `line` in a dotenv text: the first definition is replaced in place (keeping
 * `export` and the line's own ending), later ones are dropped, a missing key is appended. Every
 * other line is kept byte for byte, including the lines of other keys' multi-line values.
 */
export function upsertDotenv(text: string, key: string, line: string): string {
  const lines = splitLines(text);
  const lastEol = lines.length > 0 ? (lines[lines.length - 1] as Line).eol || "\n" : "\n";
  const out: string[] = [];
  let found = false;
  for (let i = 0; i < lines.length; i++) {
    const current = lines[i] as Line;
    const match = DEFINITION.exec(current.text);
    if (!match) {
      out.push(current.text + current.eol);
      continue;
    }
    const end = valueEnd(lines, i, match[4] ?? "");
    if (match[3] !== key) {
      for (let j = i; j <= end; j++) out.push((lines[j] as Line).text + (lines[j] as Line).eol);
      i = end;
      continue;
    }
    if (!found) out.push(`${match[1] ?? ""}${match[2] ? "export " : ""}${line}${(lines[end] as Line).eol || "\n"}`);
    found = true;
    i = end;
  }
  if (!found) {
    const last = out[out.length - 1];
    if (last !== undefined && !/\r?\n$/.test(last)) out.push(lastEol);
    out.push(line + lastEol);
  }
  return out.join("");
}

/** Whether key has a definition of its own (not a line inside another key's multi-line value). */
export function definesDotenvKey(text: string, key: string): boolean {
  const lines = splitLines(text);
  for (let i = 0; i < lines.length; i++) {
    const match = DEFINITION.exec((lines[i] as Line).text);
    if (!match) continue;
    if (match[3] === key) return true;
    i = valueEnd(lines, i, match[4] ?? "");
  }
  return false;
}

const STRICT_UTF8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

/** Reads the current file without following a symlink; empty when it does not exist. */
async function readCurrent(path: string): Promise<Buffer> {
  if ((await regularFileOrNull(path)) === null) return Buffer.alloc(0);
  try {
    const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    try {
      return await handle.readFile();
    } finally {
      await handle.close();
    }
  } catch {
    throw new SinkError("file_write_failed", `cannot read ${path}`);
  }
}

/** Upserts `NAME="value"` in a local .env file, rewritten atomically with mode 600. */
export const dotenvSink: Sink = {
  async apply(op, value) {
    const target = op.target as DotenvTarget;
    const current = await readCurrent(target.path);
    let text: string;
    try {
      text = STRICT_UTF8.decode(current);
    } catch {
      throw new SinkError("file_not_utf8", `${target.path} is not UTF-8 text; zks does not rewrite it`);
    } finally {
      current.fill(0);
    }
    const next = Buffer.from(upsertDotenv(text, op.name, dotenvLine(op.name, value.reveal())), "utf8");
    try {
      await writeFileAtomic(target.path, next);
    } finally {
      next.fill(0);
    }
    return {};
  },

  /** The file's mtime when it defines NAME; the text is read only to find the name, then zeroed. */
  async lastModified(op) {
    const target = op.target as DotenvTarget;
    const stats = await regularFileOrNull(target.path);
    if (stats === null) return { status: "missing" };
    const current = await readCurrent(target.path);
    let defined: boolean;
    try {
      defined = definesDotenvKey(STRICT_UTF8.decode(current), op.name);
    } catch {
      throw new SinkError("file_not_utf8", `${target.path} is not UTF-8 text`);
    } finally {
      current.fill(0);
    }
    return defined ? { status: "found", time: stats.mtime } : { status: "missing" };
  },
};
