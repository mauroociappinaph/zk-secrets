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

/** Index of the last line of a quoted value that starts on line `start` after `=`; `start` when it is not multi-line. */
function valueEnd(lines: string[], start: number, rest: string): number {
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
  for (let i = start + 1; i < lines.length; i++) if (closes(lines[i] as string, 0)) return i;
  return start;
}

/**
 * Sets key to `line` in a dotenv text: the first definition is replaced in place (keeping
 * `export`), later ones are dropped, a missing key is appended. Every other line is kept.
 */
export function upsertDotenv(text: string, key: string, line: string): string {
  const eol = text.includes("\r\n") ? "\r\n" : "\n";
  const lines = text.length === 0 ? [] : text.split(eol);
  if (lines.length > 0 && lines[lines.length - 1] === "") lines.pop();
  const definition = new RegExp(`^(\\s*)(export\\s+)?${key}\\s*=\\s*(.*)$`);
  const out: string[] = [];
  let found = false;
  for (let i = 0; i < lines.length; i++) {
    const match = definition.exec(lines[i] as string);
    if (!match) {
      out.push(lines[i] as string);
      continue;
    }
    const end = valueEnd(lines, i, match[3] ?? "");
    if (!found) out.push(`${match[1] ?? ""}${match[2] ? "export " : ""}${line}`);
    found = true;
    i = end;
  }
  if (!found) out.push(line);
  return `${out.join(eol)}${eol}`;
}

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
    const next = Buffer.from(upsertDotenv(current.toString("utf8"), op.name, dotenvLine(op.name, value.reveal())), "utf8");
    current.fill(0);
    try {
      await writeFileAtomic(target.path, next);
    } finally {
      next.fill(0);
    }
    return {};
  },
};
