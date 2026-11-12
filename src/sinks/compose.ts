import { join } from "node:path";
import type { ComposeTarget } from "../policy/types.ts";
import { privateDirectory, writeFileAtomic } from "./files.ts";
import type { Sink } from "./types.ts";

/** Writes `<dir>/<NAME>` (mode 600, dir 700) for a Compose `secrets: <name>: file:` entry. */
export const composeSink: Sink = {
  async apply(op, value) {
    const target = op.target as ComposeTarget;
    await privateDirectory(target.dir);
    const bytes = Buffer.from(value.reveal(), "utf8");
    try {
      await writeFileAtomic(join(target.dir, op.name), bytes);
    } finally {
      bytes.fill(0);
    }
    return {};
  },
};
