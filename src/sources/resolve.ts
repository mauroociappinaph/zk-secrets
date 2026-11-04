import { randomBytes as nodeRandomBytes } from "node:crypto";
import { readFile as nodeReadFile, realpath as nodeRealpath } from "node:fs/promises";
import { isAbsolute, relative, resolve as resolvePath } from "node:path";
import type { SourceSpec, VariableSpec } from "../policy/types.ts";
import type { HumanChannel } from "../gate/dialog.ts";
import type { Exec } from "../platform/exec.ts";
import type { Keychain } from "../platform/keychain.ts";
import { SecretBuffer } from "../secret/secret-buffer.ts";

export interface SourceDeps {
  exec: Exec;
  keychain: Keychain;
  human: HumanChannel;
  cwd: string;
  readFile?: (path: string) => Promise<Buffer>;
  randomBytes?: (size: number) => Buffer;
  realpath?: (path: string) => Promise<string>;
}

export class SourceError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.code = code;
  }
}

/** Resolves the value of one variable. The returned buffer must be disposed by the caller. */
export async function resolveValue(name: string, spec: VariableSpec, deps: SourceDeps): Promise<SecretBuffer> {
  if (!spec.source) return SecretBuffer.fromString(spec.value ?? "");
  return resolveSource(name, spec.source, deps);
}

async function resolveSource(name: string, source: SourceSpec, deps: SourceDeps): Promise<SecretBuffer> {
  switch (source.kind) {
    case "op": {
      const res = await deps.exec("op", ["read", "--no-newline", source.ref], { timeoutMs: 120_000 }).catch(() => null);
      if (!res) throw new SourceError("source_unavailable", "1Password CLI (op) is not available");
      if (res.code !== 0) {
        res.stdout.fill(0);
        throw new SourceError("source_failed", `1Password could not read the reference for ${name} (exit ${res.code})`);
      }
      return adoptNonEmpty(name, res.stdout);
    }
    case "keychain": {
      const value = await deps.keychain.get(source.service, source.account);
      if (!value || value.length === 0) {
        throw new SourceError("source_missing", `Keychain item ${source.service}/${source.account} not found`);
      }
      return value;
    }
    case "prompt": {
      const value = await deps.human.promptSecret("zks: enter secret", `Value for ${name}`);
      if (!value) throw new SourceError("source_cancelled", `no value entered for ${name}`);
      return value;
    }
    case "generate": {
      const random = (deps.randomBytes ?? nodeRandomBytes)(source.bytes ?? 32);
      const encoded = Buffer.from(random.toString(source.encoding ?? "base64url"), "utf8");
      random.fill(0);
      return SecretBuffer.adopt(encoded);
    }
    case "dotenv": {
      const read = deps.readFile ?? nodeReadFile;
      const fullPath = resolvePath(deps.cwd, source.path);
      const inside = relative(resolvePath(deps.cwd), fullPath);
      if (inside === "" || inside.startsWith("..") || isAbsolute(inside)) {
        throw new SourceError("source_invalid", `dotenv path for ${name} must stay inside the project`);
      }
      // Symlinks are resolved too: a .env link to ~/.aws/credentials stays outside the project.
      const real = deps.realpath ?? nodeRealpath;
      const realOrSelf = (path: string) => real(path).catch(() => path);
      const realPath = await realOrSelf(fullPath);
      const realInside = relative(await realOrSelf(resolvePath(deps.cwd)), realPath);
      if (realInside === "" || realInside.startsWith("..") || isAbsolute(realInside)) {
        throw new SourceError("source_invalid", `dotenv path for ${name} must stay inside the project`);
      }
      // Read the path that was checked, so a link swapped in between cannot redirect the read.
      const file = await read(realPath).catch(() => null);
      if (!file) throw new SourceError("source_missing", `dotenv file ${source.path} not readable`);
      const value = findDotenvValue(file.toString("utf8"), source.key ?? name);
      file.fill(0);
      if (value === null) throw new SourceError("source_missing", `key ${source.key ?? name} not found in ${source.path}`);
      return SecretBuffer.fromString(value);
    }
  }
}

function adoptNonEmpty(name: string, bytes: Buffer): SecretBuffer {
  const copy = Buffer.from(bytes);
  bytes.fill(0);
  if (copy.length === 0) throw new SourceError("source_missing", `empty value for ${name}`);
  return SecretBuffer.adopt(copy);
}

/** Minimal dotenv reader: KEY=value, optional export, single or double quotes, # comments. */
export function findDotenvValue(text: string, key: string): string | null {
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (line.length === 0 || line.startsWith("#")) continue;
    const match = /^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/.exec(line);
    if (!match || match[1] !== key) continue;
    let value = match[2] ?? "";
    const quote = value[0];
    if ((quote === '"' || quote === "'") && value.endsWith(quote) && value.length >= 2) {
      value = value.slice(1, -1);
      if (quote === '"') value = value.replace(/\\n/g, "\n").replace(/\\"/g, '"');
    } else {
      value = value.replace(/\s+#.*$/, "");
    }
    return value;
  }
  return null;
}
