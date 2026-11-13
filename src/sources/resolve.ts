import { createPublicKey, generateKeyPair, randomBytes as nodeRandomBytes } from "node:crypto";
import { promisify } from "node:util";
import { readFile as nodeReadFile, realpath as nodeRealpath } from "node:fs/promises";
import { isAbsolute, relative, resolve as resolvePath } from "node:path";
import type { GenerateSource, SourceSpec, VariableSpec } from "../policy/types.ts";
import { parseTemplate } from "../policy/template.ts";
import { PASSWORD_DEFAULT_LENGTH, RSA_DEFAULT_BITS } from "../policy/validate.ts";
import type { HumanChannel } from "../gate/dialog.ts";
import type { Exec } from "../platform/exec.ts";
import type { Keychain } from "../platform/keychain.ts";
import type { ToolPaths } from "../platform/tools.ts";
import { SecretBuffer } from "../secret/secret-buffer.ts";

export interface SourceDeps {
  exec: Exec;
  tools: ToolPaths;
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
      const op = deps.tools.op;
      const res = op ? await deps.exec(op, ["read", "--no-newline", source.ref], { timeoutMs: 120_000 }).catch(() => null) : null;
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
    case "clipboard":
      return readClipboard(deps.exec);
    case "generate":
      return generate(source, deps.randomBytes ?? nodeRandomBytes);
    case "public-key":
    case "template":
      throw new SourceError("source_invalid", `${name}: a ${source.kind} source is resolved with createResolver`);
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

/** Resolves policy variables at most once each; derived values read their dependencies from the cache. */
export interface Resolver {
  /** The returned buffer belongs to the resolver: do not dispose it, call resolver.dispose(). */
  resolve(name: string): Promise<SecretBuffer>;
  /** Zeroes every value resolved so far. */
  dispose(): void;
}

/**
 * One resolver per apply, so a generated value is shared by the variables derived from it.
 * onResolved sees each value once, after it is resolved (the caller registers sensitive ones with the redactor).
 */
export function createResolver(
  variables: Record<string, VariableSpec>,
  deps: SourceDeps,
  onResolved: (name: string, spec: VariableSpec, value: SecretBuffer) => void = () => {},
): Resolver {
  const cache = new Map<string, Promise<SecretBuffer>>();
  const owned: SecretBuffer[] = [];

  const dependency = async (name: string, ref: string): Promise<SecretBuffer> => {
    try {
      return await resolve(ref);
    } catch (error) {
      const code = error instanceof SourceError ? error.code : "source_failed";
      const message = error instanceof Error ? error.message : String(error);
      throw new SourceError(code, `${name} uses ${ref}: ${message}`);
    }
  };

  const compute = async (name: string): Promise<SecretBuffer> => {
    const spec = Object.hasOwn(variables, name) ? variables[name] : undefined;
    if (!spec) throw new SourceError("source_invalid", `unknown variable ${name}`);
    const source = spec.source;
    if (source?.kind === "public-key") {
      const privateKey = await dependency(name, source.of);
      const pem = createPublicKey(privateKey.reveal()).export({ type: "spki", format: "pem" });
      return SecretBuffer.fromString(String(pem));
    }
    if (source?.kind === "template") {
      const chunks: Buffer[] = [];
      try {
        for (const part of parseTemplate(source.template)) {
          if ("literal" in part) {
            chunks.push(Buffer.from(part.literal, "utf8"));
            continue;
          }
          const value = (await dependency(name, part.ref)).reveal();
          chunks.push(Buffer.from(part.url ? encodeURIComponent(value) : value, "utf8"));
        }
        return SecretBuffer.adopt(Buffer.concat(chunks));
      } finally {
        for (const chunk of chunks) chunk.fill(0);
      }
    }
    return resolveValue(name, spec, deps);
  };

  const resolve = (name: string): Promise<SecretBuffer> => {
    let pending = cache.get(name);
    if (!pending) {
      pending = compute(name).then((value) => {
        owned.push(value);
        onResolved(name, variables[name] as VariableSpec, value);
        return value;
      });
      cache.set(name, pending);
    }
    return pending;
  };

  return {
    resolve,
    dispose() {
      for (const value of owned) value.dispose();
      owned.length = 0;
    },
  };
}

const LOWER = "abcdefghijklmnopqrstuvwxyz";
const UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS = "0123456789";
/** Printable ASCII symbols without quotes, backslash, backtick or space, so values survive .env and shell quoting. */
const SYMBOLS = "!#$%&()*+,-./:;<=>?@[]^_{|}~";
/** A random source that keeps failing the rejection test is broken, not unlucky. */
const MAX_RANDOM_DRAWS = 100_000;

/** Uniform integers below n (n <= 256) by rejection sampling over random bytes. */
class UniformIndex {
  #random: (size: number) => Buffer;
  #pool: Buffer = Buffer.alloc(0);
  #pos = 0;
  #draws = 0;

  constructor(random: (size: number) => Buffer) {
    this.#random = random;
  }

  below(n: number): number {
    const limit = 256 - (256 % n);
    for (;;) {
      if (++this.#draws > MAX_RANDOM_DRAWS) throw new SourceError("source_failed", "the random source returned unusable bytes");
      if (this.#pos >= this.#pool.length) {
        this.#pool.fill(0);
        this.#pool = this.#random(64);
        this.#pos = 0;
      }
      const byte = this.#pool[this.#pos++] as number;
      if (byte < limit) return byte % n;
    }
  }

  dispose(): void {
    this.#pool.fill(0);
  }
}

function password(source: GenerateSource, random: (size: number) => Buffer): SecretBuffer {
  const length = source.length ?? PASSWORD_DEFAULT_LENGTH;
  const classes = [
    source.lower !== false ? LOWER : "",
    source.upper !== false ? UPPER : "",
    source.digits !== false ? DIGITS : "",
    source.symbols !== false ? SYMBOLS : "",
  ].filter(Boolean);
  const all = classes.join("");
  const index = new UniformIndex(random);
  const out = Buffer.alloc(length);
  try {
    // One character of each enabled class, the rest from all of them, then a Fisher-Yates shuffle.
    let k = 0;
    for (const cls of classes) out[k++] = cls.charCodeAt(index.below(cls.length));
    while (k < length) out[k++] = all.charCodeAt(index.below(all.length));
    for (let i = length - 1; i > 0; i--) {
      const j = index.below(i + 1);
      const tmp = out[i] as number;
      out[i] = out[j] as number;
      out[j] = tmp;
    }
  } catch (error) {
    out.fill(0);
    throw error;
  } finally {
    index.dispose();
  }
  return SecretBuffer.adopt(out);
}

function uuid(random: (size: number) => Buffer): SecretBuffer {
  const bytes = Buffer.from(random(16));
  bytes[6] = ((bytes[6] as number) & 0x0f) | 0x40;
  bytes[8] = ((bytes[8] as number) & 0x3f) | 0x80;
  const hex = bytes.toString("hex");
  bytes.fill(0);
  return SecretBuffer.fromString(`${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`);
}

function encodedRandom(random: (size: number) => Buffer, size: number, encoding: "base64url" | "hex"): SecretBuffer {
  const bytes = random(size);
  const encoded = Buffer.from(bytes.toString(encoding), "utf8");
  bytes.fill(0);
  return SecretBuffer.adopt(encoded);
}

const generateKeyPairAsync = promisify(generateKeyPair);

async function generate(source: GenerateSource, random: (size: number) => Buffer): Promise<SecretBuffer> {
  switch (source.format ?? "random") {
    case "random":
      return encodedRandom(random, source.bytes ?? 32, source.encoding ?? "base64url");
    case "uuid":
      return uuid(random);
    case "jwt-secret":
      return encodedRandom(random, 64, "base64url");
    case "password":
      return password(source, random);
    case "rsa-private-key": {
      const { privateKey } = await generateKeyPairAsync("rsa", { modulusLength: source.bits ?? RSA_DEFAULT_BITS });
      return SecretBuffer.fromString(String(privateKey.export({ type: "pkcs8", format: "pem" })));
    }
    case "ed25519-private-key": {
      const { privateKey } = await generateKeyPairAsync("ed25519");
      return SecretBuffer.fromString(String(privateKey.export({ type: "pkcs8", format: "pem" })));
    }
  }
}

export const PBPASTE = "/usr/bin/pbpaste";
export const PBCOPY = "/usr/bin/pbcopy";

/**
 * Reads the macOS clipboard, drops one trailing newline (a copy from a terminal adds it) and
 * clears the clipboard so the value does not linger. An empty clipboard is source_missing and
 * is left as is. Clearing is best effort: the value is already read.
 */
export async function readClipboard(exec: Exec): Promise<SecretBuffer> {
  const value = await pasteClipboard(exec);
  await clearClipboard(exec);
  return value;
}

/** Reads the clipboard without clearing it, with readClipboard's newline and error rules. */
export async function pasteClipboard(exec: Exec): Promise<SecretBuffer> {
  const res = await exec(PBPASTE, [], { timeoutMs: 10_000 }).catch(() => null);
  if (!res) throw new SourceError("source_unavailable", "the clipboard is not available (pbpaste)");
  if (res.code !== 0) {
    res.stdout.fill(0);
    throw new SourceError("source_failed", `pbpaste could not read the clipboard (exit ${res.code})`);
  }
  let end = res.stdout.length;
  if (end > 0 && res.stdout[end - 1] === 0x0a) end--;
  if (end > 0 && res.stdout[end - 1] === 0x0d) end--;
  const copy = Buffer.from(res.stdout.subarray(0, end));
  res.stdout.fill(0);
  if (copy.length === 0) throw new SourceError("source_missing", "the clipboard is empty");
  return SecretBuffer.adopt(copy);
}

/** Empties the clipboard; false when pbcopy failed. */
export async function clearClipboard(exec: Exec): Promise<boolean> {
  const res = await exec(PBCOPY, [], { input: Buffer.alloc(0), timeoutMs: 10_000 }).catch(() => null);
  return res !== null && res.code === 0;
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
      // Double quotes decode the escapes the dotenv target writes: \\ \" \$ \n \r.
      if (quote === '"') value = value.replace(/\\([\\"$nr])/g, (_, c: string) => (c === "n" ? "\n" : c === "r" ? "\r" : c));
    } else {
      value = value.replace(/\s+#.*$/, "");
    }
    return value;
  }
  return null;
}
