import { spawn } from "node:child_process";

export interface ExecResult {
  code: number;
  stdout: Buffer;
  stderr: Buffer;
}

export interface ExecOptions {
  /** Bytes written to the child's stdin; secrets travel here, never in argv. */
  input?: Buffer | string;
  /** Extra environment variables merged over the minimal base environment. */
  env?: Record<string, string>;
  timeoutMs?: number;
}

export type Exec = (command: string, args: string[], options?: ExecOptions) => Promise<ExecResult>;

const BASE_ENV_KEYS = ["PATH", "HOME", "USER", "LOGNAME", "LANG", "TMPDIR", "SHELL"];
/** Prefixes forwarded so authenticated CLIs (1Password, GitHub) keep working. */
const FORWARDED_PREFIXES = ["OP_", "GH_", "XDG_"];

export function minimalEnv(source: NodeJS.ProcessEnv): Record<string, string> {
  const env: Record<string, string> = {};
  for (const [key, value] of Object.entries(source)) {
    if (value === undefined) continue;
    if (BASE_ENV_KEYS.includes(key) || FORWARDED_PREFIXES.some((p) => key.startsWith(p))) env[key] = value;
  }
  return env;
}

/** Runs a binary without a shell, with a minimal environment and captured output. */
export function createExec(parentEnv: NodeJS.ProcessEnv = process.env): Exec {
  return (command, args, options = {}) =>
    new Promise((resolve, reject) => {
      const child = spawn(command, args, {
        shell: false,
        stdio: ["pipe", "pipe", "pipe"],
        env: { ...minimalEnv(parentEnv), ...options.env },
        timeout: options.timeoutMs ?? 120_000,
      });
      const stdout: Buffer[] = [];
      const stderr: Buffer[] = [];
      child.stdout.on("data", (chunk: Buffer) => stdout.push(chunk));
      child.stderr.on("data", (chunk: Buffer) => stderr.push(chunk));
      child.on("error", reject);
      child.on("close", (code) =>
        resolve({ code: code ?? 1, stdout: Buffer.concat(stdout), stderr: Buffer.concat(stderr) }),
      );
      child.stdin.on("error", () => undefined);
      child.stdin.end(options.input ?? "");
    });
}
