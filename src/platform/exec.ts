import { spawn } from "node:child_process";

export interface ExecResult {
  code: number;
  stdout: Buffer;
  stderr: Buffer;
}

export interface ExecOptions {
  /** Bytes written to the child's stdin; secrets travel here, never in argv. */
  input?: Buffer | string;
  /** Extra environment variables merged over childEnv (internal callers only). */
  env?: Record<string, string>;
  timeoutMs?: number;
}

export type Exec = (command: string, args: string[], options?: ExecOptions) => Promise<ExecResult>;

/** Fixed search path for child processes; the caller's PATH is never trusted. */
export const SAFE_PATH = "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin";

export interface ExecBase {
  home: string;
  user: string;
}

/** The whole environment of a child process: nothing is forwarded from the parent. */
export function childEnv(base: ExecBase): Record<string, string> {
  return { PATH: SAFE_PATH, HOME: base.home, USER: base.user, LOGNAME: base.user, LANG: "en_US.UTF-8" };
}

/** Runs a binary without a shell, with a fixed environment and captured output. */
export function createExec(base: ExecBase): Exec {
  return (command, args, options = {}) =>
    new Promise((resolve, reject) => {
      const child = spawn(command, args, {
        shell: false,
        stdio: ["pipe", "pipe", "pipe"],
        env: { ...childEnv(base), ...options.env },
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
