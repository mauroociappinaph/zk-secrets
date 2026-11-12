import { spawn } from "node:child_process";
import { accessSync, constants, statSync } from "node:fs";
import { join, resolve as resolvePath } from "node:path";

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

/** An existing regular file (symlinks followed) the current user may execute. */
export function isExecutableFile(path: string): boolean {
  try {
    accessSync(path, constants.X_OK);
    return statSync(path).isFile();
  } catch {
    return false;
  }
}

/**
 * Absolute path of command: a name without "/" is looked up on searchPath (":"-separated, absolute
 * entries only), any other value is resolved against cwd. null when it is not an executable file.
 */
export function resolveExecutable(
  command: string,
  cwd: string,
  searchPath: string,
  isExecutable: (path: string) => boolean = isExecutableFile,
): string | null {
  if (command === "") return null;
  if (command.includes("/")) {
    const path = resolvePath(cwd, command);
    return isExecutable(path) ? path : null;
  }
  for (const dir of searchPath.split(":")) {
    if (!dir.startsWith("/")) continue;
    const path = join(dir, command);
    if (isExecutable(path)) return path;
  }
  return null;
}

export interface ChildExit {
  code: number | null;
  signal: NodeJS.Signals | null;
}

export interface SpawnedChild {
  /** null once the process started; the spawn error otherwise (then `exited` never settles). */
  spawned: Promise<Error | null>;
  exited: Promise<ChildExit>;
  kill(signal: NodeJS.Signals): void;
}

/**
 * Starts path with inherited stdio in cwd. The environment is childEnv plus options.env, copied
 * by spawn() before this function returns, so the caller may zero its values right after.
 */
export type SpawnInherited = (path: string, args: string[], options: { cwd: string; env: Record<string, string> }) => SpawnedChild;

export function createSpawnInherited(base: ExecBase): SpawnInherited {
  return (path, args, options) => {
    const child = spawn(path, args, { shell: false, stdio: "inherit", cwd: options.cwd, env: { ...childEnv(base), ...options.env } });
    // While the child runs zks stays alive to return its exit code: SIGINT, SIGTERM and SIGHUP
    // sent to zks are forwarded to the child (Ctrl-C also reaches it through the terminal).
    const signals = ["SIGINT", "SIGTERM", "SIGHUP"] as const;
    const forward = (signal: NodeJS.Signals) => void child.kill(signal);
    for (const signal of signals) process.on(signal, forward);
    const release = () => {
      for (const signal of signals) process.off(signal, forward);
    };
    const spawned = new Promise<Error | null>((resolve) => {
      child.once("spawn", () => resolve(null));
      child.on("error", (error) => {
        release();
        resolve(error);
      });
    });
    const exited = new Promise<ChildExit>((resolve) => {
      child.once("exit", (code, signal) => {
        release();
        resolve({ code, signal });
      });
    });
    return { spawned, exited, kill: (signal) => void child.kill(signal) };
  };
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
