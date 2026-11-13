import type { AwsSmTarget, AwsSsmTarget, Operation } from "../policy/types.ts";
import type { Exec } from "../platform/exec.ts";
import type { Keychain } from "../platform/keychain.ts";
import type { ToolPaths } from "../platform/tools.ts";
import type { SecretBuffer } from "../secret/secret-buffer.ts";

/** Minimal AWS SDK v3 client surface: `send(new XCommand(input))`. */
export interface AwsClient {
  send(command: unknown): Promise<unknown>;
}

export interface AwsClientFactory {
  ssm(target: AwsSsmTarget): AwsClient;
  secretsManager(target: AwsSmTarget): AwsClient;
}

export interface SinkContext {
  fetch: typeof fetch;
  exec: Exec;
  keychain: Keychain;
  aws: AwsClientFactory;
  tools: ToolPaths;
}

export interface SinkResult {
  /** Provider-side version or id, never derived from the value. */
  version?: string;
}

/** When the destination last changed, from provider metadata only (never a value). */
export type LastModified =
  | { status: "found"; time: Date }
  | { status: "missing" }
  | { status: "unsupported"; reason: string };

export interface Sink {
  apply(op: Operation, value: SecretBuffer, ctx: SinkContext): Promise<SinkResult>;
  /**
   * `zks rotate NAME --check`: read-only, metadata only. Absent when the provider exposes no
   * timestamp. Failures throw SinkError like apply.
   */
  lastModified?(op: Operation, ctx: SinkContext): Promise<LastModified>;
}

/** A provider time as a Date; null when absent or unparsable. */
export function providerTime(value: unknown): Date | null {
  if (value instanceof Date) return Number.isFinite(value.getTime()) ? value : null;
  if (typeof value !== "string" && typeof value !== "number") return null;
  const time = new Date(value);
  return Number.isFinite(time.getTime()) ? time : null;
}

/** Errors carry only a code, an HTTP status and a short provider-safe message. */
export class SinkError extends Error {
  readonly code: string;
  readonly status: number | undefined;
  constructor(code: string, message: string, status?: number) {
    super(message);
    this.code = code;
    this.status = status;
  }
}
