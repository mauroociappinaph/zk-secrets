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

export interface Sink {
  apply(op: Operation, value: SecretBuffer, ctx: SinkContext): Promise<SinkResult>;
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
