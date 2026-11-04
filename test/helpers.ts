import { mkdtempSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { openAuditStore } from "../src/audit/store.ts";
import type { Mirror } from "../src/audit/types.ts";
import type { HumanChannel } from "../src/gate/dialog.ts";
import type { Exec, ExecOptions, ExecResult } from "../src/platform/exec.ts";
import type { Keychain } from "../src/platform/keychain.ts";
import type { Deps, ZksConfig } from "../src/run.ts";
import { SecretBuffer } from "../src/secret/secret-buffer.ts";
import { createSinks } from "../src/sinks/index.ts";
import type { AwsClient, AwsClientFactory } from "../src/sinks/types.ts";

export const CANARY = "zks-canary-7f3a9c2e51d4";

export function tempDir(): string {
  return mkdtempSync(join(tmpdir(), "zks-test-"));
}

export interface ExecCall {
  command: string;
  args: string[];
  input: string;
}

export function fakeExec(handler: (call: ExecCall) => Partial<ExecResult> = () => ({})) {
  const calls: ExecCall[] = [];
  const exec: Exec = async (command: string, args: string[], options: ExecOptions = {}) => {
    const input = options.input === undefined ? "" : Buffer.from(options.input).toString("utf8");
    const call = { command, args: [...args], input };
    calls.push(call);
    const res = handler(call);
    return { code: res.code ?? 0, stdout: res.stdout ?? Buffer.alloc(0), stderr: res.stderr ?? Buffer.alloc(0) };
  };
  return { exec, calls };
}

export function fakeKeychain(items: Record<string, string> = {}) {
  const store = new Map(Object.entries(items));
  const keychain: Keychain = {
    async get(service, account) {
      const v = store.get(`${service}/${account}`);
      return v === undefined ? null : SecretBuffer.fromString(v);
    },
    async set(service, account, value) {
      store.set(`${service}/${account}`, value.reveal());
    },
    async remove(service, account) {
      return store.delete(`${service}/${account}`);
    },
    async has(service, account) {
      return store.has(`${service}/${account}`);
    },
  };
  return { keychain, store };
}

export interface FetchCall {
  url: string;
  init: RequestInit;
  body: string;
}

export function fakeFetch(respond: (call: FetchCall) => { status?: number; body?: unknown } = () => ({})) {
  const calls: FetchCall[] = [];
  const fetchFn = (async (url: string | URL, init: RequestInit = {}) => {
    const call = { url: String(url), init, body: typeof init.body === "string" ? init.body : "" };
    calls.push(call);
    const res = respond(call);
    const text = res.body === undefined ? "{}" : typeof res.body === "string" ? res.body : JSON.stringify(res.body);
    return new Response(text, { status: res.status ?? 200, headers: { "content-type": "application/json" } });
  }) as typeof fetch;
  return { fetch: fetchFn, calls };
}

export interface AwsCall {
  client: "ssm" | "sm";
  command: string;
  input: Record<string, unknown>;
}

export function fakeAws(respond: (call: AwsCall) => unknown = () => ({})) {
  const calls: AwsCall[] = [];
  const client = (kind: AwsCall["client"]): AwsClient => ({
    async send(command: unknown) {
      const c = command as { constructor: { name: string }; input: Record<string, unknown> };
      const call = { client: kind, command: c.constructor.name, input: c.input };
      calls.push(call);
      return respond(call);
    },
  });
  const aws: AwsClientFactory = { ssm: () => client("ssm"), secretsManager: () => client("sm") };
  return { aws, calls };
}

export function fakeHuman(options: { approve?: boolean; prompt?: string | null } = {}) {
  const approvals: string[][] = [];
  const prompts: string[] = [];
  const human: HumanChannel = {
    async approve(_title, lines) {
      approvals.push(lines);
      return options.approve ?? true;
    },
    async promptSecret(_title, message) {
      prompts.push(message);
      const v = options.prompt === undefined ? null : options.prompt;
      return v === null ? null : SecretBuffer.fromString(v);
    },
  };
  return { human, approvals, prompts };
}

export interface TestHarness {
  deps: Deps;
  dir: string;
  auditDb: string;
  files: Map<string, string>;
  config: ZksConfig;
  exec: ReturnType<typeof fakeExec>;
  fetch: ReturnType<typeof fakeFetch>;
  aws: ReturnType<typeof fakeAws>;
  keychain: ReturnType<typeof fakeKeychain>;
  human: ReturnType<typeof fakeHuman>;
  mirrorCalls: number;
}

export function harness(
  options: {
    policy?: unknown;
    files?: Record<string, string>;
    keychain?: Record<string, string>;
    approve?: boolean;
    prompt?: string | null;
    fetch?: Parameters<typeof fakeFetch>[0];
    exec?: Parameters<typeof fakeExec>[0];
    aws?: Parameters<typeof fakeAws>[0];
  } = {},
): TestHarness {
  const dir = tempDir();
  const auditDb = join(dir, "state", "audit.db");
  const files = new Map(Object.entries(options.files ?? {}).map(([k, v]) => [join(dir, k), v]));
  if (options.policy !== undefined) files.set(join(dir, "zks.policy.json"), JSON.stringify(options.policy));
  const exec = fakeExec(options.exec);
  const fetch = fakeFetch(options.fetch);
  const aws = fakeAws(options.aws);
  const keychain = fakeKeychain(options.keychain);
  const human = fakeHuman({ approve: options.approve, prompt: options.prompt });
  const h: TestHarness = {
    dir,
    auditDb,
    files,
    config: {},
    exec,
    fetch,
    aws,
    keychain,
    human,
    mirrorCalls: 0,
    deps: undefined as unknown as Deps,
  };
  const mirror: Mirror = {
    async sync(store) {
      h.mirrorCalls++;
      return { configured: false, pushed: 0, pending: store.pendingMirror(1000).length };
    },
  };
  h.deps = {
    version: "0.0.0-test",
    cwd: dir,
    user: "tester",
    agentId: "pi:test-session",
    now: () => new Date("2026-11-04T12:00:00.000Z"),
    exec: exec.exec,
    keychain: keychain.keychain,
    human: human.human,
    fetch: fetch.fetch,
    aws: aws.aws,
    sinks: createSinks(),
    openAudit: () => openAuditStore(auditDb),
    mirror,
    readFile: async (path) => {
      const content = files.get(path);
      if (content === undefined) throw new Error("ENOENT");
      return Buffer.from(content);
    },
    createFile: async (path, data) => {
      if (files.has(path)) return false;
      files.set(path, data);
      return true;
    },
    readConfig: async () => h.config,
    writeConfig: async (config) => {
      h.config = config;
    },
    doctor: async () => ({ doctor: "fake" }),
    randomBytes: (n) => Buffer.alloc(n, 7),
  };
  return h;
}

/** Every byte the audit store wrote: DB plus WAL/SHM files. */
export async function auditBytes(auditDb: string): Promise<string> {
  const parts = await Promise.all(
    ["", "-wal", "-shm"].map((suffix) => readFile(auditDb + suffix).then((b) => b.toString("latin1"), () => "")),
  );
  return parts.join("");
}

export function parse(stdout: string): Record<string, any> {
  return JSON.parse(stdout) as Record<string, any>;
}
