import { mkdtempSync, rmSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import sodium from "libsodium-wrappers";
import { openAuditStore } from "../src/audit/store.ts";
import type { Mirror } from "../src/audit/types.ts";
import type { HumanChannel, TrustDecision } from "../src/gate/dialog.ts";
import { createSpawnInherited, type Exec, type ExecOptions, type ExecResult } from "../src/platform/exec.ts";
import type { Keychain } from "../src/platform/keychain.ts";
import type { ToolPaths } from "../src/platform/tools.ts";
import type { TrustFile } from "../src/policy/trust.ts";
import type { Deps, ZksConfig } from "../src/run.ts";
import { SecretBuffer } from "../src/secret/secret-buffer.ts";
import { createSinks } from "../src/sinks/index.ts";
import type { AwsClient, AwsClientFactory } from "../src/sinks/types.ts";

export const CANARY = "zks-canary-7f3a9c2e51d4";

await sodium.ready;
/** Test keypair standing in for a GitHub repository's Actions public key. */
export const GITHUB_KEYPAIR = sodium.crypto_box_keypair();
export const GITHUB_KEY_ID = "568250167242549743";
export const GITHUB_PUBLIC_KEY = sodium.to_base64(GITHUB_KEYPAIR.publicKey, sodium.base64_variants.ORIGINAL);
export const GH_TOKEN = "gho_testtoken123";

/** Absolute tool paths the harness resolves, as install.sh writes them to tools.json. */
export const TEST_TOOLS: ToolPaths = { egoBrowser: "/test/bin/ego-browser", gh: "/test/bin/gh", op: "/test/bin/op", docker: "/test/bin/docker" };

/** Opens a GitHub sealed box with the test keypair. */
export function openSealed(encryptedValue: string): string {
  const sealed = sodium.from_base64(encryptedValue, sodium.base64_variants.ORIGINAL);
  return sodium.to_string(sodium.crypto_box_seal_open(sealed, GITHUB_KEYPAIR.publicKey, GITHUB_KEYPAIR.privateKey));
}

/** What a healthy provider answers: GitHub public key, 201/204 on writes, 200 {} elsewhere. */
export function providerResponse(call: FetchCall): { status?: number; body?: unknown } {
  if (call.url.startsWith("https://api.github.com/")) {
    if (call.url.endsWith("/public-key")) return { body: { key_id: GITHUB_KEY_ID, key: GITHUB_PUBLIC_KEY } };
    return { status: call.init.method === "PUT" || call.init.method === "POST" ? 201 : 204 };
  }
  return {};
}

/** `gh auth token` answers with a test token; every other command succeeds silently. */
export function ghTokenExec(call: ExecCall): Partial<ExecResult> {
  if (call.command === TEST_TOOLS.gh && call.args[0] === "auth" && call.args[1] === "token") return { stdout: Buffer.from(`${GH_TOKEN}\n`) };
  return {};
}

const tempDirs: string[] = [];
process.on("exit", () => {
  for (const dir of tempDirs) rmSync(dir, { recursive: true, force: true });
});

/** A fresh directory under the system temp dir, removed when the test process exits. */
export function tempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "zks-test-"));
  tempDirs.push(dir);
  return dir;
}

export interface ExecCall {
  command: string;
  args: string[];
  input: string;
  env?: Record<string, string>;
}

export function fakeExec(handler: (call: ExecCall) => Partial<ExecResult> = () => ({})) {
  const calls: ExecCall[] = [];
  const exec: Exec = async (command: string, args: string[], options: ExecOptions = {}) => {
    const input = options.input === undefined ? "" : Buffer.from(options.input).toString("utf8");
    const call: ExecCall = { command, args: [...args], input, ...(options.env ? { env: { ...options.env } } : {}) };
    calls.push(call);
    const res = handler(call);
    return { code: res.code ?? 0, stdout: res.stdout ?? Buffer.alloc(0), stderr: res.stderr ?? Buffer.alloc(0) };
  };
  return { exec, calls };
}

export function fakeKeychain(items: Record<string, string> = {}) {
  const store = new Map(Object.entries(items));
  // Pre-seeded items count as created long ago; set() stamps the current time.
  const modified = new Map<string, Date>([...store.keys()].map((k) => [k, new Date(0)]));
  const keychain: Keychain = {
    async modifiedAt(service, account) {
      return store.has(`${service}/${account}`) ? (modified.get(`${service}/${account}`) ?? null) : null;
    },
    async get(service, account) {
      const v = store.get(`${service}/${account}`);
      return v === undefined ? null : SecretBuffer.fromString(v);
    },
    async set(service, account, value) {
      store.set(`${service}/${account}`, value.reveal());
      modified.set(`${service}/${account}`, new Date());
    },
    async remove(service, account) {
      return store.delete(`${service}/${account}`);
    },
    async has(service, account) {
      return store.has(`${service}/${account}`);
    },
  };
  return { keychain, store, modified };
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
    const status = res.status ?? 200;
    const text = res.body === undefined ? "{}" : typeof res.body === "string" ? res.body : JSON.stringify(res.body);
    const nullBody = status === 204 || status === 205 || status === 304;
    return new Response(nullBody ? null : text, { status, headers: { "content-type": "application/json" } });
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

export function fakeHuman(options: { approve?: boolean; prompt?: string | null; decision?: TrustDecision } = {}) {
  const approvals: string[][] = [];
  const prompts: string[] = [];
  const human: HumanChannel = {
    async approve(_title, lines) {
      approvals.push(lines);
      return options.approve ?? true;
    },
    async approveWithTrust(_title, lines) {
      approvals.push(lines);
      return options.decision ?? ((options.approve ?? true) ? "once" : "deny");
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
  /** In-memory ~/.config/zks/trust.json; null when the file does not exist. */
  trust: TrustFile | null;
}

export function harness(
  options: {
    policy?: unknown;
    files?: Record<string, string>;
    keychain?: Record<string, string>;
    approve?: boolean;
    prompt?: string | null;
    decision?: TrustDecision;
    fetch?: Parameters<typeof fakeFetch>[0];
    exec?: Parameters<typeof fakeExec>[0];
    aws?: Parameters<typeof fakeAws>[0];
  } = {},
): TestHarness {
  const dir = tempDir();
  const auditDb = join(dir, "state", "audit.db");
  const files = new Map(Object.entries(options.files ?? {}).map(([k, v]) => [join(dir, k), v]));
  if (options.policy !== undefined) files.set(join(dir, "zks.policy.json"), JSON.stringify(options.policy));
  const exec = fakeExec(options.exec ?? ghTokenExec);
  const fetch = fakeFetch(options.fetch ?? providerResponse);
  const aws = fakeAws(options.aws);
  const keychain = fakeKeychain(options.keychain);
  const human = fakeHuman({ approve: options.approve, prompt: options.prompt, decision: options.decision });
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
    trust: null,
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
    tools: { ...TEST_TOOLS },
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
    readTrust: async () => (h.trust === null ? null : structuredClone(h.trust)),
    writeTrust: async (file) => {
      h.trust = structuredClone(file);
    },
    doctor: async () => ({ doctor: "fake" }),
    // Never the real fixer: it would chmod the user's ~/.config/zks.
    fixPermissions: async () => ({ fixed: [], failed: [] }),
    // Real spawn, used only by `zks run` tests with a fake child script in the temp dir.
    spawnInherited: createSpawnInherited({ home: dir, user: "tester" }),
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
