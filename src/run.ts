import { readAuditAnchor, writeAuditAnchor } from "./audit/anchor.ts";
import { SHEETS_WEBHOOK_URL } from "./audit/mirror.ts";
import type { ApprovalMode, AuditRecord, AuditStore, Mirror, MirrorResult } from "./audit/types.ts";
import type { HumanChannel } from "./gate/dialog.ts";
import type { Exec } from "./platform/exec.ts";
import { ZKS_KEYCHAIN_SERVICE, type Keychain } from "./platform/keychain.ts";
import { describeDestination } from "./policy/describe.ts";
import { describeTrustKey, loadTrust, saveTrust, trustKeyOf, type TrustFile, type TrustIo } from "./policy/trust.ts";
import { PolicyError, describeSource, planOperations, validatePolicy } from "./policy/validate.ts";
import type { Operation, Policy, Provider, TargetConfig } from "./policy/types.ts";
import { Redactor } from "./secret/redactor.ts";
import type { SecretBuffer } from "./secret/secret-buffer.ts";
import { SinkError, type AwsClientFactory, type Sink } from "./sinks/types.ts";
import { SourceError, resolveValue } from "./sources/resolve.ts";
import { HELP_TEXT } from "./help.ts";
import { resolve as resolvePath } from "node:path";

export const EXIT_OK = 0;
export const EXIT_FAILED = 1;
export const EXIT_USAGE = 2;
export const EXIT_DENIED = 3;

/** One dialog must show every write in full; larger applies are refused, never truncated. */
export const MAX_OPERATIONS_PER_APPROVAL = 20;
export const MAX_DIALOG_LINE = 300;
export const MAX_DIALOG_TEXT = 6000;

const NEW_DESTINATION = "[NEW destination]";
const ALWAYS_ALLOW_NOTE =
  "Always allow: trust every [NEW destination] (whole GitHub owner, Vercel team, AWS profile+role+region or project) for all projects.";

export const TOKEN_ACCOUNTS = ["vercel", "railway", "supabase", "sheets-hmac"] as const;
export type TokenAccount = (typeof TOKEN_ACCOUNTS)[number];

export interface ZksConfig {
  sheets?: { webhookUrl?: string };
}

export interface Deps {
  version: string;
  cwd: string;
  user: string;
  agentId: string;
  now(): Date;
  exec: Exec;
  keychain: Keychain;
  human: HumanChannel;
  fetch: typeof fetch;
  aws: AwsClientFactory;
  sinks: Record<Provider, Sink>;
  openAudit(): AuditStore;
  mirror: Mirror;
  readFile(path: string): Promise<Buffer>;
  /** Writes a file only if it does not exist yet. */
  createFile(path: string, data: string): Promise<boolean>;
  readConfig(): Promise<ZksConfig>;
  writeConfig(config: ZksConfig): Promise<void>;
  /** ~/.config/zks/trust.json as stored, or null when it does not exist; verified by policy/trust.ts. */
  readTrust(): Promise<TrustFile | null>;
  writeTrust(file: TrustFile): Promise<void>;
  doctor(): Promise<Record<string, unknown>>;
  randomBytes?: (size: number) => Buffer;
}

export interface RunOutput {
  exitCode: number;
  stdout: string;
}

interface OperationResult {
  name: string;
  target: string;
  provider: Provider;
  environment: string;
  sensitive: boolean;
  source: string;
  result: "applied" | "denied" | "failed";
  version?: string;
  error?: { code: string; message: string };
  auditId: string;
}

class UsageError extends Error {}

/** A provider write succeeded but its audit record could not be appended. */
class AuditWriteError extends Error {
  readonly op: Operation;
  constructor(op: Operation) {
    super(`the provider write for ${op.name} -> ${op.targetKey} succeeded but its audit record could not be written`);
    this.op = op;
  }
}

const FORBIDDEN_FLAGS = ["--value", "--secret", "--token", "--password"];
const FLAGS_WITH_VALUE = ["--policy", "--only", "--target", "--agent", "--limit", "--project"];

/** Options each command uses; any other option is refused. --help and --version are global. */
const COMMAND_FLAGS: Record<string, string[]> = {
  init: ["--policy", "--project"],
  validate: ["--policy"],
  plan: ["--policy", "--only", "--target"],
  apply: ["--policy", "--only", "--target", "--agent"],
  "audit list": ["--limit", "--project"],
};
const SUBCOMMANDS: Record<string, string[]> = {
  auth: ["status", "set", "delete"],
  audit: ["list", "verify", "sync"],
  config: ["show", "set", "unset"],
  trust: ["list", "remove"],
};
const COMMANDS = ["init", "validate", "plan", "apply", "doctor", ...Object.keys(SUBCOMMANDS)];

interface ParsedArgs {
  positionals: string[];
  flags: Map<string, string>;
}

function parseArgs(argv: string[]): ParsedArgs {
  const positionals: string[] = [];
  const flags = new Map<string, string>();
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i] as string;
    if (!arg.startsWith("-")) {
      positionals.push(arg);
      continue;
    }
    if (!arg.startsWith("--")) throw new UsageError(`unknown option ${arg}`);
    const [flag, inline] = arg.split(/=(.*)/s, 2) as [string, string | undefined];
    if (FORBIDDEN_FLAGS.includes(flag)) {
      throw new UsageError(
        "zks never accepts secret values on the command line; declare a source in zks.policy.json or use `zks auth set`",
      );
    }
    if (flag === "--help" || flag === "--version") {
      flags.set(flag, "true");
      continue;
    }
    if (!FLAGS_WITH_VALUE.includes(flag)) throw new UsageError(`unknown option ${flag}`);
    const value = inline ?? argv[++i];
    if (value === undefined || value.startsWith("--")) throw new UsageError(`option ${flag} needs a value`);
    flags.set(flag, value);
  }
  return { positionals, flags };
}

/** Positionals each command accepts, including the command itself; undefined lets the command report usage. */
function positionalLimit(command: string, sub: string | undefined): number | undefined {
  switch (command) {
    case "init":
    case "validate":
    case "plan":
    case "apply":
    case "doctor":
      return 1;
    case "audit":
      return 2;
    case "auth":
      return sub === "status" ? 2 : sub === "set" || sub === "delete" ? 3 : undefined;
    case "config":
      return sub === "show" ? 2 : sub === "set" ? 4 : sub === "unset" ? 3 : undefined;
    case "trust":
      return sub === "list" ? 2 : sub === "remove" ? 3 : undefined;
    default:
      return undefined;
  }
}

function list(value: string | undefined): string[] | undefined {
  return value === undefined ? undefined : value.split(",").map((s) => s.trim()).filter(Boolean);
}

function json(exitCode: number, body: Record<string, unknown>): RunOutput {
  return { exitCode, stdout: `${JSON.stringify(body, null, 2)}\n` };
}

export function environmentOf(target: TargetConfig): string {
  switch (target.provider) {
    case "vercel":
      return target.environments.join("+");
    case "github":
      return target.environment ?? "";
    case "railway":
      return target.environmentId;
    default:
      return "";
  }
}

async function loadPolicy(deps: Deps, path: string | undefined): Promise<Policy> {
  const file = resolvePath(deps.cwd, path ?? "zks.policy.json");
  const bytes = await deps.readFile(file).catch(() => null);
  if (!bytes) throw new PolicyError([`policy: cannot read ${file}; run \`zks init\` first`]);
  let parsed: unknown;
  try {
    parsed = JSON.parse(bytes.toString("utf8"));
  } catch {
    throw new PolicyError([`policy: ${file} is not valid JSON`]);
  }
  return validatePolicy(parsed);
}

/** Refuses any option the command does not use. Only known command names are echoed. */
function checkFlags(command: string, sub: string | undefined, flags: Map<string, string>): void {
  if (!COMMANDS.includes(command)) return;
  const name = sub !== undefined && SUBCOMMANDS[command]?.includes(sub) ? `${command} ${sub}` : command;
  const allowed = COMMAND_FLAGS[name] ?? [];
  for (const flag of flags.keys()) {
    if (!allowed.includes(flag)) throw new UsageError(`option ${flag} is not valid for ${name}`);
  }
}

function describeOperation(op: Operation, cwd: string): Record<string, unknown> {
  return {
    name: op.name,
    target: op.targetKey,
    provider: op.target.provider,
    environment: environmentOf(op.target),
    destination: describeDestination(op),
    sensitive: op.variable.sensitive,
    source: describeSource(op.variable.source, cwd),
  };
}

/** Every write in full; writes to a destination that is not trusted yet end with [NEW destination]. */
function approvalLines(policy: Policy, ops: Operation[], cwd: string, newKeys: Set<string>): string[] {
  const lines = [`Project: ${policy.project}`, `Write ${ops.length} value(s):`, ""];
  for (const op of ops) {
    lines.push(
      `- ${op.name} -> ${describeDestination(op)} ` +
        `[${op.variable.sensitive ? "secret" : "plain"}; ${describeSource(op.variable.source, cwd)}] (target ${op.targetKey})` +
        (newKeys.has(trustKeyOf(op)) ? ` ${NEW_DESTINATION}` : ""),
    );
  }
  if (newKeys.size > 0) lines.push("", ALWAYS_ALLOW_NOTE);
  return lines;
}

function trustIo(deps: Deps): TrustIo {
  return { keychain: deps.keychain, readTrust: deps.readTrust, writeTrust: deps.writeTrust, randomBytes: deps.randomBytes };
}

export async function run(argv: string[], deps: Deps): Promise<RunOutput> {
  const redactor = new Redactor();
  try {
    const out = await dispatch(argv, deps, redactor);
    return { exitCode: out.exitCode, stdout: redactor.scrub(out.stdout) };
  } catch (error) {
    if (error instanceof UsageError) return json(EXIT_USAGE, { ok: false, error: { code: "usage", message: error.message } });
    if (error instanceof PolicyError) {
      return json(EXIT_USAGE, { ok: false, error: { code: "invalid_policy", message: "invalid policy", issues: error.issues } });
    }
    const message = redactor.scrub(error instanceof Error ? error.message : String(error));
    return json(EXIT_FAILED, { ok: false, error: { code: "internal", message } });
  } finally {
    redactor.clear();
  }
}

async function dispatch(argv: string[], deps: Deps, redactor: Redactor): Promise<RunOutput> {
  const { positionals, flags } = parseArgs(argv);
  const [command, sub, arg] = positionals;
  if (flags.has("--version")) return { exitCode: EXIT_OK, stdout: `${deps.version}\n` };
  if (flags.has("--help") || command === undefined || command === "help") return { exitCode: EXIT_OK, stdout: HELP_TEXT };
  const limit = positionalLimit(command, sub);
  // The extra argument is never echoed: it might be a pasted secret.
  if (limit !== undefined && positionals.length > limit) throw new UsageError("unexpected argument");
  checkFlags(command, sub, flags);

  switch (command) {
    case "init":
      return init(deps, flags.get("--policy"), flags.get("--project"));
    case "validate": {
      const policy = await loadPolicy(deps, flags.get("--policy"));
      return json(EXIT_OK, {
        ok: true,
        project: policy.project,
        targets: Object.keys(policy.targets).length,
        variables: Object.keys(policy.variables).length,
      });
    }
    case "plan": {
      const policy = await loadPolicy(deps, flags.get("--policy"));
      const ops = planOperations(policy, selection(flags));
      return json(EXIT_OK, { ok: true, project: policy.project, operations: ops.map((op) => describeOperation(op, deps.cwd)) });
    }
    case "apply":
      return apply(deps, flags, redactor);
    case "auth":
      return auth(deps, sub, arg);
    case "audit":
      return audit(deps, sub, flags);
    case "config":
      return config(deps, sub, arg, positionals[3]);
    case "trust":
      return trust(deps, sub, arg);
    case "doctor":
      return json(EXIT_OK, { ok: true, ...(await deps.doctor()) });
    default:
      throw new UsageError(`unknown command ${command}; run \`zks help\``);
  }
}

function selection(flags: Map<string, string>) {
  return { only: list(flags.get("--only")), targets: list(flags.get("--target")) };
}

async function apply(deps: Deps, flags: Map<string, string>, redactor: Redactor): Promise<RunOutput> {
  const policy = await loadPolicy(deps, flags.get("--policy"));
  const ops = planOperations(policy, selection(flags));
  if (ops.length === 0) return json(EXIT_OK, { ok: true, project: policy.project, results: [] });
  if (ops.length > MAX_OPERATIONS_PER_APPROVAL) {
    return json(EXIT_USAGE, {
      ok: false,
      error: {
        code: "too_many_operations",
        message: `${ops.length} writes do not fit in one approval dialog (max ${MAX_OPERATIONS_PER_APPROVAL}); narrow with --only or --target`,
      },
    });
  }

  const trustState = await loadTrust(trustIo(deps));
  const trustedKeys = new Set(trustState.destinations.map((d) => d.key));
  const newKeys = [...new Set(ops.map(trustKeyOf))].filter((key) => !trustedKeys.has(key));
  const lines = approvalLines(policy, ops, deps.cwd, new Set(newKeys));
  if (lines.some((line) => line.length > MAX_DIALOG_LINE) || lines.join("\n").length > MAX_DIALOG_TEXT) {
    return json(EXIT_USAGE, {
      ok: false,
      error: { code: "dialog_too_long", message: "the approval text is too long for one dialog; narrow with --only or --target" },
    });
  }
  const trustReport = trustState.valid ? {} : { trust: "invalid" as const };

  const agent = flags.get("--agent") ?? deps.agentId;
  // Every destination already trusted: no dialog. Otherwise the human sees every write.
  const approval: ApprovalMode = newKeys.length === 0 ? "trusted" : "dialog";
  const store = deps.openAudit();
  const results: OperationResult[] = [];
  try {
    const record = (op: Operation, result: OperationResult["result"], extra: { version?: string; errorCode?: string }) =>
      store.append({
        ts: deps.now().toISOString(),
        actorHuman: deps.user,
        actorAgent: agent,
        project: policy.project,
        provider: op.target.provider,
        target: op.targetKey,
        environment: environmentOf(op.target),
        variableName: op.name,
        action: "set",
        sensitive: op.variable.sensitive,
        sourceKind: op.sourceKind,
        result,
        providerVersion: extra.version ?? "",
        errorCode: extra.errorCode ?? "",
        approval,
      });

    const decision = approval === "trusted" ? "once" : await deps.human.approveWithTrust("zks: approve secret changes", lines);
    if (decision === "deny") {
      for (const op of ops) {
        const entry = record(op, "denied", { errorCode: "not_approved" });
        results.push(toResult(op, entry, "denied", undefined, { code: "not_approved", message: "denied or no answer in the approval dialog" }));
      }
      const anchorError = await saveAnchor(deps, store);
      const mirror = await deps.mirror.sync(store);
      return json(EXIT_DENIED, { ok: false, project: policy.project, approval, results, mirror, ...trustReport, ...anchorError });
    }

    let trustChange: { trusted?: string[]; trustError?: string } = {};
    if (decision === "always") {
      const addedAt = deps.now().toISOString();
      try {
        await saveTrust(trustIo(deps), [...trustState.destinations, ...newKeys.map((key) => ({ key, addedAt, addedBy: agent }))]);
        trustChange = { trusted: newKeys };
      } catch {
        trustChange = { trustError: "could not save the trusted destinations; this apply was still approved" };
      }
    }

    const byVariable = new Map<string, Operation[]>();
    for (const op of ops) byVariable.set(op.name, [...(byVariable.get(op.name) ?? []), op]);

    try {
      for (const [name, variableOps] of byVariable) {
        const variable = (variableOps[0] as Operation).variable;
        let value: SecretBuffer | null = null;
        try {
          value = await resolveValue(name, variable, {
            exec: deps.exec,
            keychain: deps.keychain,
            human: deps.human,
            cwd: deps.cwd,
            readFile: deps.readFile,
            randomBytes: deps.randomBytes,
          });
          if (variable.sensitive) redactor.register(value);
        } catch (error) {
          const code = error instanceof SourceError ? error.code : "source_failed";
          const message = redactor.scrub(error instanceof Error ? error.message : String(error));
          for (const op of variableOps) {
            const entry = record(op, "failed", { errorCode: code });
            results.push(toResult(op, entry, "failed", undefined, { code, message }));
          }
          continue;
        }
        try {
          for (const op of variableOps) {
            let version: string | undefined;
            try {
              const sink = deps.sinks[op.target.provider];
              ({ version } = await sink.apply(op, value, {
                fetch: deps.fetch,
                exec: deps.exec,
                keychain: deps.keychain,
                aws: deps.aws,
              }));
            } catch (error) {
              const code = error instanceof SinkError ? error.code : "provider_error";
              const message = redactor.scrub(error instanceof Error ? error.message : String(error)).slice(0, 300);
              const entry = record(op, "failed", { errorCode: code });
              results.push(toResult(op, entry, "failed", undefined, { code, message }));
              continue;
            }
            let entry: AuditRecord;
            try {
              entry = record(op, "applied", { version });
            } catch {
              throw new AuditWriteError(op);
            }
            results.push(toResult(op, entry, "applied", version));
          }
        } finally {
          value.dispose();
        }
      }
    } catch (error) {
      if (!(error instanceof AuditWriteError)) throw error;
      // Stop: further writes would go unaudited.
      await saveAnchor(deps, store);
      return json(EXIT_FAILED, { ok: false, error: { code: "audit_failed", message: error.message }, approval, results, ...trustChange });
    }

    const anchorError = await saveAnchor(deps, store);
    const mirror: MirrorResult = await deps.mirror.sync(store);
    const ok = results.every((r) => r.result === "applied");
    return json(ok ? EXIT_OK : EXIT_FAILED, {
      ok,
      project: policy.project,
      approval,
      results,
      mirror,
      ...trustChange,
      ...trustReport,
      ...anchorError,
    });
  } finally {
    store.close();
  }
}

/** Stores the audit head in the Keychain so `zks audit verify` detects a deleted tail. */
async function saveAnchor(deps: Deps, store: AuditStore): Promise<{ anchorError?: string }> {
  try {
    await writeAuditAnchor(deps.keychain, store.head());
    return {};
  } catch {
    return { anchorError: "could not store the audit anchor in the Keychain" };
  }
}

function toResult(
  op: Operation,
  entry: AuditRecord,
  result: OperationResult["result"],
  version?: string,
  error?: { code: string; message: string },
): OperationResult {
  return {
    name: op.name,
    target: op.targetKey,
    provider: op.target.provider,
    environment: environmentOf(op.target),
    sensitive: op.variable.sensitive,
    source: op.sourceKind,
    result,
    ...(version ? { version } : {}),
    ...(error ? { error } : {}),
    auditId: entry.auditId,
  };
}

async function init(deps: Deps, path: string | undefined, project: string | undefined): Promise<RunOutput> {
  const file = resolvePath(deps.cwd, path ?? "zks.policy.json");
  const template = {
    version: 1,
    project: project ?? "my-project",
    targets: {
      "vercel-prod": { provider: "vercel", projectId: "prj_REPLACE_ME", teamId: "team_REPLACE_ME", environments: ["production", "preview"] },
      "aws-ssm-prod": { provider: "aws-ssm", region: "us-east-1", prefix: "/my-project/prod/" },
    },
    variables: {
      API_SIGNING_KEY: { sensitive: true, source: { kind: "generate", bytes: 32 }, targets: ["vercel-prod", "aws-ssm-prod"] },
      NEXT_PUBLIC_SITE_URL: { sensitive: false, value: "https://example.com", targets: ["vercel-prod"] },
    },
  };
  const created = await deps.createFile(file, `${JSON.stringify(template, null, 2)}\n`);
  if (!created) throw new UsageError(`${file} already exists`);
  return json(EXIT_OK, { ok: true, created: file });
}

function parseAccount(value: string | undefined): TokenAccount {
  if (!value || !(TOKEN_ACCOUNTS as readonly string[]).includes(value)) {
    throw new UsageError(`provider must be one of ${TOKEN_ACCOUNTS.join(", ")}`);
  }
  return value as TokenAccount;
}

async function auth(deps: Deps, sub: string | undefined, arg: string | undefined): Promise<RunOutput> {
  switch (sub) {
    case "status": {
      const status: Record<string, boolean> = {};
      for (const account of TOKEN_ACCOUNTS) status[account] = await deps.keychain.has(ZKS_KEYCHAIN_SERVICE, account);
      return json(EXIT_OK, { ok: true, keychainService: ZKS_KEYCHAIN_SERVICE, tokens: status });
    }
    case "set": {
      const account = parseAccount(arg);
      const value = await deps.human.promptSecret("zks: store token", `Paste the ${account} token. It goes straight to the macOS Keychain.`);
      if (!value) return json(EXIT_DENIED, { ok: false, error: { code: "cancelled", message: "no token entered" } });
      try {
        await deps.keychain.set(ZKS_KEYCHAIN_SERVICE, account, value);
      } finally {
        value.dispose();
      }
      return json(EXIT_OK, { ok: true, stored: account });
    }
    case "delete": {
      const account = parseAccount(arg);
      const approved = await deps.human.approve("zks: delete token", [`Delete the ${account} token from the Keychain?`]);
      if (!approved) return json(EXIT_DENIED, { ok: false, error: { code: "not_approved", message: "deletion not approved" } });
      const removed = await deps.keychain.remove(ZKS_KEYCHAIN_SERVICE, account);
      return json(EXIT_OK, { ok: true, removed });
    }
    default:
      throw new UsageError("usage: zks auth status | zks auth set <provider> | zks auth delete <provider>");
  }
}

async function audit(deps: Deps, sub: string | undefined, flags: Map<string, string>): Promise<RunOutput> {
  const store = deps.openAudit();
  try {
    switch (sub) {
      case "list": {
        const limitRaw = flags.get("--limit") ?? "50";
        const limit = Number(limitRaw);
        if (!Number.isInteger(limit) || limit < 1 || limit > 1000) throw new UsageError("--limit must be an integer between 1 and 1000");
        return json(EXIT_OK, { ok: true, records: store.list({ limit, project: flags.get("--project") }) });
      }
      case "verify": {
        const anchor = await readAuditAnchor(deps.keychain);
        const result = store.verify(anchor ?? undefined);
        return json(result.ok ? EXIT_OK : EXIT_FAILED, { ...result, anchored: anchor !== null });
      }
      case "sync": {
        const mirror = await deps.mirror.sync(store);
        return json(mirror.error ? EXIT_FAILED : EXIT_OK, { ok: !mirror.error, mirror });
      }
      default:
        throw new UsageError("usage: zks audit list [--limit N] [--project P] | zks audit verify | zks audit sync");
    }
  } finally {
    store.close();
  }
}

async function trust(deps: Deps, sub: string | undefined, key: string | undefined): Promise<RunOutput> {
  const io = trustIo(deps);
  switch (sub) {
    case "list": {
      const state = await loadTrust(io);
      return json(EXIT_OK, {
        ok: true,
        valid: state.valid,
        destinations: state.destinations.map((d) => ({ ...d, description: describeTrustKey(d.key) })),
      });
    }
    case "remove": {
      // Reducing trust is always safe, so it needs no dialog. The key is only echoed once it is known.
      if (key === undefined) throw new UsageError("usage: zks trust remove <key>");
      const state = await loadTrust(io);
      const kept = state.destinations.filter((d) => d.key !== key);
      if (kept.length === state.destinations.length) throw new UsageError("not a trusted destination; see `zks trust list`");
      await saveTrust(io, kept);
      return json(EXIT_OK, { ok: true, removed: key });
    }
    default:
      throw new UsageError("usage: zks trust list | zks trust remove <key>");
  }
}

async function config(deps: Deps, sub: string | undefined, key: string | undefined, value: string | undefined): Promise<RunOutput> {
  const current = await deps.readConfig();
  switch (sub) {
    case "show":
      return json(EXIT_OK, { ok: true, config: current });
    case "set": {
      if (key !== "sheets-webhook") throw new UsageError("usage: zks config set sheets-webhook <https://script.google.com/macros/s/.../exec>");
      if (!value || !SHEETS_WEBHOOK_URL.test(value)) throw new UsageError("sheets-webhook must be a deployed Apps Script URL ending in /exec");
      if (!(await deps.human.approve("zks: approve config change", [`Mirror the audit log to ${value} (set sheets-webhook)?`]))) {
        return configNotApproved();
      }
      const next = { ...current, sheets: { ...current.sheets, webhookUrl: value } };
      await deps.writeConfig(next);
      return json(EXIT_OK, { ok: true, config: next });
    }
    case "unset": {
      if (key !== "sheets-webhook") throw new UsageError("usage: zks config unset sheets-webhook");
      if (!(await deps.human.approve("zks: approve config change", ["Stop mirroring the audit log to Google Sheets (unset sheets-webhook)?"]))) {
        return configNotApproved();
      }
      const next = { ...current, sheets: {} };
      await deps.writeConfig(next);
      return json(EXIT_OK, { ok: true, config: next });
    }
    default:
      throw new UsageError("usage: zks config show | zks config set sheets-webhook <url> | zks config unset sheets-webhook");
  }
}

function configNotApproved(): RunOutput {
  return json(EXIT_DENIED, { ok: false, error: { code: "not_approved", message: "config change not approved" } });
}
