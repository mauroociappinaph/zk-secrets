import { randomBytes as nodeRandomBytes } from "node:crypto";
import { readAuditAnchor, writeAuditAnchor } from "./audit/anchor.ts";
import { SHEETS_WEBHOOK_URL } from "./audit/mirror.ts";
import type {
  ApprovalMode,
  AuditRecord,
  AuditResult,
  AuditStore,
  CaptureSourceKind,
  Mirror,
  MirrorResult,
  WrittenDestination,
} from "./audit/types.ts";
import { LOGIN_RECIPES, loginRecipe } from "./capture/recipes.ts";
import { runCapture, runLogin } from "./capture/run.ts";
import { CAPTURE_WAIT_MS, type CaptureErrorCode, type CaptureOutcome, type LoginPending } from "./capture/script.ts";
import { MAX_LINES, type HumanChannel } from "./gate/dialog.ts";
import { SAFE_PATH, resolveExecutable, type Exec, type SpawnInherited, type SpawnedChild } from "./platform/exec.ts";
import { ZKS_KEYCHAIN_SERVICE, type Keychain } from "./platform/keychain.ts";
import type { PermissionFix } from "./platform/permissions.ts";
import type { ToolPaths } from "./platform/tools.ts";
import { describeDestination, describeEffect, summarizeEffects } from "./policy/describe.ts";
import { describeTrustKey, loadTrust, saveTrust, trustKeyOf, type TrustFile, type TrustIo } from "./policy/trust.ts";
import {
  PROJECT_NAME,
  PolicyError,
  dependentsOf,
  describeSource,
  generatedDependencies,
  planOperations,
  sourceKindOf,
  validatePolicy,
} from "./policy/validate.ts";
import type { Operation, Policy, Provider, TargetConfig } from "./policy/types.ts";
import { Redactor } from "./secret/redactor.ts";
import { SecretBuffer } from "./secret/secret-buffer.ts";
import { SinkError, type AwsClientFactory, type Sink } from "./sinks/types.ts";
import { SourceError, createResolver } from "./sources/resolve.ts";
import { HELP_TEXT } from "./help.ts";
import { constants as osConstants } from "node:os";
import { join, resolve as resolvePath } from "node:path";

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

export const TOKEN_ACCOUNTS = ["vercel", "railway", "supabase", "netlify", "sheets-hmac"] as const;
export type TokenAccount = (typeof TOKEN_ACCOUNTS)[number];

export interface ZksConfig {
  sheets?: { webhookUrl?: string };
  /** ego-browser profile for `zks capture --isolated`; never the default profile. */
  capture?: { profileId?: string };
}

export interface Deps {
  version: string;
  cwd: string;
  user: string;
  agentId: string;
  now(): Date;
  exec: Exec;
  /** Absolute paths of ego-browser, gh and op (tools.json of the install); never a PATH lookup. */
  tools: ToolPaths;
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
  /** `zks doctor --fix`: directory and file modes of ~/.config/zks and ~/.local/state/zks only. */
  fixPermissions(): Promise<PermissionFix>;
  /** `zks run`: starts the approved command with inherited stdio and childEnv plus the injected values. */
  spawnInherited: SpawnInherited;
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
const FLAGS_WITH_VALUE = [
  "--policy",
  "--only",
  "--target",
  "--agent",
  "--limit",
  "--project",
  "--space",
  "--page",
  "--selector",
  "--store",
  "--click",
  "--origin",
  "--generate",
  "--from",
  "--url",
  "--user",
  "--user-selector",
  "--password-selector",
  "--submit-selector",
  "--success-selector",
  "--recipe",
];

/** Options each command uses; any other option is refused. --help and --version are global. */
const COMMAND_FLAGS: Record<string, string[]> = {
  init: ["--policy", "--project"],
  validate: ["--policy"],
  plan: ["--policy", "--only", "--target"],
  apply: ["--policy", "--only", "--target", "--agent"],
  rotate: ["--policy", "--target"],
  run: ["--policy", "--only", "--agent"],
  inventory: ["--policy", "--project"],
  doctor: ["--fix"],
  "audit list": ["--limit", "--project"],
  "capture read": ["--space", "--page", "--selector", "--store", "--click", "--origin", "--isolated", "--url"],
  "capture fill": ["--space", "--page", "--selector", "--store", "--generate", "--from", "--origin", "--isolated", "--url"],
  "capture login": [
    "--origin",
    "--url",
    "--user",
    "--user-selector",
    "--password-selector",
    "--submit-selector",
    "--success-selector",
    "--from",
    "--recipe",
    "--agent",
    "--isolated",
    "--space",
    "--page",
  ],
  "capture recipes": [],
};
const SUBCOMMANDS: Record<string, string[]> = {
  auth: ["status", "set", "delete"],
  audit: ["list", "verify", "sync"],
  config: ["show", "set", "unset"],
  trust: ["list", "remove"],
  capture: ["read", "fill", "login", "recipes"],
};
const COMMANDS = ["init", "validate", "plan", "apply", "rotate", "run", "inventory", "doctor", ...Object.keys(SUBCOMMANDS)];

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
    if (flag === "--isolated" || flag === "--fix") {
      if (inline !== undefined) throw new UsageError(`option ${flag} takes no value`);
      flags.set(flag, "true");
      continue;
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
    case "inventory":
    case "doctor":
    case "run":
      return 1;
    case "rotate":
      return 2;
    case "audit":
      return 2;
    case "auth":
      return sub === "status" ? 2 : sub === "set" || sub === "delete" ? 3 : undefined;
    case "config":
      return sub === "show" ? 2 : sub === "set" ? 4 : sub === "unset" ? 3 : undefined;
    case "trust":
      return sub === "list" ? 2 : sub === "remove" ? 3 : undefined;
    case "capture":
      return sub === "read" || sub === "fill" || sub === "login" || sub === "recipes" ? 2 : undefined;
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
    case "netlify":
      return target.context;
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
  return withAbsolutePaths(validatePolicy(parsed), deps.cwd);
}

/** File targets are resolved against cwd once, so the dialog, trust key and sink use one absolute path. */
function withAbsolutePaths(policy: Policy, cwd: string): Policy {
  for (const target of Object.values(policy.targets)) {
    if (target.provider === "compose") target.dir = resolvePath(cwd, target.dir);
    if (target.provider === "dotenv") target.path = resolvePath(cwd, target.path);
  }
  return policy;
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
    effect: describeEffect(op),
  };
}

/** Every write in full; writes to a destination that is not trusted yet end with [NEW destination]. */
function approvalLines(policy: Policy, ops: Operation[], cwd: string, newKeys: Set<string>, header: string[] = []): string[] {
  const lines = [...header, `Project: ${policy.project}`, `Write ${ops.length} value(s):`, ""];
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
  // `zks run [options] -- <command> [args...]`: nothing after the first -- is a zks option.
  // Every other command still parses the whole argv, where -- is an unknown option.
  const separator = argv.indexOf("--");
  let { positionals, flags } = parseArgs(separator < 0 ? argv : argv.slice(0, separator));
  const runArgv = positionals[0] === "run" && separator >= 0 ? argv.slice(separator + 1) : null;
  if (positionals[0] !== "run") ({ positionals, flags } = parseArgs(argv));
  const [command, sub, arg] = positionals;
  if (flags.has("--version")) return { exitCode: EXIT_OK, stdout: `${deps.version}\n` };
  if (flags.has("--help") || command === undefined || command === "help") return { exitCode: EXIT_OK, stdout: HELP_TEXT };
  // `zks run` without -- reports its usage, not the command it was given.
  const limit = command === "run" && runArgv === null ? undefined : positionalLimit(command, sub);
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
      return json(EXIT_OK, {
        ok: true,
        project: policy.project,
        operations: ops.map((op) => describeOperation(op, deps.cwd)),
        effects: summarizeEffects(ops),
      });
    }
    case "apply":
      return apply(deps, flags, redactor);
    case "rotate":
      return rotate(deps, sub, flags, redactor);
    case "run":
      return runCommand(deps, runArgv, flags, redactor);
    case "inventory":
      return inventory(deps, flags);
    case "auth":
      return auth(deps, sub, arg);
    case "audit":
      return audit(deps, sub, flags);
    case "config":
      return config(deps, sub, arg, positionals[3]);
    case "trust":
      return trust(deps, sub, arg);
    case "capture":
      return capture(deps, sub, flags, redactor);
    case "doctor": {
      if (!flags.has("--fix")) return json(EXIT_OK, { ok: true, ...(await deps.doctor()) });
      // Fix first, so the report shows the repaired state.
      const fix = await deps.fixPermissions();
      const report = await deps.doctor();
      return json(EXIT_OK, { ok: true, ...report, fixed: fix.fixed, notFixable: notFixable(fix, report) });
    }
    default:
      throw new UsageError(`unknown command ${command}; run \`zks help\``);
  }
}

interface NotFixable {
  check: string;
  status: string;
  command: string;
}

const field = (value: unknown, key: string): unknown =>
  typeof value === "object" && value !== null ? (value as Record<string, unknown>)[key] : undefined;

/** What `doctor --fix` leaves alone (integrity, pins, trust, audit chain, Keychain), each with the command to run. */
function notFixable(fix: PermissionFix, report: Record<string, unknown>): NotFixable[] {
  const out: NotFixable[] = fix.failed.map((f) => ({ check: `permissions ${f.path}`, status: f.reason, command: `ls -l ${f.path}` }));
  const install = field(report, "install");
  const reinstall = field(install, "mode") === "system" ? "sudo ./install.sh --system" : "./install.sh";
  const installStatus = field(install, "status");
  if (typeof installStatus === "string" && installStatus !== "ok") out.push({ check: "install", status: installStatus, command: reinstall });
  const pins = field(field(report, "tools"), "pins");
  for (const [tool, status] of Object.entries(typeof pins === "object" && pins !== null ? pins : {})) {
    if (status === "changed") out.push({ check: `tools.pins.${tool}`, status, command: reinstall });
  }
  if (field(report, "trust") === "invalid") {
    out.push({ check: "trust", status: "invalid", command: "zks trust list, then choose Always allow in the next apply to sign trust.json again" });
  }
  if (field(field(report, "audit"), "ok") === false) out.push({ check: "audit", status: "broken", command: "zks audit verify" });
  const tokens = field(report, "tokens");
  for (const account of TOKEN_ACCOUNTS) {
    // The HMAC token only matters once a Sheets mirror is configured.
    if (account === "sheets-hmac" && field(field(report, "mirror"), "sheetsWebhook") !== true) continue;
    if (field(tokens, account) === false) out.push({ check: `tokens.${account}`, status: "missing", command: `zks auth set ${account}` });
  }
  return out;
}

function selection(flags: Map<string, string>) {
  return { only: list(flags.get("--only")), targets: list(flags.get("--target")) };
}

async function apply(deps: Deps, flags: Map<string, string>, redactor: Redactor): Promise<RunOutput> {
  const policy = await loadPolicy(deps, flags.get("--policy"));
  const ops = planOperations(policy, selection(flags));
  if (ops.length === 0) return json(EXIT_OK, { ok: true, project: policy.project, results: [] });
  return writeOperations(deps, redactor, policy, ops, {
    agent: flags.get("--agent") ?? deps.agentId,
    action: "set",
    alwaysAsk: false,
    title: "zks: approve secret changes",
    header: [],
    extra: {},
  });
}

const ROTATE_USAGE = "usage: zks rotate NAME [--target t1,t2] [--policy FILE]";

/**
 * Writes a NEW value of a generated variable to its targets (or the --target subset) and rewrites
 * the variables derived from it, in one apply that always shows the approval dialog. Nothing is
 * revoked at the provider the old value came from.
 */
async function rotate(deps: Deps, name: string | undefined, flags: Map<string, string>, redactor: Redactor): Promise<RunOutput> {
  if (name === undefined) throw new UsageError(ROTATE_USAGE);
  const policy = await loadPolicy(deps, flags.get("--policy"));
  // The name is only echoed once it is known: it might be a pasted secret.
  if (!Object.hasOwn(policy.variables, name)) throw new UsageError("not a variable of the policy; see `zks plan`");
  const variable = policy.variables[name] as Policy["variables"][string];
  const subset = list(flags.get("--target"));
  if (subset) {
    const unknown = subset.filter((t) => !Object.hasOwn(policy.targets, t));
    if (unknown.length > 0) throw new PolicyError(unknown.map((t) => `--target: unknown target "${t}"`));
    const foreign = subset.find((t) => !variable.targets.includes(t));
    if (foreign !== undefined) throw new UsageError(`--target: "${foreign}" is not a target of ${name}`);
  }

  let refusal: string | null = null;
  if (variable.source?.kind !== "generate") {
    refusal = `${name} is not generated by zks; only variables with a generate source can be rotated`;
  }
  const dependents = refusal === null ? dependentsOf(policy, name) : [];
  for (const dependent of dependents) {
    const other = generatedDependencies(policy, dependent).find((dep) => dep !== name);
    if (other !== undefined && refusal === null) {
      refusal = `${dependent} also uses ${other}, another generated value; rotating ${name} alone would replace it too`;
    }
  }
  const agent = deps.agentId;
  // Nothing is resolved or written; every write the rotation would have made is audited failed.
  const refuse = async (refused: Operation[], error: { code: string; message: string; [k: string]: unknown }) => {
    const store = deps.openAudit();
    try {
      const results = refused.map((op) => {
        const entry = appendOperation(deps, store, { project: policy.project, agent, action: "rotate" }, op, "failed", {
          errorCode: error.code,
        });
        return toResult(op, entry, "failed", undefined, { code: error.code, message: error.message });
      });
      const anchorError = await saveAnchor(deps, store);
      const mirror = await deps.mirror.sync(store);
      return json(EXIT_USAGE, { ok: false, project: policy.project, error, results, mirror, ...anchorError });
    } finally {
      store.close();
    }
  };
  if (refusal !== null) {
    const refused: Operation[] = variable.targets
      .filter((targetKey) => !subset || subset.includes(targetKey))
      .map((targetKey) => ({ name, targetKey, target: policy.targets[targetKey] as TargetConfig, variable, sourceKind: sourceKindOf(variable) }));
    return refuse(refused, { code: "not_rotatable", message: refusal });
  }

  const ops = planOperations(policy, { only: [name, ...dependents], targets: subset });
  if (subset) {
    // A derived value written elsewhere would keep the old value there: rotate all of it or none.
    const outside = dependents
      .map((dependent) => ({
        dependent,
        targets: (policy.variables[dependent] as Policy["variables"][string]).targets.filter((t) => !subset.includes(t)),
      }))
      .filter((d) => d.targets.length > 0);
    if (outside.length > 0) {
      const shown = outside.map((d) => `${d.dependent} (${d.targets.join(", ")})`).join(", ");
      return refuse(ops, {
        code: "dependents_outside_selection",
        message:
          `rotating ${name} on --target ${subset.join(",")} would leave derived values stale on other targets: ${shown}; ` +
          "rerun without --target or include those targets",
        dependents: outside,
      });
    }
  }
  const written = [...new Set(ops.map((op) => op.name))].filter((n) => n !== name);
  return writeOperations(deps, redactor, policy, ops, {
    agent,
    action: "rotate",
    alwaysAsk: true,
    title: "zks: approve secret rotation",
    header: [
      `Rotate ${name}: a NEW value replaces the current one${written.length > 0 ? `; derived ${written.join(", ")} rewritten with it` : ""}.`,
      "The old value is not revoked anywhere.",
      "",
    ],
    extra: { rotated: name, dependents: written },
  });
}

const RUN_USAGE = "usage: zks run [--policy FILE] [--only A,B] [--agent LABEL] -- <command> [args...]";
const MAX_RUN_ARGUMENTS = 300;

/** Arguments as the dialog shows them, in full: shell-like quoting. runCommand refuses more than 300 characters. */
function describeArguments(args: string[]): string {
  if (args.length === 0) return "(none)";
  return args.map((a) => (/^[A-Za-z0-9_@%+=:,.\/-]+$/.test(a) ? a : JSON.stringify(a))).join(" ");
}

/**
 * `zks run -- <command>`: after the human approves the command in a dialog (every time, no trust),
 * resolves the selected variables in memory and starts the command with them as environment
 * variables of that child only. zks prints nothing on success and exits with the child's code.
 * Generated variables (and those derived from them) are skipped unless named, then refused: their
 * value exists only at its destinations, and run would create a new one.
 */
async function runCommand(
  deps: Deps,
  commandArgv: string[] | null,
  flags: Map<string, string>,
  redactor: Redactor,
): Promise<RunOutput> {
  if (commandArgv === null || commandArgv.length === 0) throw new UsageError(RUN_USAGE);
  const policy = await loadPolicy(deps, flags.get("--policy"));
  const only = list(flags.get("--only"));
  const unknown = (only ?? []).find((n) => !Object.hasOwn(policy.variables, n));
  // The name is not echoed: it might be a pasted secret (same rule as rotate).
  if (unknown !== undefined) throw new UsageError("--only: a name is not a variable of the policy; see `zks plan`");
  const generated = (n: string) => policy.variables[n]?.source?.kind === "generate" || generatedDependencies(policy, n).length > 0;
  const named = Object.keys(policy.variables).filter((n) => only?.includes(n) && generated(n));
  if (named.length > 0) {
    throw new UsageError(`run cannot inject generated values; they exist only at their destinations (${named.join(", ")})`);
  }
  const names = Object.keys(policy.variables).filter((n) => (only ? only.includes(n) : !generated(n)));
  if (names.length === 0) throw new UsageError("--only: select at least one variable");
  const spec = (name: string) => policy.variables[name] as Policy["variables"][string];

  const [command, ...args] = commandArgv as [string, ...string[]];
  const shownArguments = describeArguments(args);
  // The dialog shows the arguments whole: a cut line could hide the part that matters.
  if (shownArguments.length > MAX_RUN_ARGUMENTS) {
    return json(EXIT_USAGE, {
      ok: false,
      error: {
        code: "arguments_too_long",
        message: `the arguments are longer than ${MAX_RUN_ARGUMENTS} characters; the dialog shows them in full, so shorten them`,
      },
    });
  }
  // A cwd with ":" cannot be a PATH entry; the command then only searches the fixed system PATH.
  const searchPath = deps.cwd.includes(":") ? SAFE_PATH : `${join(deps.cwd, "node_modules", ".bin")}:${SAFE_PATH}`;
  const executable = resolveExecutable(command, deps.cwd, searchPath);
  if (executable === null) {
    return json(EXIT_FAILED, {
      ok: false,
      error: {
        code: "command_not_found",
        message: "the command is not an executable file (a bare name is looked up in ./node_modules/.bin and the fixed system PATH)",
      },
    });
  }

  const lines = [
    `Project: ${policy.project}`,
    `Run a command with ${names.length} value(s) in its environment:`,
    `Command: ${executable}`,
    "Arguments:",
    shownArguments,
    `Directory: ${deps.cwd}`,
    "Variables:",
    ...names.map((n) => `- ${n} [${spec(n).sensitive ? "secret" : "plain"}; ${describeSource(spec(n).source, deps.cwd)}]`),
    "",
    "The command and every process it starts can read these values. zks asks on every run.",
  ];
  if (lines.length > MAX_LINES) {
    return json(EXIT_USAGE, {
      ok: false,
      error: { code: "too_many_operations", message: `${names.length} variables do not fit in one approval dialog; narrow with --only` },
    });
  }
  if (lines.some((line) => line.length > MAX_DIALOG_LINE) || lines.join("\n").length > MAX_DIALOG_TEXT) {
    return json(EXIT_USAGE, {
      ok: false,
      error: { code: "dialog_too_long", message: "the approval text is too long for one dialog (command path, directory or a source)" },
    });
  }

  const agent = flags.get("--agent") ?? deps.agentId;
  const head = { ok: false, project: policy.project, command: executable, variables: names, approval: "dialog" };
  let child: SpawnedChild | null = null;
  const store = deps.openAudit();
  try {
    const record = (name: string, result: AuditResult, errorCode = "") =>
      store.append({
        ts: deps.now().toISOString(),
        actorHuman: deps.user,
        actorAgent: agent,
        project: policy.project,
        provider: "run",
        target: executable,
        environment: "",
        variableName: name,
        action: "run",
        sensitive: spec(name).sensitive,
        sourceKind: sourceKindOf(spec(name)),
        result,
        providerVersion: "",
        errorCode,
        approval: "dialog",
      });
    const finish = async (exitCode: number, error: Record<string, unknown>): Promise<RunOutput> => {
      const anchorError = await saveAnchor(deps, store);
      const mirror = await deps.mirror.sync(store);
      return json(exitCode, { ...head, error, mirror, ...anchorError });
    };

    // Approve before resolving: a denied run never reads a secret.
    if (!(await deps.human.approve("zks: approve a command with secrets", lines))) {
      for (const name of names) record(name, "denied", "not_approved");
      return await finish(EXIT_DENIED, { code: "not_approved", message: "denied or no answer in the approval dialog" });
    }

    const resolver = createResolver(
      policy.variables,
      {
        exec: deps.exec,
        tools: deps.tools,
        keychain: deps.keychain,
        human: deps.human,
        cwd: deps.cwd,
        readFile: deps.readFile,
        randomBytes: deps.randomBytes,
      },
      (_name, variable, value) => {
        if (variable.sensitive) redactor.register(value);
      },
    );
    const env: Record<string, string> = {};
    try {
      for (const name of names) {
        try {
          env[name] = (await resolver.resolve(name)).reveal();
        } catch (error) {
          const code = error instanceof SourceError ? error.code : "source_failed";
          const message = redactor.scrub(error instanceof Error ? error.message : String(error)).slice(0, 300);
          for (const n of names) record(n, "failed", n === name ? code : "not_run");
          return await finish(EXIT_FAILED, { code, message, variable: name });
        }
      }
      // spawn() copies the environment before it returns; the copy belongs to the child.
      try {
        child = deps.spawnInherited(executable, args, { cwd: deps.cwd, env: { PATH: searchPath, ...env } });
      } catch (error) {
        // A synchronous spawn failure takes the same audited run_failed path as an asynchronous one.
        const spawned = Promise.resolve(error instanceof Error ? error : new Error(String(error)));
        child = { spawned, exited: new Promise<never>(() => undefined), kill: () => undefined };
      }
    } finally {
      resolver.dispose();
      for (const name of Object.keys(env)) delete env[name];
    }

    const spawnError = await child.spawned;
    if (spawnError !== null) {
      for (const name of names) record(name, "failed", "run_failed");
      child = null;
      return await finish(EXIT_FAILED, { code: "run_failed", message: redactor.scrub(spawnError.message).slice(0, 300) });
    }
    try {
      for (const name of names) record(name, "applied");
    } catch {
      // The values must not stay with a command whose run is not audited.
      child.kill("SIGTERM");
      await child.exited;
      child = null;
      await saveAnchor(deps, store);
      return json(EXIT_FAILED, { ...head, error: { code: "audit_failed", message: "the command was stopped: its audit record could not be written" } });
    }
  } finally {
    store.close();
  }

  // The child owns stdout from here on: zks prints nothing there and keeps the child's exit code.
  const exit = await (child as SpawnedChild).exited;
  await syncAfterRun(deps, redactor);
  if (exit.code !== null) return { exitCode: exit.code, stdout: "" };
  const number = exit.signal === null ? undefined : osConstants.signals[exit.signal];
  return { exitCode: number === undefined ? EXIT_FAILED : 128 + number, stdout: "" };
}

/** Audit anchor and mirror after a run: a failure is one redacted stderr line, never the exit code or stdout. */
async function syncAfterRun(deps: Deps, redactor: Redactor): Promise<void> {
  const problems: string[] = [];
  const message = (error: unknown) => (error instanceof Error ? error.message : String(error));
  try {
    const store = deps.openAudit();
    try {
      const { anchorError } = await saveAnchor(deps, store);
      if (anchorError !== undefined) problems.push(anchorError);
      try {
        const mirror = await deps.mirror.sync(store);
        if (mirror.error !== undefined) problems.push(mirror.error);
      } catch (error) {
        problems.push(message(error));
      }
    } finally {
      store.close();
    }
  } catch (error) {
    problems.push(message(error));
  }
  if (problems.length > 0) {
    const line = redactor.scrub(problems.join("; ")).replace(/[\r\n]+/g, " ").slice(0, 300);
    process.stderr.write(`zks: audit anchor/mirror: ${line}\n`);
  }
}

const DAY_MS = 86_400_000;

interface InventoryEntry {
  variable: string;
  provider: string;
  target: string;
  environment: string;
  lastWrittenAt: string | null;
  ageDays: number | null;
  writes: number;
  status: "written" | "never_written" | "not_in_policy";
}

/**
 * Which variable was written to which destination and when, from the local audit log only (no
 * network, no values). Compared with the policy of the same project when there is one.
 */
async function inventory(deps: Deps, flags: Map<string, string>): Promise<RunOutput> {
  const project = flags.get("--project");
  if (project !== undefined && !PROJECT_NAME.test(project)) throw new UsageError(`--project must match ${PROJECT_NAME}`);
  const policyFlag = flags.get("--policy");
  const policyFile = resolvePath(deps.cwd, policyFlag ?? "zks.policy.json");
  // With --project and no --policy, a missing default policy only means there is nothing to compare with.
  const readPolicy =
    policyFlag !== undefined || project === undefined || (await deps.readFile(policyFile).then(() => true, () => false));
  const loaded = readPolicy ? await loadPolicy(deps, policyFlag) : null;
  const name = project ?? (loaded as Policy).project;
  const policy = loaded !== null && loaded.project === name ? loaded : null;

  const store = deps.openAudit();
  let rows: WrittenDestination[];
  try {
    rows = store.writtenDestinations(name);
  } finally {
    store.close();
  }
  const now = deps.now().getTime();
  const key = (variable: string, target: string, provider: string) => `${variable}\u0000${target}\u0000${provider}`;
  const planned = new Map((policy ? planOperations(policy) : []).map((op) => [key(op.name, op.targetKey, op.target.provider), op]));
  const entries: InventoryEntry[] = rows.map((row) => {
    const age = Math.floor((now - Date.parse(row.lastWrittenAt)) / DAY_MS);
    const k = key(row.variableName, row.target, row.provider);
    const inPolicy = planned.delete(k) || policy === null;
    return {
      variable: row.variableName,
      provider: row.provider,
      target: row.target,
      environment: row.environment,
      lastWrittenAt: row.lastWrittenAt,
      ageDays: Number.isFinite(age) ? age : null,
      writes: row.writes,
      status: inPolicy ? "written" : "not_in_policy",
    };
  });
  for (const op of planned.values()) {
    entries.push({
      variable: op.name,
      provider: op.target.provider,
      target: op.targetKey,
      environment: environmentOf(op.target),
      lastWrittenAt: null,
      ageDays: null,
      writes: 0,
      status: "never_written",
    });
  }
  const order = (e: InventoryEntry) => [e.variable, e.target, e.provider];
  entries.sort((a, b) => {
    const [x, y] = [order(a), order(b)];
    for (let i = 0; i < x.length; i++) if (x[i] !== y[i]) return (x[i] as string) < (y[i] as string) ? -1 : 1;
    return 0;
  });
  return json(EXIT_OK, { ok: true, project: name, policy: policy ? policyFile : null, entries });
}

interface AuditContext {
  project: string;
  agent: string;
  action: "set" | "rotate";
}

function appendOperation(
  deps: Deps,
  store: AuditStore,
  ctx: AuditContext,
  op: Operation,
  result: OperationResult["result"],
  extra: { version?: string; errorCode?: string },
  approval?: ApprovalMode,
): AuditRecord {
  return store.append({
    ts: deps.now().toISOString(),
    actorHuman: deps.user,
    actorAgent: ctx.agent,
    project: ctx.project,
    provider: op.target.provider,
    target: op.targetKey,
    environment: environmentOf(op.target),
    variableName: op.name,
    action: ctx.action,
    sensitive: op.variable.sensitive,
    sourceKind: op.sourceKind,
    result,
    providerVersion: extra.version ?? "",
    errorCode: extra.errorCode ?? "",
    ...(approval ? { approval } : {}),
  });
}

interface WriteOptions {
  agent: string;
  action: "set" | "rotate";
  /** Show the dialog even when every destination is trusted. */
  alwaysAsk: boolean;
  title: string;
  /** Lines shown above the writes in the dialog. */
  header: string[];
  /** Fields added to the JSON output. */
  extra: Record<string, unknown>;
}

/** Approves, resolves and writes ops in one apply; every write is audited with opts.action. */
async function writeOperations(
  deps: Deps,
  redactor: Redactor,
  policy: Policy,
  ops: Operation[],
  opts: WriteOptions,
): Promise<RunOutput> {
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
  const lines = approvalLines(policy, ops, deps.cwd, new Set(newKeys), opts.header);
  if (lines.some((line) => line.length > MAX_DIALOG_LINE) || lines.join("\n").length > MAX_DIALOG_TEXT) {
    return json(EXIT_USAGE, {
      ok: false,
      error: { code: "dialog_too_long", message: "the approval text is too long for one dialog; narrow with --only or --target" },
    });
  }
  const trustReport = trustState.valid ? {} : { trust: "invalid" as const };

  const agent = opts.agent;
  const extra = opts.extra;
  // Every destination already trusted: no dialog (unless the command always asks). Otherwise the human sees every write.
  const approval: ApprovalMode = newKeys.length === 0 && !opts.alwaysAsk ? "trusted" : "dialog";
  const store = deps.openAudit();
  const results: OperationResult[] = [];
  try {
    const ctx: AuditContext = { project: policy.project, agent, action: opts.action };
    const record = (op: Operation, result: OperationResult["result"], extra: { version?: string; errorCode?: string }) =>
      appendOperation(deps, store, ctx, op, result, extra, approval);

    const decision = approval === "trusted" ? "once" : await deps.human.approveWithTrust(opts.title, lines);
    if (decision === "deny") {
      for (const op of ops) {
        const entry = record(op, "denied", { errorCode: "not_approved" });
        results.push(toResult(op, entry, "denied", undefined, { code: "not_approved", message: "denied or no answer in the approval dialog" }));
      }
      const anchorError = await saveAnchor(deps, store);
      const mirror = await deps.mirror.sync(store);
      return json(EXIT_DENIED, { ok: false, project: policy.project, ...extra, approval, results, mirror, ...trustReport, ...anchorError });
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

    // One resolver per apply: each value is resolved once, in dependency order, and shared by the
    // templates and public keys derived from it. Every resolved value is zeroed in the finally below.
    const resolver = createResolver(
      policy.variables,
      {
        exec: deps.exec,
        tools: deps.tools,
        keychain: deps.keychain,
        human: deps.human,
        cwd: deps.cwd,
        readFile: deps.readFile,
        randomBytes: deps.randomBytes,
      },
      (_name, spec, value) => {
        if (spec.sensitive) redactor.register(value);
      },
    );
    try {
      for (const [name, variableOps] of byVariable) {
        let value: SecretBuffer;
        try {
          value = await resolver.resolve(name);
        } catch (error) {
          const code = error instanceof SourceError ? error.code : "source_failed";
          const message = redactor.scrub(error instanceof Error ? error.message : String(error));
          for (const op of variableOps) {
            const entry = record(op, "failed", { errorCode: code });
            results.push(toResult(op, entry, "failed", undefined, { code, message }));
          }
          continue;
        }
        {
          for (const op of variableOps) {
            let version: string | undefined;
            try {
              const sink = deps.sinks[op.target.provider];
              ({ version } = await sink.apply(op, value, {
                fetch: deps.fetch,
                exec: deps.exec,
                keychain: deps.keychain,
                aws: deps.aws,
                tools: deps.tools,
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
        }
      }
    } catch (error) {
      if (!(error instanceof AuditWriteError)) throw error;
      // Stop: further writes would go unaudited.
      await saveAnchor(deps, store);
      return json(EXIT_FAILED, { ok: false, error: { code: "audit_failed", message: error.message }, ...extra, approval, results, ...trustChange });
    } finally {
      resolver.dispose();
    }

    const anchorError = await saveAnchor(deps, store);
    const mirror: MirrorResult = await deps.mirror.sync(store);
    const ok = results.every((r) => r.result === "applied");
    return json(ok ? EXIT_OK : EXIT_FAILED, {
      ok,
      project: policy.project,
      ...extra,
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
      if (key === "capture-profile") {
        if (value === undefined || !CAPTURE_PROFILE.test(value)) {
          throw new UsageError("capture-profile must be an ego-browser profile id (letters, digits, space, _ . -; at most 64)");
        }
        if (!(await deps.human.approve("zks: approve config change", [`Run isolated captures in the ego-browser profile ${value} (set capture-profile)?`]))) {
          return configNotApproved();
        }
        const next = { ...current, capture: { ...current.capture, profileId: value } };
        await deps.writeConfig(next);
        return json(EXIT_OK, { ok: true, config: next });
      }
      if (key !== "sheets-webhook") {
        throw new UsageError(
          "usage: zks config set sheets-webhook <https://script.google.com/macros/s/.../exec> | zks config set capture-profile <profileId>",
        );
      }
      if (!value || !SHEETS_WEBHOOK_URL.test(value)) throw new UsageError("sheets-webhook must be a deployed Apps Script URL ending in /exec");
      if (!(await deps.human.approve("zks: approve config change", [`Mirror the audit log to ${value} (set sheets-webhook)?`]))) {
        return configNotApproved();
      }
      const next = { ...current, sheets: { ...current.sheets, webhookUrl: value } };
      await deps.writeConfig(next);
      return json(EXIT_OK, { ok: true, config: next });
    }
    case "unset": {
      if (key === "capture-profile") {
        if (!(await deps.human.approve("zks: approve config change", ["Stop isolated captures (unset capture-profile)?"]))) {
          return configNotApproved();
        }
        const next = { ...current, capture: {} };
        await deps.writeConfig(next);
        return json(EXIT_OK, { ok: true, config: next });
      }
      if (key !== "sheets-webhook") throw new UsageError("usage: zks config unset sheets-webhook | zks config unset capture-profile");
      if (!(await deps.human.approve("zks: approve config change", ["Stop mirroring the audit log to Google Sheets (unset sheets-webhook)?"]))) {
        return configNotApproved();
      }
      const next = { ...current, sheets: {} };
      await deps.writeConfig(next);
      return json(EXIT_OK, { ok: true, config: next });
    }
    default:
      throw new UsageError(
        "usage: zks config show | zks config set sheets-webhook <url> | zks config set capture-profile <profileId> | " +
          "zks config unset sheets-webhook | zks config unset capture-profile",
      );
  }
}

function configNotApproved(): RunOutput {
  return json(EXIT_DENIED, { ok: false, error: { code: "not_approved", message: "config change not approved" } });
}

const CAPTURE_USAGE =
  "usage: zks capture read --space ID --page LABEL --selector CSS --store SERVICE/ACCOUNT [--click SELECTOR] [--origin ORIGIN] | " +
  "zks capture fill --space ID --page LABEL --selector CSS (--store SERVICE/ACCOUNT --generate BYTES | --from SERVICE/ACCOUNT) --origin ORIGIN";
const CAPTURE_SPACE = /^[1-9][0-9]{0,9}$/;
const CAPTURE_PAGE = /^[A-Za-z0-9_-]{1,32}$/;
const CAPTURE_SELECTOR = /^[\x20-\x7E]{1,300}$/;
const KEYCHAIN_ID = /^[A-Za-z0-9_.-]{1,128}$/;
const CAPTURE_ORIGIN = /^(?:https:\/\/[a-z0-9.-]+|http:\/\/(?:127\.0\.0\.1|localhost))(?::\d{1,5})?$/;
const MAX_CAPTURE_ORIGIN = 200;
const CAPTURE_URL = /^[\x21-\x7E]{1,1000}$/;
/** An ego-browser profile id as `zks config set capture-profile` accepts it. */
const CAPTURE_PROFILE = /^[A-Za-z0-9][A-Za-z0-9 _.-]{0,63}$/;
/** Script refusals of an isolated capture: nothing was read or filled. */
const ISOLATION_REFUSALS: readonly CaptureErrorCode[] = ["isolated_profile_missing", "isolated_profile_not_isolated", "login_required"];

/** The only zks tokens a capture may write, each only from its provider's own site. */
export const PINNED_CAPTURE_ORIGINS: Record<TokenAccount, string> = {
  vercel: "https://vercel.com",
  railway: "https://railway.com",
  supabase: "https://supabase.com",
  netlify: "https://app.netlify.com",
  "sheets-hmac": "https://script.google.com",
};

type CaptureFailure = CaptureErrorCode | "not_approved" | "isolated_profile_unset" | "restore_failed";

const CAPTURE_ERRORS: Record<CaptureFailure, string> = {
  origin_mismatch: "the page is not on --origin; nothing was read or filled",
  not_found: "the element or the Keychain item was not found",
  not_password_field: "the selector does not match exactly one password input in the page's main frame; nothing was filled",
  keychain_failed: "the macOS Keychain did not accept or return the item",
  browser_failed: "ego-browser failed or returned no result",
  not_approved: "replacing the Keychain item was not approved",
  isolated_profile_unset:
    "no capture-profile is configured; run `zks config set capture-profile <profileId>` with a separate ego-browser profile",
  isolated_profile_missing: "the configured capture-profile is not an ego-browser profile; nothing was read or filled",
  isolated_profile_not_isolated: "the configured capture-profile is the default ego-browser profile; pick a separate profile",
  login_required: "the isolated page did not stay on --origin; log in to the site once in the capture profile; nothing was read or filled",
  login_redirected: "the page left --origin during the login",
  restore_failed: "the previous value of the Keychain item could not be written back",
};

interface CaptureRequest {
  mode: "read" | "fill";
  sourceKind: CaptureSourceKind;
  /** null for --isolated. */
  space: number | null;
  page: string | null;
  /** --isolated: the page zks opens in its own space; its origin equals origin. */
  isolated: { url: string } | null;
  selector: string;
  click: string | null;
  origin: string | null;
  /** The item written (read, fill --generate) or filled (fill --from). */
  service: string;
  account: string;
  generateBytes: number | null;
}

/** Validates every capture option. Messages never echo a value: a selector could be a pasted secret. */
function parseCapture(sub: string | undefined, flags: Map<string, string>): CaptureRequest {
  if (sub !== "read" && sub !== "fill") throw new UsageError(CAPTURE_USAGE);
  const space = flags.get("--space");
  const page = flags.get("--page");
  const selector = flags.get("--selector");
  const isolated = flags.has("--isolated");
  const url = flags.get("--url");
  if (isolated) {
    if (space !== undefined || page !== undefined) throw new UsageError("--isolated cannot be combined with --space or --page");
    if (selector === undefined || (sub === "read" && !flags.has("--store"))) throw new UsageError(CAPTURE_USAGE);
    if (url === undefined || !flags.has("--origin")) throw new UsageError("--isolated needs --url and --origin");
  } else {
    if (url !== undefined) throw new UsageError("--url needs --isolated");
    if (space === undefined || page === undefined || selector === undefined) throw new UsageError(CAPTURE_USAGE);
    if (sub === "read" && !flags.has("--store")) throw new UsageError(CAPTURE_USAGE);
    if (!CAPTURE_SPACE.test(space)) throw new UsageError("--space must be a positive integer (the TaskSpace id)");
    if (!CAPTURE_PAGE.test(page)) throw new UsageError("--page must be an ego page label (letters, digits, _ or -, at most 32)");
  }
  if (!CAPTURE_SELECTOR.test(selector)) throw new UsageError("--selector must be 1-300 printable ASCII characters");
  const click = flags.get("--click") ?? null;
  if (click !== null && !CAPTURE_SELECTOR.test(click)) throw new UsageError("--click must be 1-300 printable ASCII characters");
  const origin = flags.get("--origin") ?? null;
  if (origin !== null && (origin.length > MAX_CAPTURE_ORIGIN || !CAPTURE_ORIGIN.test(origin))) {
    throw new UsageError("--origin must be https://host[:port] or http://127.0.0.1|localhost[:port]");
  }
  if (isolated && new URL(checkedCaptureUrl(url as string)).origin !== origin) throw new UsageError("--url must be on --origin");
  const common = {
    space: isolated ? null : Number(space),
    page: isolated ? null : (page as string),
    isolated: isolated ? { url: url as string } : null,
    selector,
    click,
    origin,
  };

  if (sub === "read") {
    const { service, account } = keychainRef(flags.get("--store") as string, "--store");
    if (service.toLowerCase() === ZKS_KEYCHAIN_SERVICE) {
      // Any other spelling of the service would store a token zks never reads.
      if (service !== ZKS_KEYCHAIN_SERVICE || !(TOKEN_ACCOUNTS as readonly string[]).includes(account)) {
        throw new UsageError(`the Keychain service zks only takes captured provider tokens: ${TOKEN_ACCOUNTS.join(", ")}`);
      }
      const pinned = PINNED_CAPTURE_ORIGINS[account as TokenAccount];
      if (origin !== pinned) throw new UsageError(`zks/${account} can only be captured with --origin ${pinned}`);
    }
    return { mode: "read", sourceKind: "capture-read", service, account, generateBytes: null, ...common };
  }

  const store = flags.get("--store");
  const generate = flags.get("--generate");
  const from = flags.get("--from");
  const generating = store !== undefined && generate !== undefined && from === undefined;
  if (!generating && !(from !== undefined && store === undefined && generate === undefined)) {
    throw new UsageError("capture fill takes --store with --generate, or --from alone");
  }
  // The origin pins where a value may go: page JavaScript on any other site could read the field.
  if (origin === null) throw new UsageError("capture fill needs --origin");
  const { service, account } = generating ? keychainRef(store as string, "--store") : keychainRef(from as string, "--from");
  if (service.toLowerCase() === ZKS_KEYCHAIN_SERVICE) throw new UsageError("capture fill cannot use the Keychain service zks");
  if (!generating) return { mode: "fill", sourceKind: "capture-from", service, account, generateBytes: null, ...common };
  const bytes = Number(generate);
  if (!/^[0-9]{1,3}$/.test(generate as string) || bytes < 16 || bytes > 128) {
    throw new UsageError("--generate must be an integer between 16 and 128");
  }
  return { mode: "fill", sourceKind: "capture-generate", service, account, generateBytes: bytes, ...common };
}

/** An http(s) URL of printable ASCII; never echoed. */
function checkedCaptureUrl(value: string): string {
  const message = "--url must be an http(s) URL of at most 1000 printable ASCII characters";
  if (!CAPTURE_URL.test(value)) throw new UsageError(message);
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new UsageError(message);
  }
  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") throw new UsageError(message);
  return value;
}

/** The configured isolated-capture profile, or null when unset or not a valid id (config.json is not trusted). */
function captureProfile(config: ZksConfig): string | null {
  const id = config.capture?.profileId;
  return typeof id === "string" && CAPTURE_PROFILE.test(id) ? id : null;
}

function keychainRef(value: string, flag: string): { service: string; account: string } {
  const parts = value.split("/");
  if (parts.length !== 2 || !parts.every((part) => KEYCHAIN_ID.test(part))) {
    throw new UsageError(`${flag} must be SERVICE/ACCOUNT, each matching ^[A-Za-z0-9_.-]{1,128}$`);
  }
  return { service: parts[0] as string, account: parts[1] as string };
}

/**
 * Runs zks's own ego-browser script against the agent's TaskSpace page: the value goes from the
 * page to the Keychain (read) or from the Keychain to the page (fill) inside that script, and zks
 * reports only its length. Every capture is audited and mirrored; replacing an existing item needs
 * approval, and so does filling a stored item into any origin other than the one it came from.
 */
async function capture(deps: Deps, sub: string | undefined, flags: Map<string, string>, redactor: Redactor): Promise<RunOutput> {
  if (sub === "recipes") {
    return json(EXIT_OK, { ok: true, recipes: Object.entries(LOGIN_RECIPES).map(([name, recipe]) => ({ name, ...recipe })) });
  }
  if (sub === "login") return captureLogin(deps, flags);
  const req = parseCapture(sub, flags);
  const store = `${req.service}/${req.account}`;
  const base = { command: "capture", mode: req.mode, store, origin: req.origin, ...(req.isolated ? { isolated: true } : {}) };
  const audit = deps.openAudit();
  try {
    let approval: ApprovalMode | undefined;
    const finish = async (
      result: AuditResult,
      outcome: { code: CaptureFailure; message?: string; restored?: true } | { length: number },
    ) => {
      const errorCode = "code" in outcome ? outcome.code : "";
      // A successful read or generate records the stored item's modification time, which a later
      // fill --from must match exactly to stay silent.
      const itemModified =
        result === "applied" && req.sourceKind !== "capture-from"
          ? ((await deps.keychain.modifiedAt(req.service, req.account).catch(() => null))?.toISOString() ?? "")
          : "";
      const entry = audit.append({
        ts: deps.now().toISOString(),
        actorHuman: deps.user,
        actorAgent: deps.agentId,
        project: req.service,
        provider: "keychain",
        target: store,
        environment: req.origin ?? "",
        variableName: req.account,
        action: "capture",
        sensitive: true,
        sourceKind: req.sourceKind,
        result,
        providerVersion: itemModified,
        errorCode,
        ...(approval ? { approval } : {}),
      });
      const anchorError = await saveAnchor(deps, audit);
      const mirror = await deps.mirror.sync(audit);
      if (!("code" in outcome)) {
        return json(EXIT_OK, { ok: true, ...base, length: outcome.length, auditId: entry.auditId, mirror, ...anchorError });
      }
      return json(result === "denied" ? EXIT_DENIED : EXIT_FAILED, {
        ok: false,
        ...base,
        error: { code: outcome.code, message: outcome.message ?? CAPTURE_ERRORS[outcome.code] },
        ...(outcome.restored ? { restored: true } : {}),
        auditId: entry.auditId,
        mirror,
        ...anchorError,
      });
    };

    const egoBrowser = deps.tools.egoBrowser;
    if (!egoBrowser) return await finish("failed", { code: "browser_failed" });
    // Isolated: checked before any dialog or Keychain write, so a refusal stores nothing.
    const profileId = req.isolated ? captureProfile(await deps.readConfig()) : null;
    if (req.isolated && profileId === null) return await finish("failed", { code: "isolated_profile_unset" });
    let existed = false;

    if (req.sourceKind === "capture-from") {
      if (!(await deps.keychain.has(req.service, req.account))) return await finish("failed", { code: "not_found" });
      // Silent only into the origin the item was last captured or generated from.
      // ...and only while the item is unchanged since that capture (a later replacement
      // outside zks could be any secret).
      const recorded = audit.lastCapture(store);
      const modified = await deps.keychain.modifiedAt(req.service, req.account);
      // The item must still carry exactly the modification time recorded by that capture.
      const unchanged = recorded !== null && modified !== null && recorded.itemModified !== "" && modified.toISOString() === recorded.itemModified;
      if (recorded === null || recorded.origin !== req.origin || !unchanged) {
        approval = "dialog";
        const from = recorded?.origin || "unknown";
        const changed = recorded !== null && recorded.origin === req.origin && !unchanged;
        const lines = [
          `Fill ${store} into ${req.origin}?`,
          changed ? `It was captured from ${from}, but the item changed after that capture.` : `It was captured from ${from}.`,
        ];
        if (!(await deps.human.approve("zks: fill a stored secret", lines))) {
          return await finish("denied", { code: "not_approved", message: "filling the stored item into this origin was not approved" });
        }
      }
    } else if (await deps.keychain.has(req.service, req.account)) {
      existed = true;
      approval = "dialog";
      const where = req.isolated
        ? `${req.origin} (isolated ego-browser profile ${profileId})`
        : `${req.origin ?? "the current page, origin not checked"} (TaskSpace ${req.space}, page ${req.page})`;
      const lines = [
        `Replace the Keychain item ${store}?`,
        req.mode === "read" ? `New value: read from ${where}` : `New value: a random password zks generates, filled into ${where}`,
      ];
      if (!(await deps.human.approve("zks: replace Keychain item", lines))) return await finish("denied", { code: "not_approved" });
    }

    // An approved replacement keeps the old value in memory only, to write it back if the capture
    // does not end ok (a read stores from inside the script, so this runs after the script returns).
    let previous: SecretBuffer | null = null;
    if (existed) {
      try {
        previous = await deps.keychain.get(req.service, req.account);
      } catch {
        return await finish("failed", { code: "keychain_failed" });
      }
      if (previous !== null) redactor.register(previous);
    }
    try {
      /** Writes the old value back; false when that write failed. */
      const restore = async (): Promise<boolean> => {
        if (previous === null) return true;
        try {
          await deps.keychain.set(req.service, req.account, previous);
          return true;
        } catch {
          return false;
        }
      };
      /** A failure after the item may have been replaced: restore first, then audit it. */
      const fail = async (code: CaptureFailure) => {
        if (previous === null) return await finish("failed", { code });
        if (await restore()) return await finish("failed", { code, restored: true });
        return await finish("failed", {
          code: "restore_failed",
          message:
            `the capture failed (${code}) and the previous value of the Keychain item could not be written back; ` +
            "the item now holds whatever the capture left",
        });
      };

      let outcome: CaptureOutcome;
      try {
        if (req.generateBytes !== null) {
          const random = (deps.randomBytes ?? nodeRandomBytes)(req.generateBytes);
          const value = SecretBuffer.adopt(Buffer.from(random.toString("base64url"), "utf8"));
          random.fill(0);
          redactor.register(value);
          try {
            await deps.keychain.set(req.service, req.account, value);
          } catch {
            return await fail("keychain_failed");
          } finally {
            value.dispose();
          }
        }
        outcome = await captureStep(deps, egoBrowser, req, profileId);
      } catch (error) {
        // A thrown error is still reported as before, after the old value is back.
        if (!(await restore())) return await fail("browser_failed");
        throw error;
      }
      // A refused isolated fill --generate filled nothing: drop the item zks just created for it.
      if (!outcome.ok && req.generateBytes !== null && !existed && ISOLATION_REFUSALS.includes(outcome.code)) {
        await deps.keychain.remove(req.service, req.account).catch(() => false);
      }
      // Awaited inside the try: the audit store must stay open until finish has synced the mirror.
      return outcome.ok ? await finish("applied", { length: outcome.length }) : await fail(outcome.code);
    } finally {
      previous?.dispose();
    }
  } finally {
    audit.close();
  }
}

const LOGIN_USAGE =
  "usage: zks capture login --origin ORIGIN --url URL --user USERNAME --user-selector CSS --password-selector CSS " +
  "--submit-selector SELECTOR --from SERVICE/ACCOUNT [--success-selector CSS] [--recipe NAME] [--agent LABEL] " +
  "(--isolated | --space ID --page LABEL)";
/** A login name or e-mail: printable ASCII, no leading or trailing space. Not a secret, but never echoed. */
const LOGIN_USER = /^[\x21-\x7E](?:[\x20-\x7E]{0,252}[\x21-\x7E])?$/;

interface LoginRequest {
  /** null for --isolated. */
  space: number | null;
  page: string | null;
  isolated: boolean;
  origin: string;
  url: string;
  user: string;
  userSelector: string;
  passwordSelector: string;
  submitSelector: string;
  successSelector: string | null;
  service: string;
  account: string;
  agent: string | undefined;
}

/** Validates `capture login`, with a --recipe filling only the flags that were not given. Never echoes a value. */
function parseLogin(flags: Map<string, string>): LoginRequest {
  const recipeName = flags.get("--recipe");
  const recipe = recipeName === undefined ? null : loginRecipe(recipeName);
  if (recipeName !== undefined && recipe === null) throw new UsageError("unknown recipe; `zks capture recipes` lists them");
  if (recipe !== null && recipe.requiresOrigin && !flags.has("--origin")) throw new UsageError(`recipe ${recipeName} needs --origin`);
  const origin = flags.get("--origin") ?? recipe?.origin ?? undefined;
  const url = flags.get("--url") ?? recipe?.url ?? (recipe !== null && origin !== undefined ? `${origin}/` : undefined);
  const user = flags.get("--user");
  const userSelector = flags.get("--user-selector") ?? recipe?.userSelector;
  const passwordSelector = flags.get("--password-selector") ?? recipe?.passwordSelector;
  const submitSelector = flags.get("--submit-selector") ?? recipe?.submitSelector;
  const successSelector = flags.get("--success-selector") ?? recipe?.successSelector ?? null;
  const from = flags.get("--from");
  const isolated = flags.has("--isolated");
  const space = flags.get("--space");
  const page = flags.get("--page");
  if (isolated && (space !== undefined || page !== undefined)) throw new UsageError("--isolated cannot be combined with --space or --page");
  if (
    origin === undefined || url === undefined || user === undefined || userSelector === undefined || passwordSelector === undefined ||
    submitSelector === undefined || from === undefined || (!isolated && (space === undefined || page === undefined))
  ) {
    throw new UsageError(LOGIN_USAGE);
  }
  if (!isolated) {
    if (!CAPTURE_SPACE.test(space as string)) throw new UsageError("--space must be a positive integer (the TaskSpace id)");
    if (!CAPTURE_PAGE.test(page as string)) throw new UsageError("--page must be an ego page label (letters, digits, _ or -, at most 32)");
  }
  if (origin.length > MAX_CAPTURE_ORIGIN || !CAPTURE_ORIGIN.test(origin)) {
    throw new UsageError("--origin must be https://host[:port] or http://127.0.0.1|localhost[:port]");
  }
  if (new URL(checkedCaptureUrl(url)).origin !== origin) throw new UsageError("--url must be on --origin");
  if (!LOGIN_USER.test(user)) throw new UsageError("--user must be 1-254 printable ASCII characters");
  const selectors: Array<[string, string | null]> = [
    ["--user-selector", userSelector],
    ["--password-selector", passwordSelector],
    ["--submit-selector", submitSelector],
    ["--success-selector", successSelector],
  ];
  for (const [flag, value] of selectors) {
    if (value !== null && !CAPTURE_SELECTOR.test(value)) throw new UsageError(`${flag} must be 1-300 printable ASCII characters`);
  }
  const { service, account } = keychainRef(from, "--from");
  if (service.toLowerCase() === ZKS_KEYCHAIN_SERVICE) throw new UsageError("capture login cannot use the Keychain service zks");
  return {
    space: isolated ? null : Number(space),
    page: isolated ? null : (page as string),
    isolated,
    origin,
    url,
    user,
    userSelector,
    passwordSelector,
    submitSelector,
    successSelector,
    service,
    account,
    agent: flags.get("--agent"),
  };
}

/**
 * Logs an ego-browser session into a site with a stored password: zks's own script sets the
 * username, reads the Keychain item and types it into the password field inside ego, submits and
 * reports booleans only. Every login asks first (no trust); the audit holds the origin and the item.
 */
async function captureLogin(deps: Deps, flags: Map<string, string>): Promise<RunOutput> {
  const req = parseLogin(flags);
  const item = `${req.service}/${req.account}`;
  const base = { command: "capture", mode: "login", origin: req.origin, from: item, ...(req.isolated ? { isolated: true } : {}) };
  const audit = deps.openAudit();
  try {
    let approval: ApprovalMode | undefined;
    const finish = async (
      result: AuditResult,
      outcome: { code: CaptureFailure; message?: string; finalOrigin?: string } | { loggedIn: boolean; finalOrigin: string; pending?: LoginPending },
    ) => {
      const entry = audit.append({
        ts: deps.now().toISOString(),
        actorHuman: deps.user,
        actorAgent: req.agent ?? deps.agentId,
        project: req.service,
        provider: "capture",
        target: req.origin,
        environment: "",
        variableName: item,
        action: "capture",
        sensitive: true,
        sourceKind: "capture-login",
        result,
        providerVersion: "",
        errorCode: "code" in outcome ? outcome.code : "",
        ...(approval ? { approval } : {}),
      });
      const anchorError = await saveAnchor(deps, audit);
      const mirror = await deps.mirror.sync(audit);
      if (!("code" in outcome)) {
        return json(EXIT_OK, {
          ok: true,
          ...base,
          loggedIn: outcome.loggedIn,
          finalOrigin: outcome.finalOrigin,
          ...(outcome.pending ? { pending: outcome.pending } : {}),
          auditId: entry.auditId,
          mirror,
          ...anchorError,
        });
      }
      return json(result === "denied" ? EXIT_DENIED : EXIT_FAILED, {
        ok: false,
        ...base,
        error: { code: outcome.code, message: outcome.message ?? CAPTURE_ERRORS[outcome.code] },
        ...(outcome.finalOrigin !== undefined ? { finalOrigin: outcome.finalOrigin } : {}),
        auditId: entry.auditId,
        mirror,
        ...anchorError,
      });
    };

    const egoBrowser = deps.tools.egoBrowser;
    if (!egoBrowser) return await finish("failed", { code: "browser_failed" });
    const profileId = req.isolated ? captureProfile(await deps.readConfig()) : null;
    if (req.isolated && profileId === null) return await finish("failed", { code: "isolated_profile_unset" });
    if (!(await deps.keychain.has(req.service, req.account))) return await finish("failed", { code: "not_found" });

    // Metadata only: where the item came from, and whether it changed since that capture.
    const recorded = audit.lastCapture(item);
    const modified = await deps.keychain.modifiedAt(req.service, req.account);
    const from = recorded?.origin || "unknown";
    const changed = recorded !== null && (recorded.itemModified === "" || modified === null || modified.toISOString() !== recorded.itemModified);
    const browser = req.isolated ? `isolated ego-browser profile ${profileId}` : `TaskSpace ${req.space}, page ${req.page}`;
    const lines = [
      `Log in to ${req.origin}?`,
      `Page: ${req.url}`,
      `User: ${req.user}`,
      `Password: Keychain item ${item}, typed into the password field, then the form is submitted (log in).`,
      changed ? `The item was captured from ${from}, but it changed after that capture.` : `The item was captured from ${from}.`,
      `Browser: ${browser}; the logged-in session then stays in that browser profile.`,
      "zks asks on every login.",
    ];
    if (lines.some((line) => line.length > MAX_DIALOG_LINE)) {
      return json(EXIT_USAGE, {
        ok: false,
        error: { code: "dialog_too_long", message: "the approval text is too long for one dialog (a line over 300 characters: shorten --url or --user)" },
      });
    }
    approval = "dialog";
    if (!(await deps.human.approve("zks: log in to a website", lines))) {
      return await finish("denied", { code: "not_approved", message: "the login was not approved; nothing was read" });
    }

    const outcome = await runLogin(deps.exec, egoBrowser, {
      mode: "login",
      space: req.space,
      page: req.page,
      selector: req.passwordSelector,
      click: null,
      origin: req.origin,
      service: req.service,
      account: req.account,
      waitMs: CAPTURE_WAIT_MS,
      ...(req.isolated && profileId !== null
        ? { isolated: { profileId, url: req.url, name: `zks-capture-${(deps.randomBytes ?? nodeRandomBytes)(8).toString("hex")}` } }
        : {}),
      login: { url: req.url, user: req.user, userSelector: req.userSelector, submitSelector: req.submitSelector, successSelector: req.successSelector },
    });
    if (outcome.ok) return await finish("applied", outcome);
    if (outcome.code === "login_redirected") {
      return await finish("failed", {
        code: "login_redirected",
        message: `the page left --origin during the login (final origin ${outcome.finalOrigin})`,
        finalOrigin: outcome.finalOrigin,
      });
    }
    return await finish("failed", { code: outcome.code });
  } finally {
    audit.close();
  }
}

/** Runs zks's capture script for req; the value never leaves it. */
function captureStep(deps: Deps, egoBrowser: string, req: CaptureRequest, profileId: string | null): Promise<CaptureOutcome> {
  return runCapture(deps.exec, egoBrowser, {
    mode: req.mode,
    space: req.space,
    page: req.page,
    selector: req.selector,
    click: req.click,
    origin: req.origin,
    service: req.service,
    account: req.account,
    waitMs: CAPTURE_WAIT_MS,
    ...(req.isolated && profileId !== null
      ? {
          isolated: {
            profileId,
            url: req.isolated.url,
            name: `zks-capture-${(deps.randomBytes ?? nodeRandomBytes)(8).toString("hex")}`,
          },
        }
      : {}),
  });
}
