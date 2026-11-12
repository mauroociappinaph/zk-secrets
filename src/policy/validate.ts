import { resolve as resolvePath } from "node:path";
import { MAX_TEMPLATE_LENGTH, TemplateSyntaxError, parseTemplate, templateRefs } from "./template.ts";
import {
  GENERATE_FORMATS,
  NETLIFY_CONTEXTS,
  PROVIDERS,
  VERCEL_ENVIRONMENTS,
  type Operation,
  type Policy,
  type SourceKind,
  type SourceSpec,
  type TargetConfig,
  type VariableSpec,
} from "./types.ts";

export const VARIABLE_NAME = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/;
export const TARGET_KEY = /^[a-z0-9][a-z0-9-]{0,62}$/;
export const PROJECT_NAME = /^[A-Za-z0-9._-]{1,64}$/;
const VERCEL_ID = /^[A-Za-z0-9_.-]{1,100}$/;
const GIT_BRANCH = /^[A-Za-z0-9_.\/-]{1,250}$/;
const GITHUB_ENVIRONMENT = /^[A-Za-z0-9_.-]{1,255}$/;
const RAILWAY_ID = /^[A-Za-z0-9-]{1,64}$/;
const NETLIFY_ID = /^[A-Za-z0-9_-]{1,100}$/;
const DOCKER_HOST = /^(unix:\/\/\/[\x21-\x7e]{1,200}|tcp:\/\/[A-Za-z0-9.:\[\]-]{1,200}|ssh:\/\/[A-Za-z0-9.:@-]{1,200})$/;
/** Docker secret names: letters, digits, `_`, `.`, `-`, starting and ending with a letter or digit. */
const DOCKER_SECRET_NAME = /^[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,62}[A-Za-z0-9])?$/;
/** A file system path zks shows in the dialog: printable ASCII, at most 200 characters. */
const FILE_PATH = /^[\x20-\x7E]{1,200}$/;
const DOTENV_FILE_NAME = /(^|\/)\.env[A-Za-z0-9_.-]*$/;
const AWS_PROFILE = /^[A-Za-z0-9_.-]{1,64}$/;
const KMS_KEY_ID = /^(alias\/[A-Za-z0-9\/_-]{1,250}|[0-9a-f-]{36}|arn:aws[a-z-]*:kms:[a-z0-9-]+:\d{12}:(key|alias)\/[A-Za-z0-9\/_-]+)$/;
const KEYCHAIN_ID = /^[A-Za-z0-9_.-]{1,128}$/;
/** At most 200 characters in total, so every approval line stays readable. */
const OP_REF = /^op:\/\/[\x21-\x7E]{1,195}$/;
const DOTENV_PATH = /^(?=.{1,200}$)(?:[A-Za-z0-9_-][A-Za-z0-9_.-]*\/)*\.env[A-Za-z0-9_.-]*$/;
/** Keychain service holding zks's own provider tokens and audit anchor; never a policy source. */
const RESERVED_KEYCHAIN_SERVICE = "zks";
const AWS_REGION = /^[a-z]{2}(-[a-z]+)+-\d$/;
const SSM_PREFIX = /^(?=.{1,200}$)\/([A-Za-z0-9_.-]+\/)*$/;
const SM_PREFIX = /^(?=.{0,200}$)([A-Za-z0-9_.+=@-]+\/)*$/;
const GITHUB_REPO = /^(?=.{1,100}$)[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;
/** Path segments GitHub would resolve as directories in an API URL. */
const DOT_SEGMENTS = [".", ".."];
/** Names that would collide with Object.prototype when used as keys, compared in lower case. */
const RESERVED_VARIABLE_NAMES = ["__proto__", "constructor", "prototype"];
const ROLE_ARN = /^arn:aws[a-z-]*:iam::\d{12}:role\/[A-Za-z0-9+=,.@_\/-]+$/;
const GENERATE_MIN_BYTES = 16;
const GENERATE_MAX_BYTES = 512;
export const PASSWORD_MIN_LENGTH = 12;
export const PASSWORD_MAX_LENGTH = 128;
export const PASSWORD_DEFAULT_LENGTH = 32;
export const RSA_DEFAULT_BITS = 3072;
const RSA_BITS = [2048, 3072, 4096];
const PASSWORD_CLASSES = ["lower", "upper", "digits", "symbols"] as const;
/** Options each generate format accepts besides kind and format. */
const FORMAT_OPTIONS: Record<string, string[]> = {
  random: ["bytes", "encoding"],
  uuid: [],
  "jwt-secret": [],
  password: ["length", ...PASSWORD_CLASSES],
  "rsa-private-key": ["bits"],
  "ed25519-private-key": [],
};
const GENERATE_OPTIONS = ["bytes", "encoding", "length", ...PASSWORD_CLASSES, "bits"];
const PRIVATE_KEY_FORMATS = ["rsa-private-key", "ed25519-private-key"];
const SOURCE_KINDS = ["op", "keychain", "prompt", "generate", "dotenv", "public-key", "template"];

export class PolicyError extends Error {
  readonly issues: string[];
  constructor(issues: string[]) {
    super(`invalid policy: ${issues.join("; ")}`);
    this.issues = issues;
  }
}

type Json = Record<string, unknown>;

const isObject = (v: unknown): v is Json => typeof v === "object" && v !== null && !Array.isArray(v);

/** Validates untrusted JSON into a Policy or throws PolicyError listing every issue. */
export function validatePolicy(input: unknown): Policy {
  const issues: string[] = [];
  if (!isObject(input)) throw new PolicyError(["policy: must be a JSON object"]);

  if (input.version !== 1) issues.push("version: must be 1");
  if (typeof input.project !== "string" || !PROJECT_NAME.test(input.project)) {
    issues.push(`project: must match ${PROJECT_NAME}`);
  }

  const targets = isObject(input.targets) ? input.targets : {};
  if (!isObject(input.targets)) issues.push("targets: must be an object");
  for (const [key, target] of Object.entries(targets)) {
    if (!TARGET_KEY.test(key)) issues.push(`targets.${key}: key must match ${TARGET_KEY}`);
    validateTarget(`targets.${key}`, target, issues);
  }

  const variables = isObject(input.variables) ? input.variables : {};
  if (!isObject(input.variables)) issues.push("variables: must be an object");
  for (const [name, spec] of Object.entries(variables)) {
    validateVariable(name, spec, targets, variables, issues);
  }
  validateCycles(variables, issues);

  if (issues.length > 0) throw new PolicyError(issues);
  return input as unknown as Policy;
}

function requireString(path: string, value: unknown, pattern: RegExp, issues: string[]): void {
  if (typeof value !== "string" || !pattern.test(value)) issues.push(`${path}: must match ${pattern}`);
}

function optionalString(path: string, value: unknown, pattern: RegExp, issues: string[]): void {
  if (value !== undefined) requireString(path, value, pattern, issues);
}

function validateTarget(path: string, target: unknown, issues: string[]): void {
  if (!isObject(target)) {
    issues.push(`${path}: must be an object`);
    return;
  }
  const provider = target.provider;
  if (typeof provider !== "string" || !(PROVIDERS as readonly string[]).includes(provider)) {
    issues.push(`${path}.provider: must be one of ${PROVIDERS.join(", ")}`);
    return;
  }
  switch (provider) {
    case "vercel": {
      requireString(`${path}.projectId`, target.projectId, VERCEL_ID, issues);
      optionalString(`${path}.teamId`, target.teamId, VERCEL_ID, issues);
      if (
        target.gitBranch !== undefined &&
        (typeof target.gitBranch !== "string" || !GIT_BRANCH.test(target.gitBranch) || target.gitBranch.includes(".."))
      ) {
        issues.push(`${path}.gitBranch: must match ${GIT_BRANCH} without ".."`);
      }
      const envs = target.environments;
      if (
        !Array.isArray(envs) ||
        envs.length === 0 ||
        !envs.every((e) => (VERCEL_ENVIRONMENTS as readonly unknown[]).includes(e))
      ) {
        issues.push(`${path}.environments: must be a non-empty subset of ${VERCEL_ENVIRONMENTS.join(", ")}`);
      }
      break;
    }
    case "aws-ssm":
    case "aws-sm": {
      requireString(`${path}.region`, target.region, AWS_REGION, issues);
      requireString(`${path}.prefix`, target.prefix, provider === "aws-ssm" ? SSM_PREFIX : SM_PREFIX, issues);
      optionalString(`${path}.profile`, target.profile, AWS_PROFILE, issues);
      optionalString(`${path}.roleArn`, target.roleArn, ROLE_ARN, issues);
      optionalString(`${path}.kmsKeyId`, target.kmsKeyId, KMS_KEY_ID, issues);
      break;
    }
    case "github":
      requireString(`${path}.repo`, target.repo, GITHUB_REPO, issues);
      if (typeof target.repo === "string" && GITHUB_REPO.test(target.repo) && target.repo.split("/").some((s) => DOT_SEGMENTS.includes(s))) {
        issues.push(`${path}.repo: owner and name must not be "." or ".."`);
      }
      optionalString(`${path}.environment`, target.environment, GITHUB_ENVIRONMENT, issues);
      if (typeof target.environment === "string" && DOT_SEGMENTS.includes(target.environment)) {
        issues.push(`${path}.environment: must not be "." or ".."`);
      }
      break;
    case "railway":
      requireString(`${path}.projectId`, target.projectId, RAILWAY_ID, issues);
      requireString(`${path}.environmentId`, target.environmentId, RAILWAY_ID, issues);
      optionalString(`${path}.serviceId`, target.serviceId, RAILWAY_ID, issues);
      if (target.tokenType !== undefined && target.tokenType !== "account" && target.tokenType !== "project") {
        issues.push(`${path}.tokenType: must be "account" or "project"`);
      }
      if (target.skipDeploys !== undefined && typeof target.skipDeploys !== "boolean") {
        issues.push(`${path}.skipDeploys: must be a boolean`);
      }
      break;
    case "supabase":
      requireString(`${path}.projectRef`, target.projectRef, /^[a-z0-9]{20}$/, issues);
      break;
    case "netlify":
      requireString(`${path}.accountId`, target.accountId, NETLIFY_ID, issues);
      optionalString(`${path}.siteId`, target.siteId, NETLIFY_ID, issues);
      if (!(NETLIFY_CONTEXTS as readonly unknown[]).includes(target.context)) {
        issues.push(`${path}.context: must be one of ${NETLIFY_CONTEXTS.join(", ")}`);
      }
      break;
    case "docker-swarm":
      if (typeof target.host !== "string" || !DOCKER_HOST.test(target.host)) {
        issues.push(`${path}.host: must be unix:///path, tcp://host:port or ssh://user@host`);
      }
      if (target.replace !== undefined && typeof target.replace !== "boolean") issues.push(`${path}.replace: must be a boolean`);
      break;
    case "compose":
      if (typeof target.dir !== "string" || !FILE_PATH.test(target.dir)) issues.push(`${path}.dir: must be a path of 1 to 200 printable characters`);
      break;
    case "dotenv":
      if (typeof target.path !== "string" || !FILE_PATH.test(target.path) || !DOTENV_FILE_NAME.test(target.path)) {
        issues.push(`${path}.path: must be a path of 1 to 200 printable characters to a .env* file`);
      }
      break;
  }
}

function validateGenerate(path: string, source: Json, issues: string[]): void {
  const format = source.format ?? "random";
  if (typeof format !== "string" || !(GENERATE_FORMATS as readonly string[]).includes(format)) {
    issues.push(`${path}.format: must be one of ${GENERATE_FORMATS.join(", ")}`);
    return;
  }
  const allowed = FORMAT_OPTIONS[format] as string[];
  for (const option of GENERATE_OPTIONS) {
    if (source[option] !== undefined && !allowed.includes(option)) issues.push(`${path}.${option}: is not valid for format "${format}"`);
  }
  switch (format) {
    case "random": {
      const bytes = source.bytes ?? 32;
      if (!Number.isInteger(bytes) || (bytes as number) < GENERATE_MIN_BYTES || (bytes as number) > GENERATE_MAX_BYTES) {
        issues.push(`${path}.bytes: must be an integer between ${GENERATE_MIN_BYTES} and ${GENERATE_MAX_BYTES}`);
      }
      if (source.encoding !== undefined && source.encoding !== "base64url" && source.encoding !== "hex") {
        issues.push(`${path}.encoding: must be "base64url" or "hex"`);
      }
      break;
    }
    case "password": {
      const length = source.length ?? PASSWORD_DEFAULT_LENGTH;
      if (!Number.isInteger(length) || (length as number) < PASSWORD_MIN_LENGTH || (length as number) > PASSWORD_MAX_LENGTH) {
        issues.push(`${path}.length: must be an integer between ${PASSWORD_MIN_LENGTH} and ${PASSWORD_MAX_LENGTH}`);
      }
      let enabled = 0;
      for (const cls of PASSWORD_CLASSES) {
        const value = source[cls] ?? true;
        if (typeof value !== "boolean") issues.push(`${path}.${cls}: must be true or false`);
        else if (value) enabled++;
      }
      if (enabled === 0 && PASSWORD_CLASSES.every((cls) => typeof (source[cls] ?? true) === "boolean")) {
        issues.push(`${path}: password needs at least one of ${PASSWORD_CLASSES.join(", ")}`);
      }
      break;
    }
    case "rsa-private-key":
      if (source.bits !== undefined && !RSA_BITS.includes(source.bits as number)) issues.push(`${path}.bits: must be 2048, 3072 or 4096`);
      break;
  }
}

function isPrivateKeySource(spec: unknown): boolean {
  return isObject(spec) && isObject(spec.source) && spec.source.kind === "generate" && PRIVATE_KEY_FORMATS.includes(spec.source.format as string);
}

/** Variables another variable's source reads: template references and the private key of a public-key. */
export function dependenciesOf(source: SourceSpec | undefined): string[] {
  if (source?.kind === "public-key") return [source.of];
  if (source?.kind === "template") {
    try {
      return templateRefs(parseTemplate(source.template));
    } catch {
      return [];
    }
  }
  return [];
}

/** Reports each reference cycle once, at the variable where it is first entered. */
function validateCycles(variables: Json, issues: string[]): void {
  const state = new Map<string, "visiting" | "done">();
  const stack: string[] = [];
  const deps = (name: string): string[] => {
    const spec = variables[name];
    if (!isObject(spec) || !isObject(spec.source) || (spec.source.kind !== "template" && spec.source.kind !== "public-key")) return [];
    if (spec.source.kind === "public-key" && typeof spec.source.of !== "string") return [];
    if (spec.source.kind === "template" && typeof spec.source.template !== "string") return [];
    return dependenciesOf(spec.source as unknown as SourceSpec).filter((d) => d !== name && Object.hasOwn(variables, d));
  };
  const visit = (name: string): void => {
    state.set(name, "visiting");
    stack.push(name);
    for (const dep of deps(name)) {
      if (state.get(dep) === "visiting") {
        const cycle = [...stack.slice(stack.indexOf(dep)), dep];
        issues.push(`variables.${dep}.source.template: reference cycle ${cycle.join(" -> ")}`);
      } else if (!state.has(dep)) {
        visit(dep);
      }
    }
    stack.pop();
    state.set(name, "done");
  };
  for (const name of Object.keys(variables)) if (!state.has(name)) visit(name);
}

function validateSource(path: string, name: string, source: unknown, variables: Json, issues: string[]): void {
  if (!isObject(source)) {
    issues.push(`${path}: must be an object`);
    return;
  }
  switch (source.kind) {
    case "op":
      if (typeof source.ref !== "string" || !OP_REF.test(source.ref)) {
        issues.push(`${path}.ref: must be an op:// reference`);
      }
      break;
    case "keychain":
      if (typeof source.service === "string" && source.service.toLowerCase() === RESERVED_KEYCHAIN_SERVICE) {
        issues.push(`${path}.service: "${RESERVED_KEYCHAIN_SERVICE}" is reserved for zks provider tokens`);
      } else {
        requireString(`${path}.service`, source.service, KEYCHAIN_ID, issues);
      }
      requireString(`${path}.account`, source.account, KEYCHAIN_ID, issues);
      break;
    case "prompt":
      break;
    case "generate":
      validateGenerate(path, source, issues);
      break;
    case "public-key": {
      const of = source.of;
      if (typeof of !== "string" || !VARIABLE_NAME.test(of) || of === name) issues.push(`${path}.of: must name another variable`);
      else if (!Object.hasOwn(variables, of)) issues.push(`${path}.of: unknown variable "${of}"`);
      else if (!isPrivateKeySource(variables[of])) {
        issues.push(`${path}.of: "${of}" must use a generate rsa-private-key or ed25519-private-key source`);
      }
      break;
    }
    case "template": {
      const text = source.template;
      if (typeof text !== "string" || text.length === 0 || text.length > MAX_TEMPLATE_LENGTH) {
        issues.push(`${path}.template: must be a string of 1 to ${MAX_TEMPLATE_LENGTH} characters`);
        break;
      }
      let refs: string[];
      try {
        refs = templateRefs(parseTemplate(text));
      } catch (error) {
        if (!(error instanceof TemplateSyntaxError)) throw error;
        issues.push(`${path}.template: ${error.message}`);
        break;
      }
      if (refs.length === 0) issues.push(`${path}.template: must reference at least one variable`);
      for (const ref of refs) {
        if (ref === name) issues.push(`${path}.template: references itself`);
        else if (!Object.hasOwn(variables, ref)) issues.push(`${path}.template: unknown variable "${ref}"`);
      }
      break;
    }
    case "dotenv":
      if (typeof source.path !== "string" || !DOTENV_PATH.test(source.path) || source.path.split("/").includes("..")) {
        issues.push(`${path}.path: must be a relative .env* file inside the project`);
      }
      optionalString(`${path}.key`, source.key, VARIABLE_NAME, issues);
      break;
    default:
      issues.push(`${path}.kind: must be one of ${SOURCE_KINDS.join(", ")}`);
  }
}

function validateVariable(name: string, spec: unknown, targets: Json, variables: Json, issues: string[]): void {
  const path = `variables.${name}`;
  if (RESERVED_VARIABLE_NAMES.includes(name.toLowerCase())) issues.push(`${path}: name is reserved`);
  else if (!VARIABLE_NAME.test(name)) issues.push(`${path}: name must match ${VARIABLE_NAME}`);
  if (!isObject(spec)) {
    issues.push(`${path}: must be an object`);
    return;
  }
  if (typeof spec.sensitive !== "boolean") issues.push(`${path}.sensitive: must be true or false`);
  if (spec.description !== undefined && typeof spec.description !== "string") {
    issues.push(`${path}.description: must be a string`);
  }

  if (spec.sensitive === true && spec.value !== undefined) {
    issues.push(`${path}.value: is not allowed when sensitive is true; use a source`);
  }
  if (spec.value !== undefined && typeof spec.value !== "string") issues.push(`${path}.value: must be a string`);
  if (spec.source === undefined && spec.value === undefined) issues.push(`${path}: needs a source or a value`);
  if (spec.source !== undefined && spec.value !== undefined) issues.push(`${path}: use either source or value, not both`);
  // A public key is the one derived value that is not secret.
  if (spec.source !== undefined && spec.sensitive === false && !(isObject(spec.source) && spec.source.kind === "public-key")) {
    issues.push(`${path}.sensitive: must be true when a source is used; only literal values can be non-sensitive`);
  }
  if (spec.source !== undefined) validateSource(`${path}.source`, name, spec.source, variables, issues);

  if (!Array.isArray(spec.targets) || spec.targets.length === 0) {
    issues.push(`${path}.targets: must be a non-empty list of target keys`);
    return;
  }
  for (const key of spec.targets) {
    const target = typeof key === "string" && Object.hasOwn(targets, key) ? targets[key] : undefined;
    if (!isObject(target)) {
      issues.push(`${path}.targets: unknown target "${String(key)}"`);
      continue;
    }
    if (target.provider === "supabase" && name.toUpperCase().startsWith("SUPABASE_")) {
      issues.push(`${path}: Supabase reserves the SUPABASE_ prefix`);
    }
    if (
      target.provider === "vercel" &&
      spec.sensitive === true &&
      Array.isArray(target.environments) &&
      target.environments.includes("development")
    ) {
      issues.push(`${path}: Vercel sensitive variables cannot target development (target "${key}")`);
    }
    if (target.provider === "docker-swarm" && VARIABLE_NAME.test(name) && !DOCKER_SECRET_NAME.test(name)) {
      issues.push(`${path}: docker secret names must start and end with a letter or digit (target "${key}")`);
    }
  }
}

export function sourceKindOf(spec: VariableSpec): SourceKind {
  return spec.source ? spec.source.kind : "literal";
}

export interface Selection {
  only?: string[];
  targets?: string[];
}

/** Expands variables × targets into operations, filtered by --only and --target. */
export function planOperations(policy: Policy, selection: Selection = {}): Operation[] {
  const unknownNames = (selection.only ?? []).filter((n) => !Object.hasOwn(policy.variables, n));
  const unknownTargets = (selection.targets ?? []).filter((t) => !Object.hasOwn(policy.targets, t));
  const issues = [
    ...unknownNames.map((n) => `--only: unknown variable "${n}"`),
    ...unknownTargets.map((t) => `--target: unknown target "${t}"`),
  ];
  if (issues.length > 0) throw new PolicyError(issues);

  const selected = (name: string, variable: VariableSpec) =>
    (!selection.only || selection.only.includes(name)) &&
    variable.targets.some((t) => !selection.targets || selection.targets.includes(t));
  const written = new Set(Object.entries(policy.variables).filter(([n, v]) => selected(n, v)).map(([n]) => n));
  for (const name of written) {
    for (const dep of generatedDependencies(policy, name)) {
      if (!written.has(dep)) {
        issues.push(`selection: ${name} uses ${dep}, a generated value this selection does not write; select it too`);
      }
    }
  }
  if (issues.length > 0) throw new PolicyError(issues);

  const ops: Operation[] = [];
  for (const [name, variable] of Object.entries(policy.variables)) {
    if (selection.only && !selection.only.includes(name)) continue;
    for (const targetKey of variable.targets) {
      if (selection.targets && !selection.targets.includes(targetKey)) continue;
      const target = policy.targets[targetKey] as TargetConfig;
      ops.push({ name, targetKey, target, variable, sourceKind: sourceKindOf(variable) });
    }
  }
  return ops;
}

/** Generated variables a variable's value is derived from, directly or through other derived variables. */
export function generatedDependencies(policy: Policy, name: string): string[] {
  const found: string[] = [];
  const seen = new Set<string>([name]);
  const walk = (current: string): void => {
    for (const dep of dependenciesOf(policy.variables[current]?.source)) {
      if (seen.has(dep)) continue;
      seen.add(dep);
      if (policy.variables[dep]?.source?.kind === "generate") found.push(dep);
      walk(dep);
    }
  };
  walk(name);
  return found;
}

/** Variables whose value is derived from name, directly or through other derived variables, in policy order. */
export function dependentsOf(policy: Policy, name: string): string[] {
  const found = new Set<string>();
  let grew = true;
  while (grew) {
    grew = false;
    for (const [candidate, spec] of Object.entries(policy.variables)) {
      if (candidate === name || found.has(candidate)) continue;
      if (dependenciesOf(spec.source).some((dep) => dep === name || found.has(dep))) {
        found.add(candidate);
        grew = true;
      }
    }
  }
  return Object.keys(policy.variables).filter((n) => found.has(n));
}

const ROTATES = " - NEW value on every apply";

/** Human text for a source; dotenv paths are shown resolved against cwd, as zks will read them. */
export function describeSource(source: SourceSpec | undefined, cwd: string): string {
  if (!source) return "literal";
  switch (source.kind) {
    case "op":
      return `1Password ${source.ref}`;
    case "keychain":
      return `Keychain ${source.service}/${source.account}`;
    case "prompt":
      return "typed by you in a hidden dialog";
    case "generate":
      switch (source.format ?? "random") {
        case "random":
          return `NEW random value (${source.bytes ?? 32} bytes) - rotates on every apply`;
        case "password":
          return `generate password(${source.length ?? PASSWORD_DEFAULT_LENGTH})${ROTATES}`;
        case "rsa-private-key":
          return `generate rsa-private-key(${source.bits ?? RSA_DEFAULT_BITS})${ROTATES}`;
        default:
          return `generate ${source.format}${ROTATES}`;
      }
    case "dotenv":
      return `dotenv ${resolvePath(cwd, source.path)}${source.key ? `#${source.key}` : ""}`;
    case "public-key":
      return `public-key of ${source.of}`;
    case "template":
      return `template(${dependenciesOf(source).join(", ")})`;
  }
}
