import {
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
const SAFE_ID = /^[A-Za-z0-9._:/@+=-]{1,256}$/;
const AWS_REGION = /^[a-z]{2}(-[a-z]+)+-\d$/;
const SSM_PREFIX = /^\/([A-Za-z0-9_.-]+\/)*$/;
const SM_PREFIX = /^([A-Za-z0-9_.+=@-]+\/)*$/;
const GITHUB_REPO = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;
const ROLE_ARN = /^arn:aws[a-z-]*:iam::\d{12}:role\/[A-Za-z0-9+=,.@_\/-]+$/;
const GENERATE_MIN_BYTES = 16;
const GENERATE_MAX_BYTES = 512;

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
    validateVariable(name, spec, targets, issues);
  }

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
      requireString(`${path}.projectId`, target.projectId, SAFE_ID, issues);
      optionalString(`${path}.teamId`, target.teamId, SAFE_ID, issues);
      optionalString(`${path}.gitBranch`, target.gitBranch, SAFE_ID, issues);
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
      optionalString(`${path}.profile`, target.profile, SAFE_ID, issues);
      optionalString(`${path}.roleArn`, target.roleArn, ROLE_ARN, issues);
      optionalString(`${path}.kmsKeyId`, target.kmsKeyId, SAFE_ID, issues);
      break;
    }
    case "github":
      requireString(`${path}.repo`, target.repo, GITHUB_REPO, issues);
      optionalString(`${path}.environment`, target.environment, SAFE_ID, issues);
      break;
    case "railway":
      requireString(`${path}.projectId`, target.projectId, SAFE_ID, issues);
      requireString(`${path}.environmentId`, target.environmentId, SAFE_ID, issues);
      optionalString(`${path}.serviceId`, target.serviceId, SAFE_ID, issues);
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
  }
}

function validateSource(path: string, source: unknown, issues: string[]): void {
  if (!isObject(source)) {
    issues.push(`${path}: must be an object`);
    return;
  }
  switch (source.kind) {
    case "op":
      if (typeof source.ref !== "string" || !/^op:\/\/[^\s]+$/.test(source.ref)) {
        issues.push(`${path}.ref: must be an op:// reference`);
      }
      break;
    case "keychain":
      requireString(`${path}.service`, source.service, SAFE_ID, issues);
      requireString(`${path}.account`, source.account, SAFE_ID, issues);
      break;
    case "prompt":
      break;
    case "generate": {
      const bytes = source.bytes ?? 32;
      if (!Number.isInteger(bytes) || (bytes as number) < GENERATE_MIN_BYTES || (bytes as number) > GENERATE_MAX_BYTES) {
        issues.push(`${path}.bytes: must be an integer between ${GENERATE_MIN_BYTES} and ${GENERATE_MAX_BYTES}`);
      }
      if (source.encoding !== undefined && source.encoding !== "base64url" && source.encoding !== "hex") {
        issues.push(`${path}.encoding: must be "base64url" or "hex"`);
      }
      break;
    }
    case "dotenv":
      if (typeof source.path !== "string" || source.path.length === 0) issues.push(`${path}.path: must be a file path`);
      optionalString(`${path}.key`, source.key, VARIABLE_NAME, issues);
      break;
    default:
      issues.push(`${path}.kind: must be one of op, keychain, prompt, generate, dotenv`);
  }
}

function validateVariable(name: string, spec: unknown, targets: Json, issues: string[]): void {
  const path = `variables.${name}`;
  if (!VARIABLE_NAME.test(name)) issues.push(`${path}: name must match ${VARIABLE_NAME}`);
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
  if (spec.source !== undefined) validateSource(`${path}.source`, spec.source, issues);

  if (!Array.isArray(spec.targets) || spec.targets.length === 0) {
    issues.push(`${path}.targets: must be a non-empty list of target keys`);
    return;
  }
  for (const key of spec.targets) {
    const target = typeof key === "string" ? targets[key] : undefined;
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
  const unknownNames = (selection.only ?? []).filter((n) => !(n in policy.variables));
  const unknownTargets = (selection.targets ?? []).filter((t) => !(t in policy.targets));
  const issues = [
    ...unknownNames.map((n) => `--only: unknown variable "${n}"`),
    ...unknownTargets.map((t) => `--target: unknown target "${t}"`),
  ];
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

export function describeSource(source: SourceSpec | undefined): string {
  if (!source) return "literal";
  switch (source.kind) {
    case "op":
      return `1Password ${source.ref}`;
    case "keychain":
      return `Keychain ${source.service}/${source.account}`;
    case "prompt":
      return "typed by you in a hidden dialog";
    case "generate":
      return `NEW random value (${source.bytes ?? 32} bytes) - rotates on every apply`;
    case "dotenv":
      return `dotenv ${source.path}${source.key ? `#${source.key}` : ""}`;
  }
}
