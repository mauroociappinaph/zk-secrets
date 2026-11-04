import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { test } from "node:test";
import { createSheetsMirror } from "../src/audit/mirror.ts";
import { openAuditStore } from "../src/audit/store.ts";
import type { AuditEntryInput } from "../src/audit/types.ts";
import { createMacDialogs } from "../src/gate/dialog.ts";
import { agentLabel, sanitizeProcessEnv } from "../src/platform/environment.ts";
import { SAFE_PATH, childEnv } from "../src/platform/exec.ts";
import { MAX_OPERATIONS_PER_APPROVAL, run } from "../src/run.ts";
import { Redactor } from "../src/secret/redactor.ts";
import { SecretBuffer } from "../src/secret/secret-buffer.ts";
import { SourceError, resolveValue } from "../src/sources/resolve.ts";
import { CANARY, fakeExec, fakeFetch, fakeHuman, fakeKeychain, harness, parse, tempDir } from "./helpers.ts";

const BASE = { home: "/Users/real", user: "real" };
const FIVE_KEYS = { PATH: SAFE_PATH, HOME: "/Users/real", USER: "real", LOGNAME: "real", LANG: "en_US.UTF-8" };

const targets = {
  "vercel-prod": { provider: "vercel", projectId: "prj_1", teamId: "team_1", environments: ["production", "preview"], gitBranch: "main" },
  ssm: { provider: "aws-ssm", region: "sa-east-1", prefix: "/hismia/prod/", kmsKeyId: "alias/hismia", roleArn: "arn:aws:iam::123456789012:role/w", profile: "prod" },
  sm: { provider: "aws-sm", region: "sa-east-1", prefix: "hismia/prod/" },
  gh: { provider: "github", repo: "acme/web", environment: "production" },
  railway: { provider: "railway", projectId: "p1", environmentId: "e1", serviceId: "s1" },
  supa: { provider: "supabase", projectRef: "abcdefghijklmnopqrst" },
};

const policyWith = (variables: Record<string, unknown>, extraTargets: Record<string, unknown> = {}) => ({
  version: 1,
  project: "hismia-web",
  targets: { ...targets, ...extraTargets },
  variables,
});

const stripe = (targetKeys: string[]) => ({
  STRIPE_SECRET_KEY: { sensitive: true, source: { kind: "keychain", service: "hismia", account: "stripe" }, targets: targetKeys },
});

const tokens = { "zks/vercel": "tok-vercel-1", "zks/railway": "tok-railway-1", "zks/supabase": "tok-supabase-1" };

async function issuesOf(policy: unknown): Promise<string[]> {
  const out = await run(["validate"], harness({ policy }).deps);
  assert.equal(out.exitCode, 2, out.stdout);
  return parse(out.stdout).error.issues as string[];
}

// 1. Environment isolation

test("S1: childEnv forwards nothing from the parent environment", () => {
  process.env.GH_HOST = "evil.example";
  process.env.XDG_CONFIG_HOME = "/tmp/evil";
  process.env.OP_CONNECT_HOST = "https://evil.example";
  const savedPath = process.env.PATH;
  process.env.PATH = "/tmp/evil-bin";
  try {
    assert.deepEqual(childEnv(BASE), FIVE_KEYS);
  } finally {
    delete process.env.GH_HOST;
    delete process.env.XDG_CONFIG_HOME;
    delete process.env.OP_CONNECT_HOST;
    process.env.PATH = savedPath;
  }
  assert.equal(SAFE_PATH, "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin");
});

test("S1: sanitizeProcessEnv leaves exactly HOME, USER, LOGNAME, LANG and PATH", () => {
  const env: NodeJS.ProcessEnv = {
    AWS_ENDPOINT_URL: "https://evil.example",
    AWS_PROFILE: "evil",
    HTTPS_PROXY: "http://evil:8080",
    http_proxy: "http://evil:8080",
    NODE_EXTRA_CA_CERTS: "/tmp/evil.pem",
    NODE_USE_ENV_PROXY: "1",
    GH_HOST: "evil.example",
    OP_CONNECT_HOST: "https://evil.example",
    XDG_CONFIG_HOME: "/tmp/evil",
    SSL_CERT_FILE: "/tmp/evil.pem",
    HOME: "/tmp/fake-home",
    PATH: "/tmp/evil-bin",
    RANDOM_THING: "x",
  };
  sanitizeProcessEnv(env, BASE);
  assert.deepEqual(env, FIVE_KEYS);
});

test("agentLabel prefers ZKS_AGENT_LABEL, then PI_SESSION_ID, then AI_AGENT, else human", () => {
  assert.equal(agentLabel({ ZKS_AGENT_LABEL: "pi:abc", PI_SESSION_ID: "zzz", AI_AGENT: "codex" }), "pi:abc");
  assert.equal(agentLabel({ ZKS_AGENT_LABEL: "", PI_SESSION_ID: "s1", AI_AGENT: "codex" }), "pi:s1");
  assert.equal(agentLabel({ AI_AGENT: "codex" }), "codex");
  assert.equal(agentLabel({}), "human");
});

// 2. Approval dialog completeness

test("S5: the approval dialog shows the real destination of every write", async () => {
  const h = harness({ policy: policyWith(stripe(Object.keys(targets))), keychain: { ...tokens, "hismia/stripe": CANARY }, approve: false });

  const out = await run(["apply"], h.deps);

  assert.equal(out.exitCode, 3);
  assert.deepEqual(h.human.approvals[0], [
    "Project: hismia-web",
    "Write 6 value(s):",
    "",
    "- STRIPE_SECRET_KEY -> vercel project prj_1 team team_1 env production+preview branch main [secret; Keychain hismia/stripe] (target vercel-prod) [NEW destination]",
    "- STRIPE_SECRET_KEY -> aws-ssm sa-east-1 /hismia/prod/STRIPE_SECRET_KEY role arn:aws:iam::123456789012:role/w profile prod kms alias/hismia [secret; Keychain hismia/stripe] (target ssm) [NEW destination]",
    "- STRIPE_SECRET_KEY -> aws-sm sa-east-1 hismia/prod/STRIPE_SECRET_KEY [secret; Keychain hismia/stripe] (target sm) [NEW destination]",
    "- STRIPE_SECRET_KEY -> github acme/web env production secret [secret; Keychain hismia/stripe] (target gh) [NEW destination]",
    "- STRIPE_SECRET_KEY -> railway project p1 env e1 service s1 [secret; Keychain hismia/stripe] (target railway) [NEW destination]",
    "- STRIPE_SECRET_KEY -> supabase project abcdefghijklmnopqrst [secret; Keychain hismia/stripe] (target supa) [NEW destination]",
    "",
    "Always allow: trust every [NEW destination] (whole GitHub owner, Vercel team, AWS profile+role+region or project) for all projects.",
  ]);
});

test("S5: plan shows the destination and a plain github value is a variable", async () => {
  const h = harness({ policy: policyWith({ LOG_LEVEL: { sensitive: false, value: "info", targets: ["gh"] } }) });
  const out = await run(["plan"], h.deps);
  assert.equal(out.exitCode, 0, out.stdout);
  assert.equal(parse(out.stdout).operations[0].destination, "github acme/web env production variable");
});

test("S5: apply refuses more writes than one dialog can show, before any dialog or audit", async () => {
  assert.equal(MAX_OPERATIONS_PER_APPROVAL, 20);
  const variables: Record<string, unknown> = {};
  for (let i = 0; i < 21; i++) variables[`V${i}`] = { sensitive: true, source: { kind: "prompt" }, targets: ["supa"] };
  const h = harness({ policy: policyWith(variables) });

  const out = await run(["apply"], h.deps);

  assert.equal(out.exitCode, 2);
  assert.deepEqual(parse(out.stdout), {
    ok: false,
    error: { code: "too_many_operations", message: "21 writes do not fit in one approval dialog (max 20); narrow with --only or --target" },
  });
  assert.equal(h.human.approvals.length, 0);
  assert.equal(existsSync(h.auditDb), false);

  const narrowed = await run(["apply", "--only", "V1,V2"], harness({ policy: policyWith(variables), approve: false }).deps);
  assert.equal(narrowed.exitCode, 3);
});

test("S5: dialog lines are reduced to printable ASCII and an oversized dialog is denied", async () => {
  const f = fakeExec(() => ({ stdout: Buffer.from("Approve\n") }));
  await createMacDialogs(f.exec, "darwin").approve("t\u202e", ["a\u202eb", "c\nd\te", "ok é"]);
  const script = f.calls[0]!.input;
  assert.ok(script.includes("a?b\nc?d?e\nok ?"), script);
  assert.ok(!/[\u202e\u00e9\t]/.test(script));
  assert.ok(script.includes('with title "t?"'));

  const big = fakeExec(() => ({ stdout: Buffer.from("Approve\n") }));
  assert.equal(await createMacDialogs(big.exec, "darwin").approve("t", Array(26).fill("x")), false);
  assert.equal(big.calls.length, 0);
});

// 3. Sensitivity and source restrictions

test("S1: a source can never feed a non-sensitive variable", async () => {
  const issues = await issuesOf(policyWith({ LEAK: { sensitive: false, source: { kind: "keychain", service: "hismia", account: "stripe" }, targets: ["gh"] } }));
  assert.deepEqual(issues, ["variables.LEAK.sensitive: must be true when a source is used; only literal values can be non-sensitive"]);
});

test("S1: the zks Keychain service is reserved for provider tokens", async () => {
  const issues = await issuesOf(policyWith({ T: { sensitive: true, source: { kind: "keychain", service: "zks", account: "vercel" }, targets: ["gh"] } }));
  assert.deepEqual(issues, ['variables.T.source.service: "zks" is reserved for zks provider tokens']);
});

test("S1: dotenv paths must be relative .env* files inside the project", async () => {
  for (const path of ["../.env", "/Users/me/.env", "~/.aws/credentials", "apps/../../.env", ".aws/credentials", ".env\u202e", "a b/.env", ""]) {
    const issues = await issuesOf(policyWith({ D: { sensitive: true, source: { kind: "dotenv", path }, targets: ["gh"] } }));
    assert.deepEqual(issues, ["variables.D.source.path: must be a relative .env* file inside the project"], path);
  }
  for (const path of [".env", ".env.local", "apps/web/.env.production"]) {
    const out = await run(["validate"], harness({ policy: policyWith({ D: { sensitive: true, source: { kind: "dotenv", path }, targets: ["gh"] } }) }).deps);
    assert.equal(out.exitCode, 0, `${path}: ${out.stdout}`);
  }
});

test("S1: op references are printable ASCII without spaces", async () => {
  for (const ref of ["op://v/i/f\u202e", "op://v/i f", "op://", "op://v\n- FAKE -> line"]) {
    const issues = await issuesOf(policyWith({ O: { sensitive: true, source: { kind: "op", ref }, targets: ["gh"] } }));
    assert.deepEqual(issues, ["variables.O.source.ref: must be an op:// reference"], ref);
  }
});

test("S1: dotenv resolution refuses a path that leaves the project", async () => {
  let reads = 0;
  const deps = {
    exec: fakeExec().exec,
    keychain: fakeKeychain().keychain,
    human: fakeHuman().human,
    cwd: "/w/project",
    readFile: async () => {
      reads++;
      return Buffer.from("D=x");
    },
  };
  await assert.rejects(
    resolveValue("D", { sensitive: true, targets: [], source: { kind: "dotenv", path: "../other/.env" } }, deps),
    (error: unknown) =>
      error instanceof SourceError && error.code === "source_invalid" && error.message === "dotenv path for D must stay inside the project",
  );
  assert.equal(reads, 0);
});

// 4. Strict identifiers

test("prototype keys are not targets or variables", async () => {
  const proto = await issuesOf(policyWith({ A: { sensitive: true, source: { kind: "prompt" }, targets: ["__proto__", "toString"] } }));
  assert.deepEqual(proto, ['variables.A.targets: unknown target "__proto__"', 'variables.A.targets: unknown target "toString"']);

  const h = harness({ policy: policyWith(stripe(["gh"])) });
  const only = await run(["plan", "--only", "toString"], h.deps);
  assert.equal(only.exitCode, 2);
  assert.deepEqual(parse(only.stdout).error.issues, ['--only: unknown variable "toString"']);
  const target = await run(["plan", "--target", "constructor"], h.deps);
  assert.equal(target.exitCode, 2);
  assert.deepEqual(parse(target.stdout).error.issues, ['--target: unknown target "constructor"']);
});

test("target identifiers are strict", async () => {
  const bad = {
    v1: { provider: "vercel", projectId: "prj 1", teamId: "team/1", environments: ["preview"], gitBranch: "a..b" },
    g1: { provider: "github", repo: "acme/web", environment: "../x" },
    r1: { provider: "railway", projectId: "p_1", environmentId: "e.1", serviceId: "s/1" },
    a1: { provider: "aws-ssm", region: "us-east-1", prefix: "/a/", profile: "a b", kmsKeyId: "k1" },
  };
  const issues = await issuesOf({
    version: 1,
    project: "x",
    targets: bad,
    variables: { K: { sensitive: true, source: { kind: "keychain", service: "svc/x", account: "a:b" }, targets: ["g1"] } },
  });
  assert.deepEqual(issues, [
    "targets.v1.projectId: must match /^[A-Za-z0-9_.-]{1,100}$/",
    "targets.v1.teamId: must match /^[A-Za-z0-9_.-]{1,100}$/",
    'targets.v1.gitBranch: must match /^[A-Za-z0-9_.\\/-]{1,250}$/ without ".."',
    "targets.g1.environment: must match /^[A-Za-z0-9_.-]{1,255}$/",
    "targets.r1.projectId: must match /^[A-Za-z0-9-]{1,64}$/",
    "targets.r1.environmentId: must match /^[A-Za-z0-9-]{1,64}$/",
    "targets.r1.serviceId: must match /^[A-Za-z0-9-]{1,64}$/",
    "targets.a1.profile: must match /^[A-Za-z0-9_.-]{1,64}$/",
    "targets.a1.kmsKeyId: must match /^(alias\\/[A-Za-z0-9\\/_-]{1,250}|[0-9a-f-]{36}|arn:aws[a-z-]*:kms:[a-z0-9-]+:\\d{12}:(key|alias)\\/[A-Za-z0-9\\/_-]+)$/",
    "variables.K.source.service: must match /^[A-Za-z0-9_.-]{1,128}$/",
    "variables.K.source.account: must match /^[A-Za-z0-9_.-]{1,128}$/",
  ]);
  const out = await run(["validate"], harness({ policy: { version: 1, project: "x", targets: { g: { provider: "github", repo: "a/b", environment: "../x" } }, variables: {} } }).deps);
  assert.equal(out.exitCode, 2);
});

test("valid kms key forms pass", async () => {
  for (const kmsKeyId of ["alias/app", "1234abcd-12ab-34cd-56ef-1234567890ab", "arn:aws:kms:us-east-1:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab"]) {
    const policy = { version: 1, project: "x", targets: { a: { provider: "aws-sm", region: "us-east-1", prefix: "a/", kmsKeyId } }, variables: {} };
    assert.equal((await run(["validate"], harness({ policy }).deps)).exitCode, 0, kmsKeyId);
  }
});

// 5. CLI argument strictness

test("short options and extra positionals are refused without echoing them", async () => {
  const h = harness({ policy: policyWith(stripe(["gh"])) });
  const short = await run(["apply", "-x"], h.deps);
  assert.equal(short.exitCode, 2);
  assert.deepEqual(parse(short.stdout), { ok: false, error: { code: "usage", message: "unknown option -x" } });

  const cases = [
    ["plan", "sk_live_X"],
    ["apply", "sk_live_X"],
    ["validate", "sk_live_X"],
    ["init", "sk_live_X"],
    ["doctor", "sk_live_X"],
    ["audit", "verify", "sk_live_X"],
    ["auth", "status", "sk_live_X"],
    ["auth", "set", "vercel", "sk_live_X"],
    ["auth", "delete", "vercel", "sk_live_X"],
    ["config", "show", "sk_live_X"],
    ["config", "set", "sheets-webhook", "https://script.google.com/macros/s/abc/exec", "sk_live_X"],
    ["config", "unset", "sheets-webhook", "sk_live_X"],
  ];
  for (const argv of cases) {
    const out = await run(argv, h.deps);
    assert.equal(out.exitCode, 2, argv.join(" "));
    assert.equal(out.stdout, `${JSON.stringify({ ok: false, error: { code: "usage", message: "unexpected argument" } }, null, 2)}\n`);
  }
  assert.equal(h.human.approvals.length + h.human.prompts.length, 0);
  assert.equal(h.keychain.store.size, 0);
  assert.deepEqual(h.config, {});
});

test("commands keep working with their allowed arguments", async () => {
  const h = harness({ policy: policyWith(stripe(["gh"])) });
  assert.equal((await run(["plan", "--only", "STRIPE_SECRET_KEY"], h.deps)).exitCode, 0);
  assert.equal((await run(["auth", "status"], h.deps)).exitCode, 0);
  assert.equal((await run(["audit", "list", "--limit", "5"], h.deps)).exitCode, 0);
  assert.equal((await run(["config", "show"], h.deps)).exitCode, 0);
});

// 6. Audit correctness

const entry = (variableName = "API_KEY"): AuditEntryInput => ({
  ts: "2026-11-04T12:00:00.000Z",
  actorHuman: "tester",
  actorAgent: "pi:s1",
  project: "web",
  provider: "vercel",
  target: "vercel-prod",
  environment: "production",
  variableName,
  action: "set",
  sensitive: true,
  sourceKind: "op",
  result: "applied",
  providerVersion: "env_1",
  errorCode: "",
});

test("S4: an audit append failure after a successful write is reported as audit_failed, not failed", async () => {
  const h = harness({ policy: policyWith(stripe(["ssm", "sm", "gh"])), keychain: { "hismia/stripe": CANARY } });
  h.deps.openAudit = () => {
    const store = openAuditStore(h.auditDb);
    let calls = 0;
    return {
      ...store,
      append(input) {
        calls++;
        if (calls === 2) throw new Error("disk full");
        return store.append(input);
      },
    };
  };

  const out = await run(["apply"], h.deps);

  assert.equal(out.exitCode, 1, out.stdout);
  const body = parse(out.stdout);
  assert.equal(body.ok, false);
  assert.deepEqual(body.error, {
    code: "audit_failed",
    message: "the provider write for STRIPE_SECRET_KEY -> sm succeeded but its audit record could not be written",
  });
  assert.deepEqual(body.results.map((r: { target: string; result: string }) => [r.target, r.result]), [["ssm", "applied"]]);
  assert.equal(h.aws.calls.length, 2, "both AWS writes happened");
  assert.equal(h.exec.calls.length, 0, "no write after the audit failure");
  assert.ok(!out.stdout.includes(CANARY));
});

test("S4: verify with an anchor detects a deleted tail", () => {
  const path = join(tempDir(), "state", "audit.db");
  const store = openAuditStore(path);
  assert.deepEqual(store.head(), { count: 0, hash: "0".repeat(64) });
  store.append(entry("A"));
  store.append(entry("B"));
  const c = store.append(entry("C"));
  const anchor = store.head();
  assert.deepEqual(anchor, { count: 3, hash: c.hash });
  assert.deepEqual(store.verify(anchor), { ok: true, count: 3 });

  const db = new DatabaseSync(path);
  db.exec("DROP TRIGGER audit_no_delete");
  db.prepare("DELETE FROM audit WHERE audit_id = ?").run(c.auditId);
  db.close();

  assert.deepEqual(store.verify(), { ok: true, count: 2 });
  assert.deepEqual(store.verify(anchor), { ok: false, count: 2, brokenAt: "truncated" });
  assert.deepEqual(store.verify({ count: 2, hash: "f".repeat(64) }), { ok: false, count: 2, brokenAt: "truncated" });
  store.close();
});

test("S4: every apply and denied apply stores the audit head in the Keychain", async () => {
  const h = harness({ policy: policyWith(stripe(["ssm", "sm"])), keychain: { "hismia/stripe": CANARY } });
  const headNow = () => {
    const store = openAuditStore(h.auditDb);
    const head = store.head();
    store.close();
    return `${head.count}:${head.hash}`;
  };

  assert.equal((await run(["apply"], h.deps)).exitCode, 0);
  assert.equal(h.keychain.store.get("zks/audit-head"), headNow());
  assert.match(h.keychain.store.get("zks/audit-head")!, /^2:[0-9a-f]{64}$/);
  assert.equal((await run(["apply"], h.deps)).exitCode, 0);
  assert.equal(h.keychain.store.get("zks/audit-head"), headNow());
  assert.match(h.keychain.store.get("zks/audit-head")!, /^4:/);

  const denied = harness({ policy: policyWith(stripe(["ssm"])), approve: false });
  assert.equal((await run(["apply"], denied.deps)).exitCode, 3);
  assert.match(denied.keychain.store.get("zks/audit-head")!, /^1:[0-9a-f]{64}$/);
});

test("S4: zks audit verify checks the chain against the Keychain anchor", async () => {
  const h = harness({ policy: policyWith(stripe(["ssm"])), keychain: { "hismia/stripe": CANARY } });
  await run(["apply"], h.deps);
  const ok = await run(["audit", "verify"], h.deps);
  assert.equal(ok.exitCode, 0, ok.stdout);
  assert.deepEqual(parse(ok.stdout), { ok: true, count: 1, anchored: true });

  h.keychain.store.set("zks/audit-head", `5:${"a".repeat(64)}`);
  const truncated = await run(["audit", "verify"], h.deps);
  assert.equal(truncated.exitCode, 1);
  assert.deepEqual(parse(truncated.stdout), { ok: false, count: 1, brokenAt: "truncated", anchored: true });

  const fresh = harness();
  assert.deepEqual(parse((await run(["audit", "verify"], fresh.deps)).stdout), { ok: true, count: 0, anchored: false });
});

test("S4: config set and unset need the human's approval", async () => {
  const url = "https://script.google.com/macros/s/abc/exec";
  const denied = harness({ approve: false });
  denied.config = { sheets: { webhookUrl: url } };
  const unset = await run(["config", "unset", "sheets-webhook"], denied.deps);
  assert.equal(unset.exitCode, 3);
  assert.deepEqual(parse(unset.stdout), { ok: false, error: { code: "not_approved", message: "config change not approved" } });
  assert.deepEqual(denied.config, { sheets: { webhookUrl: url } });
  assert.deepEqual(denied.human.approvals[0], ["Stop mirroring the audit log to Google Sheets (unset sheets-webhook)?"]);

  const set = await run(["config", "set", "sheets-webhook", "https://script.google.com/macros/s/xyz/exec"], denied.deps);
  assert.equal(set.exitCode, 3);
  assert.deepEqual(denied.config, { sheets: { webhookUrl: url } });
  assert.deepEqual(denied.human.approvals[1], ["Mirror the audit log to https://script.google.com/macros/s/xyz/exec (set sheets-webhook)?"]);

  const approved = harness();
  const ok = await run(["config", "set", "sheets-webhook", url], approved.deps);
  assert.equal(ok.exitCode, 0, ok.stdout);
  assert.deepEqual(approved.config, { sheets: { webhookUrl: url } });
});

test("S4: the mirror refuses a webhook URL in config that zks would not accept", async () => {
  const path = join(tempDir(), "state", "audit.db");
  const store = openAuditStore(path);
  store.append(entry());
  const f = fakeFetch();
  const mirror = createSheetsMirror({
    fetch: f.fetch,
    keychain: fakeKeychain({ "zks/sheets-hmac": "k" }).keychain,
    readConfig: async () => ({ sheets: { webhookUrl: "https://evil.example/collect" } }),
    now: () => new Date("2026-11-04T12:00:00.000Z"),
  });
  assert.deepEqual(await mirror.sync(store), { configured: true, pushed: 0, pending: 1, error: "invalid sheets webhook URL in config" });
  assert.equal(f.calls.length, 0);
  store.close();
});

// 7. Redactor

test("S1: the Redactor also removes the base64url form", () => {
  const value = "????>>>>????";
  const b64 = Buffer.from(value).toString("base64");
  const b64url = Buffer.from(value).toString("base64url");
  assert.notEqual(b64url, b64.replace(/=+$/, ""));
  const r = new Redactor();
  r.register(SecretBuffer.fromString(value));
  assert.equal(r.scrub(`x ${b64url} y`), "x [REDACTED] y");
});

test("S1: a .env symlink pointing outside the project is refused", async () => {
  const { writeFileSync, symlinkSync } = await import("node:fs");
  const outside = tempDir();
  const project = tempDir();
  writeFileSync(join(outside, "credentials"), "K=outside-value\n");
  symlinkSync(join(outside, "credentials"), join(project, ".env"));
  writeFileSync(join(project, ".env.local"), "K=inside-value\n");
  const deps = { exec: fakeExec().exec, keychain: fakeKeychain().keychain, human: fakeHuman().human, cwd: project };
  await assert.rejects(
    resolveValue("K", { sensitive: true, targets: [], source: { kind: "dotenv", path: ".env" } }, deps),
    (e: Error & { code?: string }) => e.code === "source_invalid",
  );
  const ok = await resolveValue("K", { sensitive: true, targets: [], source: { kind: "dotenv", path: ".env.local" } }, deps);
  assert.equal(ok.reveal(), "inside-value");
});
