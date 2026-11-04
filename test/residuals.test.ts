import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { test } from "node:test";
import { run } from "../src/run.ts";
import { resolveValue } from "../src/sources/resolve.ts";
import { fakeExec, fakeHuman, fakeKeychain, harness, parse } from "./helpers.ts";

const base = (targets: Record<string, unknown>, variables: Record<string, unknown>) => ({ version: 1, project: "p", targets, variables });
const gh = { gh: { provider: "github", repo: "acme/web" } };
const prompt = (targetKeys: string[]) => ({ sensitive: true, source: { kind: "prompt" }, targets: targetKeys });

async function issuesOf(policy: unknown): Promise<string[]> {
  const out = await run(["validate"], harness({ policy }).deps);
  assert.equal(out.exitCode, 2, out.stdout);
  return parse(out.stdout).error.issues as string[];
}

async function validates(policy: unknown): Promise<void> {
  const out = await run(["validate"], harness({ policy }).deps);
  assert.equal(out.exitCode, 0, out.stdout);
}

// 3. Dialog length

test("S5: github repo is at most 100 characters", async () => {
  const repo100 = `acme/${"r".repeat(95)}`;
  await validates(base({ g: { provider: "github", repo: repo100 } }, {}));
  const issues = await issuesOf(base({ g: { provider: "github", repo: `${repo100}x` } }, {}));
  assert.equal(issues.length, 1);
  assert.match(issues[0]!, /^targets\.g\.repo: must match /);
});

test("S5: op refs, dotenv paths and AWS prefixes are at most 200 characters", async () => {
  const ref200 = `op://v/i/${"f".repeat(191)}`;
  assert.equal(ref200.length, 200);
  await validates(base(gh, { O: { sensitive: true, source: { kind: "op", ref: ref200 }, targets: ["gh"] } }));
  assert.deepEqual(await issuesOf(base(gh, { O: { sensitive: true, source: { kind: "op", ref: `${ref200}f` }, targets: ["gh"] } })), [
    "variables.O.source.ref: must be an op:// reference",
  ]);

  const path200 = `${"d".repeat(195)}/.env`;
  assert.equal(path200.length, 200);
  await validates(base(gh, { D: { sensitive: true, source: { kind: "dotenv", path: path200 }, targets: ["gh"] } }));
  assert.deepEqual(await issuesOf(base(gh, { D: { sensitive: true, source: { kind: "dotenv", path: `d${path200}` }, targets: ["gh"] } })), [
    "variables.D.source.path: must be a relative .env* file inside the project",
  ]);

  const ssm200 = `/${"s".repeat(198)}/`;
  const sm200 = `${"s".repeat(199)}/`;
  await validates(base({ a: { provider: "aws-ssm", region: "us-east-1", prefix: ssm200 }, b: { provider: "aws-sm", region: "us-east-1", prefix: sm200 } }, {}));
  const issues = await issuesOf(
    base({ a: { provider: "aws-ssm", region: "us-east-1", prefix: `/x${ssm200}` }, b: { provider: "aws-sm", region: "us-east-1", prefix: `x${sm200}` } }, {}),
  );
  assert.equal(issues.length, 2);
  assert.match(issues[0]!, /^targets\.a\.prefix: must match /);
  assert.match(issues[1]!, /^targets\.b\.prefix: must match /);
});

const tooLong = {
  ok: false,
  error: { code: "dialog_too_long", message: "the approval text is too long for one dialog; narrow with --only or --target" },
};

test("S5: apply refuses a dialog line over 300 characters before any dialog or audit", async () => {
  const name = `V_${"N".repeat(120)}`;
  const policy = base({ t: { provider: "aws-ssm", region: "sa-east-1", prefix: `/${"a".repeat(150)}/` } }, { [name]: prompt(["t"]) });
  const h = harness({ policy });

  const out = await run(["apply"], h.deps);

  assert.equal(out.exitCode, 2, out.stdout);
  assert.deepEqual(parse(out.stdout), tooLong);
  assert.equal(h.human.approvals.length + h.human.prompts.length, 0);
  assert.equal(existsSync(h.auditDb), false);
  assert.equal(h.aws.calls.length, 0);
});

test("S5: apply refuses a dialog over 6000 characters even when every line fits", async () => {
  const names = Array.from({ length: 20 }, (_, i) => `V${String(i).padStart(2, "0")}_${"N".repeat(96)}`);
  const targets = { t: { provider: "aws-ssm", region: "sa-east-1", prefix: "/a/b/" } };

  const one = harness({ policy: base(targets, { [names[0]!]: prompt(["t"]) }), approve: false });
  assert.equal((await run(["apply"], one.deps)).exitCode, 3);
  const lines = one.human.approvals[0]!;
  const writeLine = lines.find((l) => l.startsWith("- "))!;
  assert.ok(writeLine.length <= 300 && writeLine.length >= 290, String(writeLine.length));
  assert.ok(lines.join("\n").length - writeLine.length + 20 * (writeLine.length + 1) > 6000, "fixture must exceed 6000 characters");

  const variables = Object.fromEntries(names.map((n) => [n, prompt(["t"])]));
  const h = harness({ policy: base(targets, variables) });
  const out = await run(["apply"], h.deps);

  assert.equal(out.exitCode, 2, out.stdout);
  assert.deepEqual(parse(out.stdout), tooLong);
  assert.equal(h.human.approvals.length, 0);
  assert.equal(existsSync(h.auditDb), false);
});

// 4. dotenv absolute path, realpath read

test("S5: plan and the approval dialog show the absolute dotenv path resolved against cwd", async () => {
  const policy = base(gh, { D: { sensitive: true, source: { kind: "dotenv", path: "Users/x/.env", key: "K" }, targets: ["gh"] } });
  const h = harness({ approve: false });
  h.deps.cwd = "/";
  h.files.set("/zks.policy.json", JSON.stringify(policy));

  const plan = await run(["plan"], h.deps);
  assert.equal(plan.exitCode, 0, plan.stdout);
  assert.equal(parse(plan.stdout).operations[0].source, "dotenv /Users/x/.env#K");

  const out = await run(["apply"], h.deps);
  assert.equal(out.exitCode, 3, out.stdout);
  assert.ok(
    h.human.approvals[0]!.includes("- D -> github acme/web secret [secret; dotenv /Users/x/.env#K] (target gh) [NEW destination]"),
    h.human.approvals[0]!.join("\n"),
  );
});

test("S1: dotenv reads the real path it checked, not the path it was given", async () => {
  const reads: string[] = [];
  const deps = {
    exec: fakeExec().exec,
    keychain: fakeKeychain().keychain,
    human: fakeHuman().human,
    cwd: "/w/project",
    realpath: async (path: string) => (path === "/w/project/.env" ? "/w/project/real/.env" : path),
    readFile: async (path: string) => {
      reads.push(path);
      return Buffer.from("K=inside\n");
    },
  };
  const value = await resolveValue("K", { sensitive: true, targets: [], source: { kind: "dotenv", path: ".env" } }, deps);
  assert.equal(value.reveal(), "inside");
  assert.deepEqual(reads, ["/w/project/real/.env"]);
});

// 5. Reserved Keychain service, any case

test("S1: the reserved Keychain service check ignores case", async () => {
  for (const service of ["ZKS", "Zks", "zKs"]) {
    const issues = await issuesOf(base(gh, { T: { sensitive: true, source: { kind: "keychain", service, account: "vercel" }, targets: ["gh"] } }));
    assert.deepEqual(issues, ['variables.T.source.service: "zks" is reserved for zks provider tokens'], service);
  }
  await validates(base(gh, { T: { sensitive: true, source: { kind: "keychain", service: "zksx", account: "a" }, targets: ["gh"] } }));
});

// 6. Flags a command does not use

test("each command refuses the flags it does not use", async () => {
  const h = harness({ policy: base(gh, { A: prompt(["gh"]) }) });
  const cases: Array<[string[], string]> = [
    [["validate", "--limit", "5"], "option --limit is not valid for validate"],
    [["plan", "--agent", "x"], "option --agent is not valid for plan"],
    [["validate", "--only", "A"], "option --only is not valid for validate"],
    [["init", "--target", "gh"], "option --target is not valid for init"],
    [["apply", "--limit", "5"], "option --limit is not valid for apply"],
    [["doctor", "--policy", "x.json"], "option --policy is not valid for doctor"],
    [["auth", "status", "--project", "p"], "option --project is not valid for auth status"],
    [["audit", "verify", "--limit", "5"], "option --limit is not valid for audit verify"],
    [["audit", "sync", "--project", "p"], "option --project is not valid for audit sync"],
    [["config", "show", "--policy", "x.json"], "option --policy is not valid for config show"],
    [["trust", "list", "--limit", "5"], "option --limit is not valid for trust list"],
  ];
  for (const [argv, message] of cases) {
    const out = await run(argv, h.deps);
    assert.equal(out.exitCode, 2, argv.join(" "));
    assert.deepEqual(parse(out.stdout), { ok: false, error: { code: "usage", message } }, argv.join(" "));
  }
  assert.equal(h.human.approvals.length + h.human.prompts.length + h.fetch.calls.length, 0);
});

test("commands keep accepting the flags they use", async () => {
  const h = harness({ policy: base(gh, { A: prompt(["gh"]) }), approve: false });
  assert.equal((await run(["validate", "--policy", "zks.policy.json"], h.deps)).exitCode, 0);
  assert.equal((await run(["plan", "--policy", "zks.policy.json", "--only", "A", "--target", "gh"], h.deps)).exitCode, 0);
  assert.equal((await run(["apply", "--policy", "zks.policy.json", "--only", "A", "--target", "gh", "--agent", "codex"], h.deps)).exitCode, 3);
  assert.equal((await run(["audit", "list", "--limit", "5", "--project", "p"], h.deps)).exitCode, 0);
  assert.equal((await run(["init", "--policy", "other.json", "--project", "p"], h.deps)).exitCode, 0);
  assert.equal((await run(["doctor", "--help"], h.deps)).exitCode, 0);
  assert.equal((await run(["validate", "--version"], h.deps)).exitCode, 0);
});

// 7. Reserved variable names

test("prototype-like variable names are reserved in any case", async () => {
  const variables: Record<string, unknown> = {};
  for (const name of ["__proto__", "constructor", "PROTOTYPE", "Constructor"]) {
    Object.defineProperty(variables, name, { value: prompt(["gh"]), enumerable: true, writable: true, configurable: true });
  }
  const issues = await issuesOf(base(gh, variables));
  assert.deepEqual(issues, [
    "variables.__proto__: name is reserved",
    "variables.constructor: name is reserved",
    "variables.PROTOTYPE: name is reserved",
    "variables.Constructor: name is reserved",
  ]);
});
