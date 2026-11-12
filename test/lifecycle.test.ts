import assert from "node:assert/strict";
import { test } from "node:test";
import { run } from "../src/run.ts";
import { CANARY, auditBytes, fakeHuman, harness, parse } from "./helpers.ts";

const tokens = { "zks/vercel": "tok-vercel-1" };
const targets = {
  v1: { provider: "vercel", projectId: "prj_1", environments: ["production"] },
  v2: { provider: "vercel", projectId: "prj_2", environments: ["production"] },
};
const variables = {
  DB_USER: { sensitive: false, value: "app", targets: ["v1"] },
  DB_PASSWORD: { sensitive: true, source: { kind: "generate", format: "password", length: 16 }, targets: ["v1", "v2"] },
  DATABASE_URL: { sensitive: true, source: { kind: "template", template: "postgres://${DB_USER}:${DB_PASSWORD:url}@db/app" }, targets: ["v1"] },
  SIGNING_KEY: { sensitive: true, source: { kind: "generate", format: "ed25519-private-key" }, targets: ["v1"] },
  SIGNING_PUB: { sensitive: false, source: { kind: "public-key", of: "SIGNING_KEY" }, targets: ["v2"] },
  API_KEY: { sensitive: true, source: { kind: "keychain", service: "app", account: "api" }, targets: ["v1"] },
  TYPED: { sensitive: true, source: { kind: "prompt" }, targets: ["v1"] },
};
const policy = { version: 1, project: "acme", targets, variables };

/** "<projectId>/<NAME>" of every Vercel write, in order. */
function writes(h: ReturnType<typeof harness>): string[] {
  return h.fetch.calls.map((call) => `${/\/projects\/([^/]+)\/env/.exec(call.url)?.[1]}/${(JSON.parse(call.body) as { key: string }).key}`);
}

async function auditList(h: ReturnType<typeof harness>): Promise<Record<string, any>[]> {
  return parse((await run(["audit", "list"], h.deps)).stdout).records as Record<string, any>[];
}

// S7 — zks rotate NAME

test("S7: rotate writes a new value to every target plus its dependents, with the dialog even when trusted", async () => {
  const h = harness({ policy, keychain: { ...tokens, "app/api": CANARY }, decision: "always" });
  assert.equal((await run(["apply", "--only", "DB_USER,DB_PASSWORD,DATABASE_URL"], h.deps)).exitCode, 0);
  const asked = h.human.approvals.length;
  // PRESERVE: apply to trusted destinations still needs no dialog.
  assert.equal((await run(["apply", "--only", "DB_USER,DB_PASSWORD,DATABASE_URL"], h.deps)).exitCode, 0);
  assert.equal(h.human.approvals.length, asked);
  h.fetch.calls.length = 0;
  h.deps.randomBytes = (n) => Buffer.alloc(n, 9);

  const out = await run(["rotate", "DB_PASSWORD"], h.deps);
  assert.equal(out.exitCode, 0, out.stdout);
  assert.equal(h.human.approvals.length, asked + 1, "rotate must always ask");
  assert.match(h.human.approvals.at(-1)![0]!, /^Rotate DB_PASSWORD: /);
  assert.deepEqual(writes(h).sort(), ["prj_1/DATABASE_URL", "prj_1/DB_PASSWORD", "prj_2/DB_PASSWORD"]);
  const body = parse(out.stdout);
  assert.equal(body.ok, true);
  assert.equal(body.rotated, "DB_PASSWORD");
  assert.equal(body.approval, "dialog");
  assert.deepEqual(body.dependents, ["DATABASE_URL"]);
  assert.equal(body.results.length, 3);
  const values = h.fetch.calls.map((c) => (JSON.parse(c.body) as { value: string }).value);
  const audit = await auditBytes(h.auditDb);
  for (const v of values) {
    assert.ok(!out.stdout.includes(v), "stdout leaked a rotated value");
    assert.ok(!audit.includes(v), "audit leaked a rotated value");
  }
  const records = (await auditList(h)).slice(0, 3);
  assert.ok(records.every((r) => r.action === "rotate" && r.result === "applied" && r.approval === "dialog"));
  assert.ok(!out.stdout.includes(CANARY));
});

test("S7: rotate --target writes only that subset", async () => {
  const h = harness({ policy, keychain: tokens });
  const out = await run(["rotate", "DB_PASSWORD", "--target", "v2"], h.deps);
  assert.equal(out.exitCode, 0, out.stdout);
  assert.deepEqual(writes(h), ["prj_2/DB_PASSWORD"]);
  assert.deepEqual(parse(out.stdout).dependents, []);
});

test("S7: rotating a private key rewrites its public key", async () => {
  const h = harness({ policy, keychain: tokens });
  const out = await run(["rotate", "SIGNING_KEY"], h.deps);
  assert.equal(out.exitCode, 0, out.stdout);
  assert.deepEqual(writes(h).sort(), ["prj_1/SIGNING_KEY", "prj_2/SIGNING_PUB"]);
});

test("S7: rotate --target that is not a target of NAME is refused", async () => {
  const h = harness({ policy, keychain: tokens });
  const out = await run(["rotate", "SIGNING_KEY", "--target", "v2"], h.deps);
  assert.equal(out.exitCode, 2);
  assert.deepEqual(parse(out.stdout).error, { code: "usage", message: '--target: "v2" is not a target of SIGNING_KEY' });
  assert.equal(h.fetch.calls.length, 0);
  assert.equal(h.human.approvals.length, 0);
});

for (const name of ["API_KEY", "TYPED", "DB_USER", "DATABASE_URL", "SIGNING_PUB"]) {
  test(`S7: ${name} has no generate source: not_rotatable, nothing written, audited failed`, async () => {
    const h = harness({ policy, keychain: { ...tokens, "app/api": CANARY }, prompt: CANARY });
    const out = await run(["rotate", name], h.deps);
    assert.equal(out.exitCode, 2, out.stdout);
    const body = parse(out.stdout);
    assert.equal(body.ok, false);
    assert.equal(body.error.code, "not_rotatable");
    assert.equal(body.error.message, `${name} is not generated by zks; only variables with a generate source can be rotated`);
    assert.equal(h.fetch.calls.length, 0);
    assert.equal(h.human.approvals.length, 0);
    assert.equal(h.human.prompts.length, 0);
    const records = await auditList(h);
    const expected = (variables as Record<string, { targets: string[] }>)[name]!.targets.length;
    assert.equal(records.length, expected);
    assert.ok(records.every((r) => r.action === "rotate" && r.result === "failed" && r.errorCode === "not_rotatable" && r.variableName === name));
    assert.ok(!out.stdout.includes(CANARY));
  });
}

test("S7: a dependent that also uses another generated value is not_rotatable", async () => {
  const h = harness({
    policy: {
      ...policy,
      variables: {
        A: { sensitive: true, source: { kind: "generate" }, targets: ["v1"] },
        B: { sensitive: true, source: { kind: "generate" }, targets: ["v1"] },
        AB: { sensitive: true, source: { kind: "template", template: "${A}${B}" }, targets: ["v1"] },
      },
    },
    keychain: tokens,
  });
  const out = await run(["rotate", "A"], h.deps);
  assert.equal(out.exitCode, 2, out.stdout);
  assert.deepEqual(parse(out.stdout).error, {
    code: "not_rotatable",
    message: "AB also uses B, another generated value; rotating A alone would replace it too",
  });
  assert.equal(h.fetch.calls.length, 0);
  assert.equal(h.human.approvals.length, 0);
});

test("S7: denying the rotation writes nothing and is audited denied", async () => {
  const h = harness({ policy, keychain: tokens, approve: false });
  const out = await run(["rotate", "DB_PASSWORD"], h.deps);
  assert.equal(out.exitCode, 3, out.stdout);
  assert.equal(h.human.approvals.length, 1);
  assert.equal(h.fetch.calls.length, 0);
  const records = await auditList(h);
  assert.equal(records.length, 3);
  assert.ok(records.every((r) => r.action === "rotate" && r.result === "denied" && r.errorCode === "not_approved"));
});

test("S7: rotate needs a known NAME and never echoes an unknown one", async () => {
  const h = harness({ policy, keychain: tokens });
  const missing = await run(["rotate"], h.deps);
  assert.equal(missing.exitCode, 2);
  assert.deepEqual(parse(missing.stdout).error, { code: "usage", message: "usage: zks rotate NAME [--target t1,t2] [--policy FILE]" });
  const unknown = await run(["rotate", CANARY], h.deps);
  assert.equal(unknown.exitCode, 2);
  assert.deepEqual(parse(unknown.stdout).error, { code: "usage", message: "not a variable of the policy; see `zks plan`" });
  assert.ok(!unknown.stdout.includes(CANARY));
  assert.equal((await run(["rotate", "DB_PASSWORD", "extra"], h.deps)).exitCode, 2);
  assert.equal((await run(["rotate", "DB_PASSWORD", "--only", "X"], h.deps)).exitCode, 2);
  assert.equal(h.fetch.calls.length, 0);
});

// S8 — zks inventory

test("S8: inventory lists each secret per destination with age and write count, metadata only", async () => {
  const inv = {
    version: 1,
    project: "acme",
    targets,
    variables: {
      A: { sensitive: true, source: { kind: "keychain", service: "app", account: "api" }, targets: ["v1"] },
      B: { sensitive: false, value: "plain", targets: ["v1"] },
      G: { sensitive: true, source: { kind: "generate" }, targets: ["v2"] },
    },
  };
  const old = { ...inv, variables: { ...inv.variables, A: { ...inv.variables.A, targets: ["v1", "v2"] }, OLD: { sensitive: false, value: "x", targets: ["v1"] } } };
  const other = { ...inv, project: "other" };
  const h = harness({ policy: inv, files: { "old.json": JSON.stringify(old), "other.json": JSON.stringify(other) }, keychain: { ...tokens, "app/api": CANARY } });
  const at = (iso: string) => {
    h.deps.now = () => new Date(iso);
  };
  at("2026-11-01T08:00:00.000Z");
  assert.equal((await run(["apply", "--policy", "old.json", "--only", "A,OLD"], h.deps)).exitCode, 0);
  at("2026-11-03T09:30:00.000Z");
  assert.equal((await run(["apply", "--only", "A"], h.deps)).exitCode, 0);
  assert.equal((await run(["rotate", "G"], h.deps)).exitCode, 0);
  assert.equal((await run(["apply", "--policy", "other.json", "--only", "B"], h.deps)).exitCode, 0);
  // Denied and failed writes are not writes.
  const { human } = fakeHuman({ approve: false });
  const approving = h.deps.human;
  h.deps.human = human;
  assert.equal((await run(["apply", "--only", "B"], h.deps)).exitCode, 3);
  h.deps.human = approving;
  at("2026-11-13T12:00:00.000Z");
  const calls = h.fetch.calls.length;

  const out = await run(["inventory"], h.deps);
  assert.equal(out.exitCode, 0, out.stdout);
  assert.equal(h.fetch.calls.length, calls, "inventory must not touch the network");
  assert.ok(!out.stdout.includes(CANARY));
  assert.deepEqual(parse(out.stdout), {
    ok: true,
    project: "acme",
    policy: `${h.dir}/zks.policy.json`,
    entries: [
      { variable: "A", provider: "vercel", target: "v1", environment: "production", lastWrittenAt: "2026-11-03T09:30:00.000Z", ageDays: 10, writes: 2, status: "written" },
      { variable: "A", provider: "vercel", target: "v2", environment: "production", lastWrittenAt: "2026-11-01T08:00:00.000Z", ageDays: 12, writes: 1, status: "not_in_policy" },
      { variable: "B", provider: "vercel", target: "v1", environment: "production", lastWrittenAt: null, ageDays: null, writes: 0, status: "never_written" },
      { variable: "G", provider: "vercel", target: "v2", environment: "production", lastWrittenAt: "2026-11-03T09:30:00.000Z", ageDays: 10, writes: 1, status: "written" },
      { variable: "OLD", provider: "vercel", target: "v1", environment: "production", lastWrittenAt: "2026-11-01T08:00:00.000Z", ageDays: 12, writes: 1, status: "not_in_policy" },
    ],
  });

  const others = parse((await run(["inventory", "--project", "other"], h.deps)).stdout);
  assert.deepEqual(others, {
    ok: true,
    project: "other",
    policy: null,
    entries: [{ variable: "B", provider: "vercel", target: "v1", environment: "production", lastWrittenAt: "2026-11-03T09:30:00.000Z", ageDays: 10, writes: 1, status: "written" }],
  });
  const viaPolicy = parse((await run(["inventory", "--policy", "other.json"], h.deps)).stdout);
  assert.equal(viaPolicy.project, "other");
  assert.equal(viaPolicy.entries.length, 3);
  assert.deepEqual(viaPolicy.entries.map((e: Record<string, unknown>) => `${e.variable}/${e.status}`), ["A/never_written", "B/written", "G/never_written"]);
});

test("S8: inventory without a readable policy or --project is invalid_policy; unknown options are refused", async () => {
  const h = harness();
  const out = await run(["inventory"], h.deps);
  assert.equal(out.exitCode, 2);
  assert.equal(parse(out.stdout).error.code, "invalid_policy");
  const missing = await run(["inventory", "--policy", "nope.json", "--project", "acme"], h.deps);
  assert.equal(parse(missing.stdout).error.code, "invalid_policy");
  const empty = parse((await run(["inventory", "--project", "acme"], h.deps)).stdout);
  assert.deepEqual(empty, { ok: true, project: "acme", policy: null, entries: [] });
  assert.equal((await run(["inventory", "--only", "A"], h.deps)).exitCode, 2);
  assert.equal((await run(["inventory", "extra"], h.deps)).exitCode, 2);
});

// S9 — plan with effects

test("S9: every plan operation carries its effect, summarised by effect; no network", async () => {
  const h = harness({
    policy: {
      version: 1,
      project: "acme",
      targets: {
        vp: { provider: "vercel", projectId: "prj_1", environments: ["production"] },
        rw: { provider: "railway", projectId: "p-1", environmentId: "e-1" },
        rs: { provider: "railway", projectId: "p-1", environmentId: "e-2", skipDeploys: true },
        gh: { provider: "github", repo: "acme/app" },
        ssm: { provider: "aws-ssm", region: "us-east-1", prefix: "/acme/" },
        sm: { provider: "aws-sm", region: "us-east-1", prefix: "acme/" },
        sb: { provider: "supabase", projectRef: "abcdefghijklmnopqrst" },
      },
      variables: {
        K: { sensitive: true, source: { kind: "generate" }, targets: ["vp", "rw", "rs", "gh", "ssm", "sm", "sb"] },
        P: { sensitive: false, value: "x", targets: ["vp"] },
      },
    },
  });
  const out = await run(["plan"], h.deps);
  assert.equal(out.exitCode, 0, out.stdout);
  assert.equal(h.fetch.calls.length + h.exec.calls.length + h.aws.calls.length, 0);
  const body = parse(out.stdout);
  assert.deepEqual(
    body.operations.map((op: Record<string, unknown>) => `${op.name}/${op.target}: ${op.effect}`),
    [
      "K/vp: applies on the next deployment; redeploy to use it now",
      "K/rw: Railway redeploys the service",
      "K/rs: applies on the next Railway deploy (skipDeploys)",
      "K/gh: used by the next workflow run",
      "K/ssm: consumers read it on their next fetch",
      "K/sm: consumers read it on their next fetch",
      "K/sb: Edge Functions use it on their next invocation",
      "P/vp: applies on the next deployment; redeploy to use it now",
    ],
  );
  assert.deepEqual(body.effects, [
    { effect: "applies on the next deployment; redeploy to use it now", operations: 2, targets: ["vp"] },
    { effect: "Railway redeploys the service", operations: 1, targets: ["rw"] },
    { effect: "applies on the next Railway deploy (skipDeploys)", operations: 1, targets: ["rs"] },
    { effect: "used by the next workflow run", operations: 1, targets: ["gh"] },
    { effect: "consumers read it on their next fetch", operations: 2, targets: ["ssm", "sm"] },
    { effect: "Edge Functions use it on their next invocation", operations: 1, targets: ["sb"] },
  ]);
  // PRESERVE: the existing fields stay as they were.
  assert.deepEqual(Object.keys(body), ["ok", "project", "operations", "effects"]);
  assert.deepEqual(Object.keys(body.operations[7]), ["name", "target", "provider", "environment", "destination", "sensitive", "source", "effect"]);
  assert.deepEqual({ ...body.operations[7], effect: undefined }, {
    name: "P",
    target: "vp",
    provider: "vercel",
    environment: "production",
    destination: "vercel project prj_1 env production",
    sensitive: false,
    source: "literal",
    effect: undefined,
  });
  const narrowed = parse((await run(["plan", "--target", "gh"], h.deps)).stdout);
  assert.deepEqual(narrowed.effects, [{ effect: "used by the next workflow run", operations: 1, targets: ["gh"] }]);
});
