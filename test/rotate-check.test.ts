import assert from "node:assert/strict";
import { unlinkSync, utimesSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { HELP_TEXT } from "../src/help.ts";
import { run } from "../src/run.ts";
import { CANARY, GITHUB_KEY_ID, GITHUB_PUBLIC_KEY, auditBytes, ghTokenExec, harness, parse, type AwsCall, type FetchCall } from "./helpers.ts";

// S2 of odd/tasks/zks-v0.7.0.md — `zks rotate NAME --check`.

const WRITE = "2026-11-04T12:00:00.000Z";
const at = (offsetSeconds: number) => new Date(Date.parse(WRITE) + offsetSeconds * 1000);
/** A dotenv target file name, built so the literal never appears in this file. */
const VARS_FILE = "." + "env.local";

const targets = {
  v: { provider: "vercel", projectId: "prj_1", environments: ["production"] },
  gh: { provider: "github", repo: "acme/app" },
  ssm: { provider: "aws-ssm", region: "us-east-1", prefix: "/app/" },
  sm: { provider: "aws-sm", region: "us-east-1", prefix: "app/" },
  nl: { provider: "netlify", accountId: "acct1", context: "production" },
  de: { provider: "dotenv", path: VARS_FILE },
  co: { provider: "compose", dir: "compose-secrets" },
  rw: { provider: "railway", projectId: "proj-1", environmentId: "env-1" },
  sb: { provider: "supabase", projectRef: "abcdefghijklmnopqrst" },
  ds: { provider: "docker-swarm", host: "unix:///var/run/docker.sock" },
};

type TargetKey = keyof typeof targets;

function policyFor(tokenTargets: TargetKey[], extra: Record<string, unknown> = {}) {
  return {
    version: 1,
    project: "acme",
    targets,
    variables: { TOKEN: { sensitive: true, source: { kind: "generate" }, targets: tokenTargets }, ...extra },
  };
}

/** Provider-side state of the check phase: last-modified time per variable name, null when missing, "error" for HTTP 500. */
type Times = Record<string, Date | null | "error" | undefined>;

interface Fake {
  phase: "apply" | "check";
  times: Times;
  /** Netlify answers without updated_at when false. */
  netlifyTimestamp: boolean;
}

function fakeProviders(fake: Fake) {
  const fetch = (call: FetchCall): { status?: number; body?: unknown } => {
    const method = call.init.method ?? "GET";
    const url = new URL(call.url);
    if (fake.phase === "apply") {
      if (url.hostname === "api.github.com") {
        if (url.pathname.endsWith("/public-key")) return { body: { key_id: GITHUB_KEY_ID, key: GITHUB_PUBLIC_KEY } };
        return { status: method === "PUT" || method === "POST" ? 201 : 204 };
      }
      if (url.hostname === "api.netlify.com" && method === "GET") return { status: 404 };
      return {};
    }
    const name = decodeURIComponent(url.pathname.split("/").at(-1) ?? "");
    if (url.hostname === "api.vercel.com") {
      const envs = Object.entries(fake.times)
        .filter(([, t]) => t instanceof Date)
        .map(([key, t]) => ({ id: `env_${key}`, key, value: CANARY, type: "plain", target: ["production"], updatedAt: (t as Date).getTime() }));
      if (Object.values(fake.times).includes("error")) return { status: 500 };
      return { body: { envs } };
    }
    const time = fake.times[name];
    if (time === "error") return { status: 500 };
    if (time === null || time === undefined) return { status: 404, body: { message: "Not Found" } };
    if (url.hostname === "api.github.com") return { body: { name, value: CANARY, created_at: WRITE, updated_at: time.toISOString() } };
    if (url.hostname === "api.netlify.com") {
      return {
        body: {
          key: name,
          is_secret: true,
          values: [{ value: CANARY, context: "production" }],
          ...(fake.netlifyTimestamp ? { updated_at: time.toISOString() } : {}),
        },
      };
    }
    return {};
  };
  const aws = (call: AwsCall): unknown => {
    if (call.command === "PutParameterCommand") return { Version: 1 };
    if (call.command === "PutSecretValueCommand") return { VersionId: "v1" };
    if (call.command === "DescribeParametersCommand") {
      const filter = (call.input.ParameterFilters as Array<{ Values: string[] }>)[0]!;
      const time = fake.times[(filter.Values[0] ?? "").replace("/app/", "")];
      if (time === "error") throw Object.assign(new Error("boom"), { name: "AccessDeniedException" });
      return { Parameters: time instanceof Date ? [{ Name: filter.Values[0], LastModifiedDate: time }] : [] };
    }
    if (call.command === "DescribeSecretCommand") {
      const time = fake.times[String(call.input.SecretId).replace("app/", "")];
      if (time === "error") throw Object.assign(new Error("boom"), { name: "AccessDeniedException" });
      if (!(time instanceof Date)) throw Object.assign(new Error("gone"), { name: "ResourceNotFoundException" });
      return { Name: call.input.SecretId, LastChangedDate: time };
    }
    throw new Error(`unexpected AWS command ${call.command}`);
  };
  return { fetch, aws };
}

/** A harness whose providers accept writes, then answer --check from fake.times. */
function setup(policy: unknown, keychain: Record<string, string> = {}) {
  const fake: Fake = { phase: "apply", times: {}, netlifyTimestamp: true };
  const providers = fakeProviders(fake);
  const h = harness({
    policy,
    keychain: { "zks/vercel": CANARY, "zks/netlify": CANARY, ...keychain },
    fetch: providers.fetch,
    aws: providers.aws,
    exec: ghTokenExec,
  });
  return { h, fake };
}

async function applyAll(h: ReturnType<typeof harness>, fake: Fake, only?: string) {
  const out = await run(["apply", ...(only ? ["--only", only] : [])], h.deps);
  assert.equal(out.exitCode, 0, out.stdout);
  fake.phase = "check";
  h.fetch.calls.length = 0;
  h.aws.calls.length = 0;
  h.exec.calls.length = 0;
}

async function check(h: ReturnType<typeof harness>, name = "TOKEN", extra: string[] = []) {
  const out = await run(["rotate", name, "--check", ...extra], h.deps);
  return { out, body: parse(out.stdout) };
}

function only(body: Record<string, any>, target: string, variable = "TOKEN"): Record<string, any> {
  const found = (body.checks as Record<string, any>[]).find((c) => c.target === target && c.variable === variable);
  assert.ok(found, `no check for ${variable} on ${target}`);
  return found;
}

test("S2: vercel current, stale and missing from the env updatedAt; derived variables are checked too", async () => {
  const policy = policyFor(["v"], {
    DERIVED: { sensitive: true, source: { kind: "template", template: "x-${TOKEN}" }, targets: ["v"] },
    OTHER: { sensitive: true, source: { kind: "template", template: "y-${TOKEN}" }, targets: ["v"] },
  });
  const { h, fake } = setup(policy);
  await applyAll(h, fake);
  fake.times = { TOKEN: at(30), DERIVED: at(-3600) };

  const { out, body } = await check(h);
  assert.equal(out.exitCode, 1, out.stdout);
  assert.deepEqual(body, {
    ok: false,
    name: "TOKEN",
    checks: [
      {
        variable: "TOKEN",
        target: "v",
        provider: "vercel",
        destination: "vercel project prj_1 env production",
        status: "current",
        providerTime: at(30).toISOString(),
        lastWrite: WRITE,
      },
      {
        variable: "DERIVED",
        target: "v",
        provider: "vercel",
        destination: "vercel project prj_1 env production",
        status: "stale",
        providerTime: at(-3600).toISOString(),
        lastWrite: WRITE,
      },
      {
        variable: "OTHER",
        target: "v",
        provider: "vercel",
        destination: "vercel project prj_1 env production",
        status: "missing",
        lastWrite: WRITE,
      },
    ],
  });
  // Only list reads with the Keychain token; nothing is written.
  assert.ok(h.fetch.calls.length > 0);
  for (const call of h.fetch.calls) {
    assert.equal(call.init.method ?? "GET", "GET");
    assert.match(call.url, /^https:\/\/api\.vercel\.com\/v10\/projects\/prj_1\/env/);
  }
});

test("S2: every check current exits 0 with ok true", async () => {
  const { h, fake } = setup(policyFor(["v", "gh"]));
  await applyAll(h, fake);
  fake.times = { TOKEN: at(0) };
  const { out, body } = await check(h);
  assert.equal(out.exitCode, 0, out.stdout);
  assert.equal(body.ok, true);
  assert.deepEqual(
    body.checks.map((c: Record<string, any>) => [c.target, c.status]),
    [
      ["v", "current"],
      ["gh", "current"],
    ],
  );
});

test("S2: github reads secrets/{name} or variables/{name} updated_at; 404 is missing", async () => {
  const policy = policyFor(["gh"], { PLAIN: { sensitive: false, value: CANARY, targets: ["gh"] } });
  const { h, fake } = setup(policy);
  await applyAll(h, fake);
  fake.times = { TOKEN: at(-200) };

  const stale = await check(h);
  assert.equal(stale.out.exitCode, 1);
  assert.deepEqual(only(stale.body, "gh"), {
    variable: "TOKEN",
    target: "gh",
    provider: "github",
    destination: "github acme/app secret",
    status: "stale",
    providerTime: at(-200).toISOString(),
    lastWrite: WRITE,
  });
  assert.deepEqual(
    h.fetch.calls.map((c) => `${c.init.method ?? "GET"} ${c.url}`),
    ["GET https://api.github.com/repos/acme/app/actions/secrets/TOKEN"],
  );
  assert.equal(h.exec.calls.length, 1, "only `gh auth token` runs");

  // A non-generated variable (here a policy literal) is checked as well: variables/{name}.
  fake.times = { PLAIN: at(5) };
  h.fetch.calls.length = 0;
  const plain = await check(h, "PLAIN");
  assert.equal(plain.out.exitCode, 0, plain.out.stdout);
  assert.equal(only(plain.body, "gh", "PLAIN").status, "current");
  assert.deepEqual(
    h.fetch.calls.map((c) => c.url),
    ["https://api.github.com/repos/acme/app/actions/variables/PLAIN"],
  );

  fake.times = {};
  const missing = await check(h);
  assert.equal(missing.out.exitCode, 1);
  assert.deepEqual(only(missing.body, "gh"), {
    variable: "TOKEN",
    target: "gh",
    provider: "github",
    destination: "github acme/app secret",
    status: "missing",
    lastWrite: WRITE,
  });
});

test("S2: aws-ssm uses DescribeParameters with a Name filter (never GetParameter); none found is missing", async () => {
  const { h, fake } = setup(policyFor(["ssm"]));
  await applyAll(h, fake);
  fake.times = { TOKEN: at(-120) };
  const current = await check(h);
  assert.equal(current.out.exitCode, 0, current.out.stdout);
  assert.deepEqual(only(current.body, "ssm"), {
    variable: "TOKEN",
    target: "ssm",
    provider: "aws-ssm",
    destination: "aws-ssm us-east-1 /app/TOKEN",
    status: "current",
    providerTime: at(-120).toISOString(),
    lastWrite: WRITE,
  });
  assert.deepEqual(h.aws.calls, [
    {
      client: "ssm",
      command: "DescribeParametersCommand",
      input: { ParameterFilters: [{ Key: "Name", Option: "Equals", Values: ["/app/TOKEN"] }] },
    },
  ]);

  fake.times = {};
  const missing = await check(h);
  assert.equal(missing.out.exitCode, 1);
  assert.equal(only(missing.body, "ssm").status, "missing");
  assert.ok(h.aws.calls.every((c) => c.command === "DescribeParametersCommand"));
});

test("S2: aws-sm uses DescribeSecret LastChangedDate (never GetSecretValue); ResourceNotFound is missing", async () => {
  const { h, fake } = setup(policyFor(["sm"]));
  await applyAll(h, fake);
  fake.times = { TOKEN: at(-121) };
  const stale = await check(h);
  assert.equal(stale.out.exitCode, 1);
  assert.deepEqual(only(stale.body, "sm"), {
    variable: "TOKEN",
    target: "sm",
    provider: "aws-sm",
    destination: "aws-sm us-east-1 app/TOKEN",
    status: "stale",
    providerTime: at(-121).toISOString(),
    lastWrite: WRITE,
  });
  assert.deepEqual(h.aws.calls, [{ client: "sm", command: "DescribeSecretCommand", input: { SecretId: "app/TOKEN" } }]);

  fake.times = {};
  const missing = await check(h);
  assert.equal(only(missing.body, "sm").status, "missing");
});

test("S2: tolerance boundary — exactly 120 s before the audit write is current, 121 s is stale", async () => {
  const { h, fake } = setup(policyFor(["sm"]));
  await applyAll(h, fake);
  fake.times = { TOKEN: at(-120) };
  const edge = await check(h);
  assert.equal(edge.out.exitCode, 0, edge.out.stdout);
  assert.equal(only(edge.body, "sm").status, "current");
  fake.times = { TOKEN: at(-121) };
  const past = await check(h);
  assert.equal(past.out.exitCode, 1);
  assert.equal(only(past.body, "sm").status, "stale");
});

test("S2: netlify reads updated_at; without one the check is unknown with a reason", async () => {
  const { h, fake } = setup(policyFor(["nl"]));
  await applyAll(h, fake);
  fake.times = { TOKEN: at(60) };
  const current = await check(h);
  assert.equal(current.out.exitCode, 0, current.out.stdout);
  assert.deepEqual(only(current.body, "nl"), {
    variable: "TOKEN",
    target: "nl",
    provider: "netlify",
    destination: "netlify account acct1 context production",
    status: "current",
    providerTime: at(60).toISOString(),
    lastWrite: WRITE,
  });
  assert.deepEqual(
    h.fetch.calls.map((c) => `${c.init.method ?? "GET"} ${c.url}`),
    ["GET https://api.netlify.com/api/v1/accounts/acct1/env/TOKEN"],
  );

  fake.netlifyTimestamp = false;
  const unknown = await check(h);
  assert.equal(unknown.out.exitCode, 1);
  assert.deepEqual(only(unknown.body, "nl"), {
    variable: "TOKEN",
    target: "nl",
    provider: "netlify",
    destination: "netlify account acct1 context production",
    status: "unknown",
    lastWrite: WRITE,
    reason: "Netlify returned no updated_at for this variable",
  });

  fake.times = {};
  const missing = await check(h);
  assert.equal(only(missing.body, "nl").status, "missing");
});

test("S2: dotenv uses the file mtime when the key is defined; a missing key or file is missing", async () => {
  const { h, fake } = setup(policyFor(["de"]));
  await applyAll(h, fake);
  const file = join(h.dir, VARS_FILE);
  utimesSync(file, at(10), at(10));
  const current = await check(h);
  assert.equal(current.out.exitCode, 0, current.out.stdout);
  assert.deepEqual(only(current.body, "de"), {
    variable: "TOKEN",
    target: "de",
    provider: "dotenv",
    destination: `dotenv file ${file}`,
    status: "current",
    providerTime: at(10).toISOString(),
    lastWrite: WRITE,
  });

  utimesSync(file, at(-7200), at(-7200));
  const stale = await check(h);
  assert.equal(stale.out.exitCode, 1);
  assert.equal(only(stale.body, "de").status, "stale");

  // A key only inside another key's multi-line value is not a definition.
  writeFileSync(file, `OTHER="${CANARY}\nTOKEN=inside"\nTOKEN_2=${CANARY}\n`, { mode: 0o600 });
  const noKey = await check(h);
  assert.equal(noKey.out.exitCode, 1);
  assert.equal(only(noKey.body, "de").status, "missing");
  assert.ok(!noKey.out.stdout.includes(CANARY));

  unlinkSync(file);
  const gone = await check(h);
  assert.equal(gone.out.exitCode, 1);
  assert.equal(only(gone.body, "de").status, "missing");
});

test("S2: compose uses the secret file mtime; a missing file is missing", async () => {
  const { h, fake } = setup(policyFor(["co"]));
  await applyAll(h, fake);
  const file = join(h.dir, "compose-secrets", "TOKEN");
  utimesSync(file, at(0), at(0));
  const current = await check(h);
  assert.equal(current.out.exitCode, 0, current.out.stdout);
  assert.deepEqual(only(current.body, "co"), {
    variable: "TOKEN",
    target: "co",
    provider: "compose",
    destination: `compose file ${file}`,
    status: "current",
    providerTime: at(0).toISOString(),
    lastWrite: WRITE,
  });

  // The file disappears after the write: missing, not current.
  unlinkSync(file);
  const missing = await check(h);
  assert.equal(missing.out.exitCode, 1);
  assert.equal(only(missing.body, "co").status, "missing");
});

test("S2: railway, supabase and docker-swarm expose no timestamp: unknown with a reason, no provider call", async () => {
  const { h } = setup(policyFor(["rw", "sb", "ds"]), { "zks/railway": CANARY, "zks/supabase": CANARY });
  const { out, body } = await check(h);
  assert.equal(out.exitCode, 1);
  assert.deepEqual(
    body.checks.map((c: Record<string, any>) => [c.provider, c.status, c.reason]),
    [
      ["railway", "unknown", "railway exposes no last-modified time"],
      ["supabase", "unknown", "supabase exposes no last-modified time"],
      ["docker-swarm", "unknown", "docker-swarm exposes no last-modified time"],
    ],
  );
  assert.equal(h.fetch.calls.length, 0);
  assert.equal(h.exec.calls.length, 0);
});

test("S2: a destination found with no applied audit write is unknown with a reason", async () => {
  const { h, fake } = setup(policyFor(["sm"]));
  fake.phase = "check";
  fake.times = { TOKEN: at(0) };
  const { out, body } = await check(h);
  assert.equal(out.exitCode, 1);
  assert.deepEqual(only(body, "sm"), {
    variable: "TOKEN",
    target: "sm",
    provider: "aws-sm",
    destination: "aws-sm us-east-1 app/TOKEN",
    status: "unknown",
    providerTime: at(0).toISOString(),
    reason: "no applied zks write of this variable to this target in the audit log",
  });
});

test("S2: a failing provider call is unknown with its safe reason, never a value", async () => {
  const { h, fake } = setup(policyFor(["v", "ssm"]));
  await applyAll(h, fake);
  fake.times = { TOKEN: "error" };
  const { out, body } = await check(h);
  assert.equal(out.exitCode, 1);
  assert.deepEqual(only(body, "v"), {
    variable: "TOKEN",
    target: "v",
    provider: "vercel",
    destination: "vercel project prj_1 env production",
    status: "unknown",
    lastWrite: WRITE,
    reason: "Vercel http_500",
  });
  assert.equal(only(body, "ssm").status, "unknown");
  assert.equal(only(body, "ssm").reason, "AWS AccessDeniedException");
  assert.ok(!out.stdout.includes(CANARY));
});

test("S2: a missing provider token is unknown with the token hint", async () => {
  const { h, fake } = setup(policyFor(["v"]));
  await applyAll(h, fake);
  await h.deps.keychain.remove("zks", "vercel");
  const { out, body } = await check(h);
  assert.equal(out.exitCode, 1);
  assert.equal(only(body, "v").status, "unknown");
  assert.equal(only(body, "v").reason, "no vercel token in the Keychain; run `zks auth set vercel`");
});

test("S2: --check accepts a non-generated variable, opens no dialog, writes nothing and appends no audit record", async () => {
  const policy = policyFor(["v"], {
    API_KEY: { sensitive: true, source: { kind: "keychain", service: "app", account: "api" }, targets: ["v", "de"] },
  });
  const { h, fake } = setup(policy, { "app/api": CANARY });
  await applyAll(h, fake, "API_KEY");
  fake.times = { API_KEY: at(0) };
  utimesSync(join(h.dir, VARS_FILE), at(0), at(0));
  const approvals = h.human.approvals.length;
  const auditBefore = parse((await run(["audit", "list", "--limit", "1000"], h.deps)).stdout).records.length;
  const mirrorBefore = h.mirrorCalls;
  const keychainBefore = new Map(h.keychain.store);
  const trustBefore = JSON.stringify(h.trust);

  const { out, body } = await check(h, "API_KEY");
  assert.equal(out.exitCode, 0, out.stdout);
  assert.deepEqual(
    body.checks.map((c: Record<string, any>) => [c.variable, c.target, c.status]),
    [
      ["API_KEY", "v", "current"],
      ["API_KEY", "de", "current"],
    ],
  );
  assert.equal(h.human.approvals.length, approvals, "no dialog");
  assert.equal(h.human.prompts.length, 0);
  assert.equal(parse((await run(["audit", "list", "--limit", "1000"], h.deps)).stdout).records.length, auditBefore, "no audit append");
  assert.equal(h.mirrorCalls, mirrorBefore);
  assert.deepEqual(h.keychain.store, keychainBefore);
  assert.equal(JSON.stringify(h.trust), trustBefore);
  assert.ok(h.fetch.calls.every((c) => (c.init.method ?? "GET") === "GET" && c.body === ""), "only reads");
  assert.ok(!out.stdout.includes(CANARY));
});

test("S2: values never reach the output: provider tokens, stored values and file contents stay out", async () => {
  const policy = policyFor(["v", "gh", "nl", "de"], { PLAIN: { sensitive: false, value: CANARY, targets: ["gh", "v"] } });
  const { h, fake } = setup(policy);
  await applyAll(h, fake);
  fake.times = { TOKEN: at(-9999), PLAIN: at(0) };
  for (const name of ["TOKEN", "PLAIN"]) {
    const { out } = await check(h, name);
    assert.ok(!out.stdout.includes(CANARY), `${name}: stdout leaked a value or token`);
  }
  // The check itself appended nothing that could carry a value.
  assert.ok(!(await auditBytes(h.auditDb)).includes(CANARY));
});

test("S2: --check honours --target and refuses a target that is not one of NAME", async () => {
  const { h, fake } = setup(policyFor(["v", "sm"]));
  await applyAll(h, fake);
  fake.times = { TOKEN: at(0) };
  const { out, body } = await check(h, "TOKEN", ["--target", "sm"]);
  assert.equal(out.exitCode, 0, out.stdout);
  assert.deepEqual(body.checks.map((c: Record<string, any>) => c.target), ["sm"]);
  assert.equal(h.fetch.calls.length, 0);

  const foreign = await check(h, "TOKEN", ["--target", "gh"]);
  assert.equal(foreign.out.exitCode, 2);
  assert.deepEqual(foreign.body.error, { code: "usage", message: '--target: "gh" is not a target of TOKEN' });

  const unknownName = await run(["rotate", CANARY, "--check"], h.deps);
  assert.equal(unknownName.exitCode, 2);
  assert.ok(!unknownName.stdout.includes(CANARY));
  assert.deepEqual(parse((await run(["rotate", "TOKEN", "--check=yes"], h.deps)).stdout).error, {
    code: "usage",
    message: "option --check takes no value",
  });
  // Other commands refuse it like any option they do not use (same rule as --fix).
  const apply = await run(["apply", "--check"], h.deps);
  assert.equal(apply.exitCode, 2);
  assert.deepEqual(parse(apply.stdout).error, { code: "usage", message: "option --check is not valid for apply" });
});

test("S2 PRESERVE: rotate without --check still refuses a non-generated variable, audited failed", async () => {
  const policy = policyFor(["v"], {
    API_KEY: { sensitive: true, source: { kind: "keychain", service: "app", account: "api" }, targets: ["v"] },
  });
  const { h } = setup(policy, { "app/api": CANARY });
  const out = await run(["rotate", "API_KEY"], h.deps);
  assert.equal(out.exitCode, 2);
  assert.deepEqual(parse(out.stdout).error, {
    code: "not_rotatable",
    message: "API_KEY is not generated by zks; only variables with a generate source can be rotated",
  });
  const records = parse((await run(["audit", "list"], h.deps)).stdout).records;
  assert.deepEqual(
    records.map((r: Record<string, any>) => [r.action, r.result, r.errorCode]),
    [["rotate", "failed", "not_rotatable"]],
  );
});

test("S2: help documents rotate --check", () => {
  assert.match(HELP_TEXT, /zks rotate NAME --check \[--target t1,t2\] \[--policy FILE\]/);
});
