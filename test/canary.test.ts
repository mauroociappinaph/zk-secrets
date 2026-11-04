import assert from "node:assert/strict";
import { test } from "node:test";
import { openAuditStore } from "../src/audit/store.ts";
import { run } from "../src/run.ts";
import { CANARY, auditBytes, harness, parse } from "./helpers.ts";

const allTargetsPolicy = {
  version: 1,
  project: "hismia-web",
  targets: {
    "vercel-prod": { provider: "vercel", projectId: "prj_1", teamId: "team_1", environments: ["production", "preview"] },
    ssm: { provider: "aws-ssm", region: "sa-east-1", prefix: "/hismia/prod/", kmsKeyId: "alias/hismia" },
    sm: { provider: "aws-sm", region: "sa-east-1", prefix: "hismia/prod/" },
    gh: { provider: "github", repo: "acme/web", environment: "production" },
    railway: { provider: "railway", projectId: "p1", environmentId: "e1", serviceId: "s1" },
    supa: { provider: "supabase", projectRef: "abcdefghijklmnopqrst" },
  },
  variables: {
    STRIPE_SECRET_KEY: {
      sensitive: true,
      source: { kind: "keychain", service: "hismia", account: "stripe" },
      targets: ["vercel-prod", "ssm", "sm", "gh", "railway", "supa"],
    },
  },
};

const tokens = { "zks/vercel": "tok-vercel-1", "zks/railway": "tok-railway-1", "zks/supabase": "tok-supabase-1" };

test("S1: a sensitive value reaches every provider but never stdout, argv or the audit store", async () => {
  const h = harness({ policy: allTargetsPolicy, keychain: { ...tokens, "hismia/stripe": CANARY } });

  const out = await run(["apply"], h.deps);

  assert.equal(out.exitCode, 0, out.stdout);
  assert.ok(!out.stdout.includes(CANARY), "stdout leaked the value");
  const body = parse(out.stdout);
  assert.equal(body.ok, true);
  assert.deepEqual(
    body.results.map((r: { target: string; result: string }) => [r.target, r.result]),
    [["vercel-prod", "applied"], ["ssm", "applied"], ["sm", "applied"], ["gh", "applied"], ["railway", "applied"], ["supa", "applied"]],
  );

  // Delivered to each provider through body, stdin or SDK input only.
  assert.equal(h.fetch.calls.length, 3);
  for (const call of h.fetch.calls) {
    assert.ok(call.body.includes(CANARY));
    assert.ok(!call.url.includes(CANARY));
  }
  assert.equal(h.aws.calls.length, 2);
  for (const call of h.aws.calls) assert.ok(JSON.stringify(call.input).includes(CANARY));
  assert.equal(h.exec.calls.length, 1);
  assert.equal(h.exec.calls[0]?.input, CANARY);
  for (const call of h.exec.calls) assert.ok(!call.args.join(" ").includes(CANARY), "argv leaked the value");

  const bytes = await auditBytes(h.auditDb);
  assert.ok(bytes.length > 0);
  assert.ok(!bytes.includes(CANARY), "audit store leaked the value");
  assert.ok(!bytes.includes(Buffer.from(CANARY).toString("hex")));
});

test("S4: each write leaves one metadata-only audit record with project, name, actor and result", async () => {
  const h = harness({ policy: allTargetsPolicy, keychain: { ...tokens, "hismia/stripe": CANARY } });
  await run(["apply", "--target", "ssm", "--agent", "codex:42"], h.deps);

  const store = openAuditStore(h.auditDb);
  const records = store.list();
  assert.equal(store.verify().ok, true);
  store.close();
  assert.equal(records.length, 1);
  const { auditId, hash, prevHash, ...rest } = records[0]!;
  assert.match(auditId, /^[0-9A-Z]{26}$/);
  assert.match(hash, /^[0-9a-f]{64}$/);
  assert.equal(prevHash, "0".repeat(64));
  assert.deepEqual(rest, {
    ts: "2026-11-04T12:00:00.000Z",
    actorHuman: "tester",
    actorAgent: "codex:42",
    project: "hismia-web",
    provider: "aws-ssm",
    target: "ssm",
    environment: "",
    variableName: "STRIPE_SECRET_KEY",
    action: "set",
    sensitive: true,
    sourceKind: "keychain",
    result: "applied",
    providerVersion: "",
    errorCode: "",
    mirroredAt: "",
  });
});

test("S1: a provider error that echoes the value is scrubbed from the output", async () => {
  const h = harness({
    policy: allTargetsPolicy,
    keychain: { ...tokens, "hismia/stripe": CANARY },
    fetch: () => ({ status: 400, body: { error: { code: CANARY, message: `bad value ${CANARY}` } } }),
  });

  const out = await run(["apply", "--target", "vercel-prod"], h.deps);

  assert.equal(out.exitCode, 1);
  assert.ok(!out.stdout.includes(CANARY));
  const result = parse(out.stdout).results[0];
  assert.equal(result.result, "failed");
  assert.equal(result.error.code, "vercel_failed");
  assert.equal(result.error.message, "Vercel [REDACTED]");
  assert.ok(!(await auditBytes(h.auditDb)).includes(CANARY));
});

test("S5: denying the dialog writes nothing, audits denied and exits 3", async () => {
  const h = harness({ policy: allTargetsPolicy, keychain: { ...tokens, "hismia/stripe": CANARY }, approve: false });

  const out = await run(["apply"], h.deps);

  assert.equal(out.exitCode, 3);
  const body = parse(out.stdout);
  assert.equal(body.ok, false);
  assert.ok(body.results.every((r: { result: string }) => r.result === "denied"));
  assert.equal(h.fetch.calls.length, 0);
  assert.equal(h.aws.calls.length, 0);
  assert.equal(h.exec.calls.length, 0);
  assert.equal(h.human.approvals.length, 1);
  assert.ok(h.human.approvals[0]!.some((l) => l === "- STRIPE_SECRET_KEY -> vercel project prj_1 team team_1 env production+preview [secret; Keychain hismia/stripe] (target vercel-prod)"));
  const store = openAuditStore(h.auditDb);
  assert.deepEqual(store.list().map((r) => r.result), Array(6).fill("denied"));
  store.close();
});

test("S1: zks refuses secret values on the command line before touching anything", async () => {
  for (const flag of ["--value", "--secret=abc", "--token", "--password"]) {
    const h = harness({ policy: allTargetsPolicy });
    const out = await run(["apply", flag, "abc"], h.deps);
    assert.equal(out.exitCode, 2);
    assert.deepEqual(parse(out.stdout), {
      ok: false,
      error: {
        code: "usage",
        message: "zks never accepts secret values on the command line; declare a source in zks.policy.json or use `zks auth set`",
      },
    });
    assert.equal(h.human.approvals.length, 0);
    assert.equal(h.fetch.calls.length + h.exec.calls.length, 0);
  }
});

test("S2: a prompt source asks the human once per variable and reuses the value for every target", async () => {
  const policy = {
    ...allTargetsPolicy,
    variables: { API_KEY: { sensitive: true, source: { kind: "prompt" }, targets: ["ssm", "sm"] } },
  };
  const h = harness({ policy, prompt: CANARY });

  const out = await run(["apply"], h.deps);

  assert.equal(out.exitCode, 0, out.stdout);
  assert.deepEqual(h.human.prompts, ["Value for API_KEY"]);
  assert.equal(h.aws.calls.length, 2);
  assert.ok(!out.stdout.includes(CANARY));
});

test("S2: a cancelled prompt fails the variable without writing", async () => {
  const policy = { ...allTargetsPolicy, variables: { API_KEY: { sensitive: true, source: { kind: "prompt" }, targets: ["ssm"] } } };
  const h = harness({ policy, prompt: null });

  const out = await run(["apply"], h.deps);

  assert.equal(out.exitCode, 1);
  assert.equal(parse(out.stdout).results[0].error.code, "source_cancelled");
  assert.equal(h.aws.calls.length, 0);
});

test("S3: a non-sensitive env var with a literal value goes out as plain", async () => {
  const policy = {
    ...allTargetsPolicy,
    variables: { NEXT_PUBLIC_SITE_URL: { sensitive: false, value: "https://hismia.app", targets: ["vercel-prod", "gh", "ssm"] } },
  };
  const h = harness({ policy, keychain: tokens });

  const out = await run(["apply"], h.deps);

  assert.equal(out.exitCode, 0, out.stdout);
  assert.deepEqual(JSON.parse(h.fetch.calls[0]!.body), {
    key: "NEXT_PUBLIC_SITE_URL",
    value: "https://hismia.app",
    type: "plain",
    target: ["production", "preview"],
  });
  assert.deepEqual(h.exec.calls[0]?.args, ["variable", "set", "NEXT_PUBLIC_SITE_URL", "--repo", "acme/web", "--env", "production"]);
  assert.equal(h.aws.calls[0]?.input.Type, "String");
});

test("plan lists operations without network, dialogs or audit", async () => {
  const h = harness({ policy: allTargetsPolicy });

  const out = await run(["plan", "--only", "STRIPE_SECRET_KEY", "--target", "gh,supa"], h.deps);

  assert.equal(out.exitCode, 0);
  assert.deepEqual(parse(out.stdout), {
    ok: true,
    project: "hismia-web",
    operations: [
      {
        name: "STRIPE_SECRET_KEY",
        target: "gh",
        provider: "github",
        environment: "production",
        destination: "github acme/web env production secret",
        sensitive: true,
        source: "Keychain hismia/stripe",
      },
      {
        name: "STRIPE_SECRET_KEY",
        target: "supa",
        provider: "supabase",
        environment: "",
        destination: "supabase project abcdefghijklmnopqrst",
        sensitive: true,
        source: "Keychain hismia/stripe",
      },
    ],
  });
  assert.equal(h.human.approvals.length + h.fetch.calls.length + h.exec.calls.length, 0);
});

test("an invalid policy exits 2 with every issue and writes nothing", async () => {
  const policy = {
    version: 1,
    project: "x",
    targets: { v: { provider: "vercel", projectId: "p", environments: ["development"] } },
    variables: { TOKEN: { sensitive: true, value: "plaintext", targets: ["v", "nope"] } },
  };
  const h = harness({ policy });

  const out = await run(["apply"], h.deps);

  assert.equal(out.exitCode, 2);
  assert.deepEqual(parse(out.stdout).error.issues, [
    "variables.TOKEN.value: is not allowed when sensitive is true; use a source",
    "variables.TOKEN: Vercel sensitive variables cannot target development (target \"v\")",
    "variables.TOKEN.targets: unknown target \"nope\"",
  ]);
  assert.ok(!out.stdout.includes("plaintext"));
  assert.equal(h.human.approvals.length, 0);
});
