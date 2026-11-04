import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { test } from "node:test";
import { openAuditStore } from "../src/audit/store.ts";
import { createMacDialogs } from "../src/gate/dialog.ts";
import { describeTrustKey, trustKeyOf } from "../src/policy/trust.ts";
import type { Operation, TargetConfig } from "../src/policy/types.ts";
import { run } from "../src/run.ts";
import { CANARY, fakeExec, harness, parse, type TestHarness } from "./helpers.ts";

const targets = {
  gh: { provider: "github", repo: "acme/web", environment: "production" },
  gh2: { provider: "github", repo: "ACME/api" },
  ssm: { provider: "aws-ssm", region: "sa-east-1", prefix: "/app/", profile: "prod", roleArn: "arn:aws:iam::123456789012:role/w" },
  supa: { provider: "supabase", projectRef: "abcdefghijklmnopqrst" },
};
const policy = {
  version: 1,
  project: "web",
  targets,
  variables: { STRIPE: { sensitive: true, source: { kind: "keychain", service: "app", account: "stripe" }, targets: ["gh", "gh2", "ssm", "supa"] } },
};
const keychain = { "app/stripe": CANARY, "zks/supabase": "tok-supabase" };

function op(target: TargetConfig): Operation {
  return { name: "A", targetKey: "t", target, variable: { sensitive: true, targets: ["t"], source: { kind: "prompt" } }, sourceKind: "prompt" };
}

const GH_KEY = "github:acme";
const SSM_KEY = "aws:prod:arn:aws:iam::123456789012:role/w:sa-east-1";
const SUPA_KEY = "supabase:abcdefghijklmnopqrst";

function records(h: TestHarness) {
  const store = openAuditStore(h.auditDb);
  try {
    return store.list({ limit: 1000 }).reverse();
  } finally {
    store.close();
  }
}

test("S10: trustKeyOf names the destination each provider trusts", () => {
  assert.equal(trustKeyOf(op({ provider: "github", repo: "Acme/Web" })), "github:acme");
  assert.equal(trustKeyOf(op({ provider: "github", repo: "acme/other", environment: "prod" })), "github:acme");
  assert.equal(trustKeyOf(op({ provider: "vercel", projectId: "p", teamId: "team_1", environments: ["preview"] })), "vercel:team:team_1");
  assert.equal(trustKeyOf(op({ provider: "vercel", projectId: "p", environments: ["preview"] })), "vercel:personal");
  // A team whose id is "personal" is not the personal account.
  assert.equal(trustKeyOf(op({ provider: "vercel", projectId: "p", teamId: "personal", environments: ["preview"] })), "vercel:team:personal");
  assert.equal(trustKeyOf(op({ provider: "aws-ssm", region: "us-east-1", prefix: "/a/" })), "aws:default:no-role:us-east-1");
  assert.equal(
    trustKeyOf(op({ provider: "aws-sm", region: "sa-east-1", prefix: "a/", profile: "prod", roleArn: "arn:aws:iam::123456789012:role/w" })),
    SSM_KEY,
  );
  assert.equal(trustKeyOf(op({ provider: "railway", projectId: "p1", environmentId: "e1" })), "railway:p1");
  assert.equal(trustKeyOf(op({ provider: "supabase", projectRef: "abcdefghijklmnopqrst" })), SUPA_KEY);
});

test("S10: describeTrustKey explains the scope of each key", () => {
  assert.equal(describeTrustKey("github:acme"), "GitHub owner acme (every repository)");
  assert.equal(describeTrustKey("vercel:team:team_1"), "Vercel team team_1");
  assert.equal(describeTrustKey("vercel:team:personal"), "Vercel team personal");
  assert.equal(describeTrustKey("vercel:personal"), "Vercel personal account");
  assert.equal(describeTrustKey("vercel:team_1"), "old Vercel key format; it no longer matches any write (remove it)");
  assert.equal(describeTrustKey("vercel:team:"), "unknown destination");
  assert.equal(describeTrustKey(SSM_KEY), "AWS profile prod, role arn:aws:iam::123456789012:role/w, region sa-east-1 (SSM and Secrets Manager)");
  assert.equal(describeTrustKey("aws:default:no-role:us-east-1"), "AWS profile default, no role, region us-east-1 (SSM and Secrets Manager)");
  assert.equal(describeTrustKey("railway:p1"), "Railway project p1");
  assert.equal(describeTrustKey(SUPA_KEY), "Supabase project abcdefghijklmnopqrst");
  assert.equal(describeTrustKey("nope"), "unknown destination");
});

test("S10: Always allow persists the new destinations and the next apply opens no dialog", async () => {
  const h = harness({ policy, keychain, decision: "always" });

  const first = await run(["apply", "--agent", "codex:1"], h.deps);

  assert.equal(first.exitCode, 0, first.stdout);
  assert.equal(h.human.approvals.length, 1);
  const body = parse(first.stdout);
  assert.equal(body.approval, "dialog");
  assert.deepEqual(body.trusted, [GH_KEY, SSM_KEY, SUPA_KEY]);
  assert.deepEqual(
    h.trust!.destinations,
    [GH_KEY, SSM_KEY, SUPA_KEY].map((key) => ({ key, addedAt: "2026-11-04T12:00:00.000Z", addedBy: "codex:1" })),
  );
  const hmacKey = h.keychain.store.get("zks/trust-hmac")!;
  assert.match(hmacKey, /^[0-9a-f]{64}$/);
  const canonical = JSON.stringify({
    destinations: h.trust!.destinations.map((d) => ({ addedAt: d.addedAt, addedBy: d.addedBy, key: d.key })),
    version: 1,
  });
  assert.equal(h.trust!.mac, createHmac("sha256", hmacKey).update(canonical).digest("hex"));
  assert.ok(!JSON.stringify(h.trust).includes(CANARY));

  const second = await run(["apply"], h.deps);

  assert.equal(second.exitCode, 0, second.stdout);
  assert.equal(h.human.approvals.length, 1, "no second dialog");
  assert.equal(parse(second.stdout).approval, "trusted");
  assert.equal(parse(second.stdout).trust, undefined);
  const all = records(h);
  assert.deepEqual(all.map((r) => [r.result, r.approval]), [...Array(4).fill(["applied", "dialog"]), ...Array(4).fill(["applied", "trusted"])]);
  const store = openAuditStore(h.auditDb);
  assert.equal(store.verify().ok, true);
  store.close();
});

test("S10: a mixed apply shows every write and marks only the new destinations", async () => {
  const h = harness({ policy, keychain, decision: "always" });
  assert.equal((await run(["apply", "--target", "gh"], h.deps)).exitCode, 0);
  h.human.approvals.length = 0;

  const out = await run(["apply", "--target", "gh,gh2,ssm"], h.deps);

  assert.equal(out.exitCode, 0, out.stdout);
  assert.deepEqual(h.human.approvals[0], [
    "Project: web",
    "Write 3 value(s):",
    "",
    "- STRIPE -> github acme/web env production secret [secret; Keychain app/stripe] (target gh)",
    "- STRIPE -> github ACME/api secret [secret; Keychain app/stripe] (target gh2)",
    "- STRIPE -> aws-ssm sa-east-1 /app/STRIPE role arn:aws:iam::123456789012:role/w profile prod [secret; Keychain app/stripe] (target ssm) [NEW destination]",
    "",
    "Always allow: trust every [NEW destination] (whole GitHub owner, Vercel team, AWS profile+role+region or project) for all projects.",
  ]);
});

test("S10: Approve once writes but persists nothing", async () => {
  const h = harness({ policy, keychain, decision: "once" });

  const out = await run(["apply", "--target", "supa"], h.deps);

  assert.equal(out.exitCode, 0, out.stdout);
  assert.equal(parse(out.stdout).approval, "dialog");
  assert.equal(parse(out.stdout).trusted, undefined);
  assert.equal(h.trust, null);
  assert.equal(h.keychain.store.has("zks/trust-hmac"), false);
  assert.equal((await run(["apply", "--target", "supa"], h.deps)).exitCode, 0);
  assert.equal(h.human.approvals.length, 2, "asked again");
  assert.deepEqual(records(h).map((r) => r.approval), ["dialog", "dialog"]);
});

test("S5/S10: Deny writes nothing, trusts nothing and audits denied", async () => {
  const h = harness({ policy, keychain, decision: "deny" });

  const out = await run(["apply"], h.deps);

  assert.equal(out.exitCode, 3, out.stdout);
  assert.equal(h.fetch.calls.length + h.aws.calls.length + h.exec.calls.length, 0);
  assert.equal(h.trust, null);
  assert.deepEqual(records(h).map((r) => [r.result, r.approval]), Array(4).fill(["denied", "dialog"]));
});

test("S10: a tampered trust file is treated as empty and reported invalid", async () => {
  const tamperings: Array<(h: TestHarness) => void> = [
    (h) => h.trust!.destinations.push({ key: SSM_KEY, addedAt: "2026-11-04T12:00:00.000Z", addedBy: "evil" }),
    (h) => {
      h.trust!.mac = "0".repeat(64);
    },
    (h) => {
      h.trust = { version: 1, destinations: h.trust!.destinations } as unknown as TestHarness["trust"];
    },
    (h) => {
      h.trust = "garbage" as unknown as TestHarness["trust"];
    },
    (h) => {
      h.keychain.store.delete("zks/trust-hmac");
    },
  ];
  for (const [i, tamper] of tamperings.entries()) {
    const h = harness({ policy, keychain, decision: "always" });
    assert.equal((await run(["apply", "--target", "gh"], h.deps)).exitCode, 0);
    tamper(h);
    h.human.approvals.length = 0;

    const out = await run(["apply", "--target", "gh"], h.deps);

    assert.equal(out.exitCode, 0, out.stdout);
    assert.equal(h.human.approvals.length, 1, `tampering ${i}: dialog shown`);
    assert.ok(h.human.approvals[0]!.some((l) => l.endsWith("(target gh) [NEW destination]")), `tampering ${i}`);
    assert.equal(parse(out.stdout).trust, "invalid", `tampering ${i}`);
  }
});

test("S10: trust list shows keys, dates, descriptions and validity", async () => {
  const h = harness({ policy, keychain, decision: "always" });
  assert.deepEqual(parse((await run(["trust", "list"], h.deps)).stdout), { ok: true, valid: true, destinations: [] });
  await run(["apply", "--target", "gh,supa", "--agent", "codex:1"], h.deps);

  const out = await run(["trust", "list"], h.deps);

  assert.equal(out.exitCode, 0);
  assert.deepEqual(parse(out.stdout), {
    ok: true,
    valid: true,
    destinations: [
      { key: GH_KEY, addedAt: "2026-11-04T12:00:00.000Z", addedBy: "codex:1", description: "GitHub owner acme (every repository)" },
      { key: SUPA_KEY, addedAt: "2026-11-04T12:00:00.000Z", addedBy: "codex:1", description: "Supabase project abcdefghijklmnopqrst" },
    ],
  });

  h.trust!.mac = "f".repeat(64);
  assert.deepEqual(parse((await run(["trust", "list"], h.deps)).stdout), { ok: true, valid: false, destinations: [] });
});

test("S10: trust remove drops a key without a dialog; an unknown key is a usage error", async () => {
  const h = harness({ policy, keychain, decision: "always" });
  await run(["apply", "--target", "gh,supa"], h.deps);
  const dialogs = h.human.approvals.length;

  const out = await run(["trust", "remove", GH_KEY], h.deps);

  assert.equal(out.exitCode, 0, out.stdout);
  assert.deepEqual(parse(out.stdout), { ok: true, removed: GH_KEY });
  assert.equal(h.human.approvals.length, dialogs);
  assert.deepEqual(parse((await run(["trust", "list"], h.deps)).stdout).destinations.map((d: { key: string }) => d.key), [SUPA_KEY]);
  assert.equal(parse((await run(["trust", "list"], h.deps)).stdout).valid, true);

  const unknown = await run(["trust", "remove", "github:nobody"], h.deps);
  assert.equal(unknown.exitCode, 2);
  assert.deepEqual(parse(unknown.stdout), { ok: false, error: { code: "usage", message: "not a trusted destination; see `zks trust list`" } });
  assert.equal((await run(["trust", "remove"], h.deps)).exitCode, 2);
  assert.equal((await run(["trust", "remove", SUPA_KEY, "extra"], h.deps)).exitCode, 2);
  assert.deepEqual(parse((await run(["trust", "list"], h.deps)).stdout).destinations.map((d: { key: string }) => d.key), [SUPA_KEY]);
});

test("S10: the three-button dialog maps only explicit answers; everything else denies", async () => {
  const answer = (stdout: string, code = 0) => fakeExec(() => ({ code, stdout: Buffer.from(stdout) }));
  const once = answer("Approve once\n");
  assert.equal(await createMacDialogs(once.exec, "darwin").approveWithTrust("t", ["a"]), "once");
  const script = once.calls[0]!.input;
  assert.equal(once.calls[0]!.command, "/usr/bin/osascript");
  assert.ok(script.includes('buttons {"Deny", "Approve once", "Always allow"} default button "Deny" cancel button "Deny"'), script);
  assert.equal(await createMacDialogs(answer("Always allow\n").exec, "darwin").approveWithTrust("t", ["a"]), "always");
  for (const stdout of ["Deny\n", "timeout\n", "", "Approve\n"]) {
    assert.equal(await createMacDialogs(answer(stdout).exec, "darwin").approveWithTrust("t", ["a"]), "deny", stdout);
  }
  assert.equal(await createMacDialogs(answer("Always allow\n", 1).exec, "darwin").approveWithTrust("t", ["a"]), "deny");
  const failing = createMacDialogs(async () => {
    throw new Error("spawn failed");
  }, "darwin");
  assert.equal(await failing.approveWithTrust("t", ["a"]), "deny");
  const linux = answer("Always allow\n");
  assert.equal(await createMacDialogs(linux.exec, "linux").approveWithTrust("t", ["a"]), "deny");
  const big = answer("Always allow\n");
  assert.equal(await createMacDialogs(big.exec, "darwin").approveWithTrust("t", Array(26).fill("x")), "deny");
  assert.equal(linux.calls.length + big.calls.length, 0);
});
