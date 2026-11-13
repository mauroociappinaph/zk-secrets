import assert from "node:assert/strict";
import { test } from "node:test";
import { HELP_TEXT } from "../src/help.ts";
import { run } from "../src/run.ts";
import { CANARY, harness, parse } from "./helpers.ts";

// S2 of odd/tasks/zks-v0.5.0.md — `zks inventory --older-than <N>d`.

const targets = {
  v1: { provider: "vercel", projectId: "prj_1", environments: ["production"] },
  v2: { provider: "vercel", projectId: "prj_2", environments: ["production"] },
};
const variables = {
  A: { sensitive: true, source: { kind: "keychain", service: "app", account: "api" }, targets: ["v1"] },
  B: { sensitive: false, value: "plain", targets: ["v1"] },
  G: { sensitive: true, source: { kind: "generate" }, targets: ["v2"] },
};
const policy = { version: 1, project: "acme", targets, variables };
const oldPolicy = { ...policy, variables: { ...variables, OLD: { sensitive: false, value: "x", targets: ["v1"] } } };

// renew added in 0.6.0 (S1 of odd/tasks/zks-v0.6.0.md).
const renewA = {
  how: "source",
  source: "keychain",
  step: "replace the Keychain item app/api with a new value from the provider (zks capture read or zks capture file)",
  then: "zks apply --only A",
  revoke: "delete the old value at the provider yourself",
};
const renewB = { how: "edit", step: "change the value in the policy", then: "zks apply --only B" };
const renewG = { how: "rotate", command: "zks rotate G", revoke: "delete the old value at the provider yourself" };
const A = { variable: "A", provider: "vercel", target: "v1", environment: "production", lastWrittenAt: "2026-11-01T08:00:00.000Z", writes: 1, status: "written", renew: renewA };
const B = { variable: "B", provider: "vercel", target: "v1", environment: "production", lastWrittenAt: null, ageDays: null, writes: 0, status: "never_written", renew: renewB };
const G = { variable: "G", provider: "vercel", target: "v2", environment: "production", lastWrittenAt: "2026-11-03T08:00:00.000Z", writes: 1, status: "written", renew: renewG };
const OLD = { variable: "OLD", provider: "vercel", target: "v1", environment: "production", lastWrittenAt: "2026-10-01T08:00:00.000Z", writes: 1, status: "not_in_policy" };

/** A written 2026-11-01T08:00Z, G rotated 2026-11-03T08:00Z, OLD (no longer in the policy) 2026-10-01T08:00Z, B never. */
async function setup() {
  const h = harness({ policy, files: { "old.json": JSON.stringify(oldPolicy) }, keychain: { "zks/vercel": "tok-vercel-1", "app/api": CANARY } });
  const at = (iso: string) => {
    h.deps.now = () => new Date(iso);
  };
  at("2026-10-01T08:00:00.000Z");
  assert.equal((await run(["apply", "--policy", "old.json", "--only", "OLD"], h.deps)).exitCode, 0);
  at("2026-11-01T08:00:00.000Z");
  assert.equal((await run(["apply", "--only", "A"], h.deps)).exitCode, 0);
  at("2026-11-03T08:00:00.000Z");
  assert.equal((await run(["rotate", "G"], h.deps)).exitCode, 0);
  return { h, at };
}

test("S2: --older-than keeps entries written strictly more than N days ago plus never-written ones, and adds olderThanDays", async () => {
  const { h, at } = await setup();
  // Exactly 10 days after A's write: A is not older than 10 days.
  at("2026-11-11T08:00:00.000Z");
  const exact = await run(["inventory", "--older-than", "10d"], h.deps);
  assert.equal(exact.exitCode, 0, exact.stdout);
  assert.ok(!exact.stdout.includes(CANARY));
  assert.deepEqual(parse(exact.stdout), {
    ok: true,
    project: "acme",
    policy: `${h.dir}/zks.policy.json`,
    olderThanDays: 10,
    entries: [B, { ...OLD, ageDays: 41 }],
  });

  // One millisecond later A is older than 10 days; G (8 days) is not.
  at("2026-11-11T08:00:00.001Z");
  const later = parse((await run(["inventory", "--older-than=10d"], h.deps)).stdout);
  assert.equal(later.olderThanDays, 10);
  assert.deepEqual(later.entries, [{ ...A, ageDays: 10 }, B, { ...OLD, ageDays: 41 }]);

  const week = parse((await run(["inventory", "--older-than", "7d"], h.deps)).stdout);
  assert.deepEqual(week.entries, [{ ...A, ageDays: 10 }, B, { ...G, ageDays: 8 }, { ...OLD, ageDays: 41 }]);

  const max = parse((await run(["inventory", "--older-than", "3650d"], h.deps)).stdout);
  assert.equal(max.olderThanDays, 3650);
  assert.deepEqual(max.entries, [B]);

  // With --project (no policy comparison) the filter applies too.
  const project = parse((await run(["inventory", "--project", "acme", "--policy", "zks.policy.json", "--older-than", "1d"], h.deps)).stdout);
  assert.equal(project.olderThanDays, 1);
  assert.deepEqual(
    project.entries.map((e: Record<string, unknown>) => e.variable),
    ["A", "B", "G", "OLD"],
  );
});

test("S2: without --older-than the inventory output is unchanged (no olderThanDays, every entry)", async () => {
  const { h, at } = await setup();
  at("2026-11-11T08:00:00.000Z");
  const out = await run(["inventory"], h.deps);
  assert.equal(out.exitCode, 0);
  const expected = {
    ok: true,
    project: "acme",
    policy: `${h.dir}/zks.policy.json`,
    entries: [{ ...A, ageDays: 10 }, B, { ...G, ageDays: 8 }, { ...OLD, ageDays: 41 }],
  };
  // Key order as before: ageDays sits after lastWrittenAt; since 0.6.0 renew follows status (absent for not_in_policy).
  const ordered = expected.entries.map((e) => ({
    variable: e.variable,
    provider: e.provider,
    target: e.target,
    environment: e.environment,
    lastWrittenAt: e.lastWrittenAt,
    ageDays: e.ageDays,
    writes: e.writes,
    status: e.status,
    ...("renew" in e ? { renew: e.renew } : {}),
  }));
  assert.equal(out.stdout, `${JSON.stringify({ ...expected, entries: ordered }, null, 2)}\n`);
});

test("S2: --older-than accepts only <N>d with N an integer from 1 to 3650; anything else is a usage error", async () => {
  const { h, at } = await setup();
  at("2026-11-11T08:00:00.000Z");
  const message = "--older-than must be <N>d with N a whole number of days from 1 to 3650, e.g. 90d";
  for (const value of ["0d", "3651d", "90", "d", "-5d", "90D", "1.5d", "90days", "90h", " 90d", "090d", "1e2d", "", "99999999999999999999d"]) {
    const out = await run(["inventory", `--older-than=${value}`], h.deps);
    assert.equal(out.exitCode, 2, value);
    assert.deepEqual(parse(out.stdout), { ok: false, error: { code: "usage", message } }, value);
  }
  const missing = await run(["inventory", "--older-than"], h.deps);
  assert.equal(missing.exitCode, 2);
  assert.equal(parse(missing.stdout).error.code, "usage");
  // Only inventory takes the option.
  assert.equal((await run(["plan", "--older-than", "90d"], h.deps)).exitCode, 2);
  // The refused calls changed nothing: the inventory is still whole.
  assert.equal(parse((await run(["inventory"], h.deps)).stdout).entries.length, 4);
});

test("S2: help documents --older-than", () => {
  assert.match(HELP_TEXT, /zks inventory \[--project P\] \[--policy FILE\] \[--older-than <N>d\]/);
});

// S1 of odd/tasks/zks-v0.6.0.md — every policy entry says how to renew its value.

const REVOKE = "delete the old value at the provider yourself";
const renewPolicy = {
  version: 1,
  project: "acme",
  targets: { v1: { provider: "vercel", projectId: "prj_1", environments: ["production"] } },
  variables: {
    G: { sensitive: true, source: { kind: "generate" }, targets: ["v1"] },
    H: { sensitive: true, source: { kind: "generate", format: "password" }, targets: ["v1"] },
    KEY: { sensitive: true, source: { kind: "generate", format: "ed25519-private-key" }, targets: ["v1"] },
    PUB: { sensitive: false, source: { kind: "public-key", of: "KEY" }, targets: ["v1"] },
    ONE: { sensitive: true, source: { kind: "template", template: "x-${G}" }, targets: ["v1"] },
    TWO: { sensitive: true, source: { kind: "template", template: "${ONE}:${H}" }, targets: ["v1"] },
    K: { sensitive: true, source: { kind: "keychain", service: "app", account: "api" }, targets: ["v1"] },
    O: { sensitive: true, source: { kind: "op", ref: "op://vault/stripe/key" }, targets: ["v1"] },
    D: { sensitive: true, source: { kind: "dotenv", path: ".env.source", key: "DB_PASS" }, targets: ["v1"] },
    DN: { sensitive: true, source: { kind: "dotenv", path: ".env.source" }, targets: ["v1"] },
    P: { sensitive: true, source: { kind: "prompt" }, targets: ["v1"] },
    C: { sensitive: true, source: { kind: "clipboard" }, targets: ["v1"] },
    L: { sensitive: false, value: CANARY, targets: ["v1"] },
    MIX: { sensitive: true, source: { kind: "template", template: "${K}@${O}/${L}" }, targets: ["v1"] },
    LIT: { sensitive: true, source: { kind: "template", template: "plain-${L}" }, targets: ["v1"] },
  },
};

function renewHarness() {
  const h = harness({
    policy: renewPolicy,
    files: { ".env.source": `DB_PASS=${CANARY}\nDN=${CANARY}\n` },
    keychain: { "zks/vercel": "tok-vercel-1", "app/api": CANARY },
  });
  h.deps.now = () => new Date("2026-11-11T08:00:00.000Z");
  return h;
}

function expectedRenew(dir: string): Record<string, unknown> {
  const then = (name: string) => `zks apply --only ${name}`;
  const keychainStep = "replace the Keychain item app/api with a new value from the provider (zks capture read or zks capture file)";
  return {
    G: { how: "rotate", command: "zks rotate G", revoke: REVOKE },
    H: { how: "rotate", command: "zks rotate H", revoke: REVOKE },
    KEY: { how: "rotate", command: "zks rotate KEY", revoke: REVOKE },
    PUB: { how: "rotate", command: "zks rotate KEY", revoke: REVOKE },
    ONE: { how: "rotate", command: "zks rotate G", revoke: REVOKE },
    TWO: { how: "rotate", command: "zks rotate G", also: ["H"], revoke: REVOKE },
    K: { how: "source", source: "keychain", step: keychainStep, then: then("K"), revoke: REVOKE },
    O: { how: "source", source: "op", step: "update op://vault/stripe/key in 1Password", then: then("O"), revoke: REVOKE },
    D: { how: "source", source: "dotenv", step: `update DB_PASS in ${dir}/.env.source`, then: then("D"), revoke: REVOKE },
    DN: { how: "source", source: "dotenv", step: `update DN in ${dir}/.env.source`, then: then("DN"), revoke: REVOKE },
    P: { how: "source", source: "prompt", step: "get a new value from the provider; zks asks for it in a dialog", then: then("P"), revoke: REVOKE },
    C: { how: "source", source: "clipboard", step: "copy a new value from the provider", then: then("C"), revoke: REVOKE },
    L: { how: "edit", step: "change the value in the policy", then: then("L") },
    MIX: {
      how: "source",
      from: [
        { variable: "K", source: "keychain", step: keychainStep },
        { variable: "O", source: "op", step: "update op://vault/stripe/key in 1Password" },
        { variable: "L", source: "literal", step: "change the value in the policy" },
      ],
      then: then("MIX"),
      revoke: REVOKE,
    },
    LIT: { how: "edit", step: "change the value in the policy", then: then("LIT") },
  };
}

test("S1: every policy entry carries a renew hint by source kind, metadata only", async () => {
  const h = renewHarness();
  const out = await run(["inventory"], h.deps);
  assert.equal(out.exitCode, 0, out.stdout);
  assert.ok(!out.stdout.includes(CANARY));
  const body = parse(out.stdout);
  const want = expectedRenew(h.dir);
  assert.deepEqual(Object.fromEntries(body.entries.map((e: Record<string, unknown>) => [e.variable, e.renew])), want);
  // renew is the last key of each entry; everything else is as before.
  assert.deepEqual(body.entries.find((e: Record<string, unknown>) => e.variable === "K"), {
    variable: "K",
    provider: "vercel",
    target: "v1",
    environment: "production",
    lastWrittenAt: null,
    ageDays: null,
    writes: 0,
    status: "never_written",
    renew: want.K,
  });
  assert.deepEqual(Object.keys(body.entries[0]).at(-1), "renew");
  // zks itself never offers to revoke: only source/rotate say so, and as an instruction to the human.
  for (const e of body.entries) {
    const r = e.renew as Record<string, unknown>;
    assert.equal(r.revoke === REVOKE, r.how === "source" || r.how === "rotate", e.variable);
  }
});

test("S1: entries not_in_policy have no renew; --older-than keeps renew on the entries it keeps", async () => {
  const { h, at } = await setup();
  at("2026-11-11T08:00:00.001Z");
  const out = await run(["inventory", "--older-than", "10d"], h.deps);
  assert.equal(out.exitCode, 0, out.stdout);
  assert.ok(!out.stdout.includes(CANARY));
  const entries = parse(out.stdout).entries as Record<string, unknown>[];
  assert.deepEqual(
    entries.map((e) => [e.variable, e.status, e.renew]),
    [
      [
        "A",
        "written",
        {
          how: "source",
          source: "keychain",
          step: "replace the Keychain item app/api with a new value from the provider (zks capture read or zks capture file)",
          then: "zks apply --only A",
          revoke: REVOKE,
        },
      ],
      ["B", "never_written", { how: "edit", step: "change the value in the policy", then: "zks apply --only B" }],
      ["OLD", "not_in_policy", undefined],
    ],
  );
  assert.ok(!("renew" in (entries[2] as object)));
});

test("S2 (0.6.0): help says inventory tells how to renew each entry", () => {
  assert.match(HELP_TEXT, /and how to renew each/);
});
