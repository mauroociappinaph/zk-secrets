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

const A = { variable: "A", provider: "vercel", target: "v1", environment: "production", lastWrittenAt: "2026-11-01T08:00:00.000Z", writes: 1, status: "written" };
const B = { variable: "B", provider: "vercel", target: "v1", environment: "production", lastWrittenAt: null, ageDays: null, writes: 0, status: "never_written" };
const G = { variable: "G", provider: "vercel", target: "v2", environment: "production", lastWrittenAt: "2026-11-03T08:00:00.000Z", writes: 1, status: "written" };
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
  // Key order as before: ageDays sits after lastWrittenAt.
  const ordered = expected.entries.map((e) => ({
    variable: e.variable,
    provider: e.provider,
    target: e.target,
    environment: e.environment,
    lastWrittenAt: e.lastWrittenAt,
    ageDays: e.ageDays,
    writes: e.writes,
    status: e.status,
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
