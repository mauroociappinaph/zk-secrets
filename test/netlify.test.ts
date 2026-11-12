import assert from "node:assert/strict";
import { test } from "node:test";
import { describeEffect } from "../src/policy/describe.ts";
import { describeTrustKey, trustKeyOf } from "../src/policy/trust.ts";
import type { Operation, TargetConfig } from "../src/policy/types.ts";
import { PolicyError, validatePolicy } from "../src/policy/validate.ts";
import { HELP_TEXT } from "../src/help.ts";
import { PINNED_CAPTURE_ORIGINS, TOKEN_ACCOUNTS, run } from "../src/run.ts";
import { SecretBuffer } from "../src/secret/secret-buffer.ts";
import { netlifySink } from "../src/sinks/netlify.ts";
import { SinkError, type SinkContext } from "../src/sinks/types.ts";
import { CANARY, TEST_TOOLS, auditBytes, fakeAws, fakeExec, fakeFetch, fakeKeychain, harness, parse, type FetchCall } from "./helpers.ts";

const API = "https://api.netlify.com/api/v1/accounts/acme-team/env";
const TARGET = { provider: "netlify", accountId: "acme-team", siteId: "5f1c2d3e", context: "production" } as const;

function op(target: TargetConfig, sensitive = true): Operation {
  return { name: "API_KEY", targetKey: "nl", target, variable: { sensitive, targets: ["nl"], source: { kind: "prompt" } }, sourceKind: "prompt" };
}

function ctx(respond: (call: FetchCall) => { status?: number; body?: unknown }, tokens: Record<string, string> = { "zks/netlify": "tn" }) {
  const fetch = fakeFetch(respond);
  const context: SinkContext = { fetch: fetch.fetch, exec: fakeExec().exec, aws: fakeAws().aws, keychain: fakeKeychain(tokens).keychain, tools: TEST_TOOLS };
  return { context, fetch };
}

async function rejects(promise: Promise<unknown>, code: string, message: string): Promise<void> {
  await assert.rejects(promise, (error: unknown) => {
    assert.ok(error instanceof SinkError, String(error));
    assert.equal(error.code, code);
    assert.equal(error.message, message);
    assert.ok(!error.message.includes(CANARY));
    return true;
  });
}

test("S11: netlify updates the value of an existing secret variable for its context", async () => {
  const c = ctx((call) => (call.init.method === "GET" ? { body: { key: "API_KEY", is_secret: true } } : { body: { id: "val_1" } }));

  assert.deepEqual(await netlifySink.apply(op(TARGET), SecretBuffer.fromString(CANARY), c.context), {});

  assert.deepEqual(
    c.fetch.calls.map((call) => [call.init.method, call.url]),
    [
      ["GET", `${API}/API_KEY?site_id=5f1c2d3e`],
      ["PATCH", `${API}/API_KEY?site_id=5f1c2d3e`],
    ],
  );
  assert.equal(c.fetch.calls[0]!.body, "");
  assert.deepEqual(JSON.parse(c.fetch.calls[1]!.body), { context: "production", value: CANARY });
  for (const call of c.fetch.calls) assert.equal((call.init.headers as Record<string, string>).authorization, "Bearer tn");
});

test("S11: netlify creates a missing variable with is_secret for sensitive values, account-wide without siteId", async () => {
  const c = ctx((call) => (call.init.method === "GET" ? { status: 404 } : { status: 201, body: [{ key: "API_KEY" }] }));
  const target = { provider: "netlify", accountId: "acme-team", context: "all" } as const;

  await netlifySink.apply(op(target), SecretBuffer.fromString(CANARY), c.context);

  assert.deepEqual(
    c.fetch.calls.map((call) => [call.init.method, call.url]),
    [
      ["GET", `${API}/API_KEY`],
      ["POST", API],
    ],
  );
  assert.deepEqual(JSON.parse(c.fetch.calls[1]!.body), [{ key: "API_KEY", values: [{ value: CANARY, context: "all" }], is_secret: true }]);

  const plain = ctx((call) => (call.init.method === "GET" ? { status: 404 } : { status: 201 }));
  await netlifySink.apply(op(TARGET, false), SecretBuffer.fromString("info"), plain.context);
  assert.deepEqual(JSON.parse(plain.fetch.calls[1]!.body), [{ key: "API_KEY", values: [{ value: "info", context: "production" }], is_secret: false }]);
  assert.equal(plain.fetch.calls[1]!.url, `${API}?site_id=5f1c2d3e`);
});

test("S11: netlify refuses to put a sensitive value into an existing variable that is not secret", async () => {
  const c = ctx(() => ({ body: { key: "API_KEY", is_secret: false } }));
  await rejects(
    netlifySink.apply(op(TARGET), SecretBuffer.fromString(CANARY), c.context),
    "netlify_not_secret",
    "the Netlify variable API_KEY exists and is not secret; delete it in Netlify or mark it secret, then apply again",
  );
  assert.deepEqual(c.fetch.calls.map((call) => call.init.method), ["GET"]);
});

test("S11: netlify without a token fails before any request; HTTP errors report only the status", async () => {
  const none = ctx(() => ({}), {});
  await rejects(netlifySink.apply(op(TARGET), SecretBuffer.fromString(CANARY), none.context), "missing_token", "no netlify token in the Keychain; run `zks auth set netlify`");
  assert.equal(none.fetch.calls.length, 0);

  const denied = ctx(() => ({ status: 401, body: { message: `bad ${CANARY}` } }));
  await rejects(netlifySink.apply(op(TARGET), SecretBuffer.fromString(CANARY), denied.context), "netlify_failed", "Netlify HTTP 401");
  assert.equal(denied.fetch.calls.length, 1);

  const patchFails = ctx((call) => (call.init.method === "GET" ? { body: { is_secret: true } } : { status: 422, body: { message: CANARY } }));
  await rejects(netlifySink.apply(op(TARGET), SecretBuffer.fromString(CANARY), patchFails.context), "netlify_failed", "Netlify HTTP 422");
});

test("S11: netlify targets are validated", () => {
  const policy = (target: unknown) => ({ version: 1, project: "p", targets: { nl: target }, variables: {} });
  assert.doesNotThrow(() => validatePolicy(policy(TARGET)));
  assert.doesNotThrow(() => validatePolicy(policy({ provider: "netlify", accountId: "a1", context: "deploy-preview" })));
  const issues = (target: unknown) => {
    try {
      validatePolicy(policy(target));
      return [];
    } catch (error) {
      return (error as PolicyError).issues;
    }
  };
  assert.deepEqual(issues({ provider: "netlify", accountId: "a/../b", siteId: "x y", context: "staging" }), [
    "targets.nl.accountId: must match /^[A-Za-z0-9_-]{1,100}$/",
    "targets.nl.siteId: must match /^[A-Za-z0-9_-]{1,100}$/",
    "targets.nl.context: must be one of all, production, deploy-preview, branch-deploy, dev",
  ]);
  assert.deepEqual(issues({ provider: "netlify", accountId: "a" }), ["targets.nl.context: must be one of all, production, deploy-preview, branch-deploy, dev"]);
});

test("S11: netlify trust key, effect, token account and pinned capture origin", () => {
  assert.equal(trustKeyOf(op(TARGET)), "netlify:acme-team");
  assert.equal(describeTrustKey("netlify:acme-team"), "Netlify account acme-team (every site)");
  assert.equal(describeEffect(op(TARGET)), "applies on the next Netlify build or deploy");
  assert.ok((TOKEN_ACCOUNTS as readonly string[]).includes("netlify"));
  assert.equal(PINNED_CAPTURE_ORIGINS.netlify, "https://app.netlify.com");
  assert.ok(HELP_TEXT.includes("netlify"));
});

const POLICY = {
  version: 1,
  project: "web",
  targets: { nl: TARGET },
  variables: { API_KEY: { sensitive: true, source: { kind: "keychain", service: "app", account: "key" }, targets: ["nl"] } },
};

test("S11 S1 S5: apply to Netlify asks for a new destination and keeps the value out of output and audit", async () => {
  const h = harness({
    policy: POLICY,
    keychain: { "app/key": CANARY, "zks/netlify": "tn" },
    fetch: (call) => (call.init.method === "GET" ? { status: 404 } : { status: 201 }),
  });

  const plan = await run(["plan"], h.deps);
  assert.equal(plan.exitCode, 0, plan.stdout);
  const planned = parse(plan.stdout).operations[0];
  assert.equal(planned.destination, "netlify account acme-team site 5f1c2d3e context production");
  assert.equal(planned.environment, "production");
  assert.equal(h.fetch.calls.length, 0);

  const out = await run(["apply"], h.deps);
  assert.equal(out.exitCode, 0, out.stdout);
  assert.equal(h.human.approvals.length, 1);
  assert.ok(h.human.approvals[0]!.some((line) => line.includes("netlify account acme-team site 5f1c2d3e context production") && line.includes("[NEW destination]")));
  assert.equal(parse(out.stdout).results[0].result, "applied");
  assert.ok(!out.stdout.includes(CANARY));
  assert.ok(!h.human.approvals.flat().join("\n").includes(CANARY));
  assert.ok(!(await auditBytes(h.auditDb)).includes(CANARY));
  assert.deepEqual(JSON.parse(h.fetch.calls[1]!.body)[0].values, [{ value: CANARY, context: "production" }]);

  const denied = harness({ policy: POLICY, keychain: { "app/key": CANARY, "zks/netlify": "tn" }, approve: false });
  assert.equal((await run(["apply"], denied.deps)).exitCode, 3);
  assert.equal(denied.fetch.calls.length, 0);
});
