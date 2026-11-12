import assert from "node:assert/strict";
import { test } from "node:test";
import type { SecretBuffer } from "../src/secret/secret-buffer.ts";
import { run } from "../src/run.ts";
import { CANARY, TEST_TOOLS, auditBytes, harness, parse, type ExecCall } from "./helpers.ts";

// L12 (1): a capture that replaces an approved existing Keychain item puts the old value back
// when it does not end ok. The old value is CANARY: it must never reach stdout, audit or the script.

const ORIGIN = "http://127.0.0.1:8123";
const URL_ = `${ORIGIN}/account/tokens`;
const PROFILE = "zks-capture";
const NEW_VALUE = "new-value-written-by-the-script";

const READ = ["capture", "read", "--space", "4", "--page", "p1", "--selector", "#tok", "--store", "app/key", "--origin", ORIGIN];
const GENERATE = ["capture", "fill", "--space", "4", "--page", "p1", "--selector", "#pw", "--store", "app/key", "--generate", "24", "--origin", ORIGIN];
const ISO_READ = ["capture", "read", "--isolated", "--url", URL_, "--selector", "#tok", "--store", "app/key", "--origin", ORIGIN];
const ISO_GENERATE = ["capture", "fill", "--isolated", "--url", URL_, "--selector", "#pw", "--store", "app/key", "--generate", "24", "--origin", ORIGIN];

const FAILURES = ["origin_mismatch", "not_found", "not_password_field", "keychain_failed", "browser_failed"];
const ISOLATION_REFUSALS = ["isolated_profile_missing", "isolated_profile_not_isolated", "login_required"];

type H = ReturnType<typeof harness>;

/**
 * A harness whose fake ego-browser behaves like the script did its Keychain write (as a read
 * does with `security -i`) and then ended with `marker`; `code` is ego's exit code.
 */
function setup(marker: string, options: { isolated?: boolean; code?: number; write?: boolean } = {}) {
  const ref: { h?: H } = {};
  const h = harness({
    keychain: { "app/key": CANARY },
    exec: (call: ExecCall) => {
      if (call.command !== TEST_TOOLS.egoBrowser) return {};
      if (options.write ?? true) ref.h!.keychain.store.set("app/key", NEW_VALUE);
      return { code: options.code ?? 0, stdout: Buffer.from(`${marker}\n`) };
    },
  });
  ref.h = h;
  if (options.isolated) h.config = { capture: { profileId: PROFILE } };
  // Every value zks reads from the Keychain, to check that each buffer ends zeroed.
  const read: SecretBuffer[] = [];
  const get = h.keychain.keychain.get;
  h.keychain.keychain.get = async (service, account) => {
    const v = await get(service, account);
    if (v !== null) read.push(v);
    return v;
  };
  return { h, read };
}

function records(h: H) {
  const store = h.deps.openAudit();
  try {
    return store.list({ limit: 100 });
  } finally {
    store.close();
  }
}

async function assertNoLeak(h: H, stdout: string) {
  assert.ok(!stdout.includes(CANARY), "stdout leaked the old value");
  assert.ok(!(await auditBytes(h.auditDb)).includes(CANARY), "audit leaked the old value");
  for (const call of h.exec.calls) {
    assert.ok(!call.input.includes(CANARY), "the script carried the old value");
    assert.ok(call.args.every((a) => !a.includes(CANARY)), "argv carried the old value");
  }
}

async function assertRestored(argv: string[], code: string, options: { isolated?: boolean; exitCode?: number; marker?: string } = {}) {
  const marker = options.marker ?? `ZKS_RESULT {"ok":false,"code":"${code}"}`;
  const { h, read } = setup(marker, { isolated: options.isolated, code: options.exitCode });
  const out = await run(argv, h.deps);
  const label = `${argv[1]}${options.isolated ? " --isolated" : ""} ${code}`;
  assert.equal(out.exitCode, 1, `${label}: ${out.stdout}`);
  const body = parse(out.stdout);
  assert.equal(body.ok, false);
  assert.equal(body.error.code, code, label);
  assert.equal(body.restored, true, `${label}: restored`);
  assert.equal(h.keychain.store.get("app/key"), CANARY, `${label}: the old value was not written back`);
  assert.deepEqual(h.human.approvals.length, 1, label);
  const [record] = records(h);
  assert.deepEqual([record!.result, record!.errorCode, record!.approval], ["failed", code, "dialog"], label);
  assert.ok(read.length > 0 && read.every((b) => b.disposed), `${label}: the old value buffer was not zeroed`);
  await assertNoLeak(h, out.stdout);
}

test("S3/L12: a failed read over an approved replacement writes the old value back", async () => {
  for (const code of FAILURES) await assertRestored(READ, code);
  // A non-zero ego exit and output without the marker are browser_failed, restored too.
  await assertRestored(READ, "browser_failed", { exitCode: 1, marker: 'ZKS_RESULT {"ok":true,"length":4}' });
  await assertRestored(READ, "browser_failed", { marker: "no marker" });
});

test("S3/L12: a failed fill --generate over an approved replacement writes the old value back", async () => {
  for (const code of FAILURES) await assertRestored(GENERATE, code);
});

test("S3/L12: isolated refusals and failures over an approved replacement write the old value back", async () => {
  for (const code of [...ISOLATION_REFUSALS, ...FAILURES]) {
    await assertRestored(ISO_READ, code, { isolated: true });
    await assertRestored(ISO_GENERATE, code, { isolated: true });
  }
});

test("S3/L12: a failed Keychain write of the generated value writes the old value back", async () => {
  const { h, read } = setup('ZKS_RESULT {"ok":true,"length":32}');
  const set = h.keychain.keychain.set;
  let calls = 0;
  h.keychain.keychain.set = async (service, account, value) => {
    if (++calls === 1) throw new Error("security failed");
    return set(service, account, value);
  };
  const out = await run(GENERATE, h.deps);
  assert.equal(out.exitCode, 1, out.stdout);
  const body = parse(out.stdout);
  assert.deepEqual([body.error.code, body.restored], ["keychain_failed", true]);
  assert.equal(h.keychain.store.get("app/key"), CANARY);
  assert.equal(h.exec.calls.length, 0);
  assert.ok(read.every((b) => b.disposed));
  await assertNoLeak(h, out.stdout);
});

test("S3/L12: a thrown error after the replacement writes the old value back", async () => {
  const { h, read } = setup('ZKS_RESULT {"ok":true,"length":32}', { isolated: true });
  let calls = 0;
  // The first call makes the generated value; the second (the space name) throws.
  h.deps.randomBytes = (n) => {
    if (++calls === 2) throw new Error("entropy failed");
    return Buffer.alloc(n, 7);
  };
  const out = await run(ISO_GENERATE, h.deps);
  assert.equal(out.exitCode, 1, out.stdout);
  assert.equal(parse(out.stdout).error.code, "internal");
  assert.equal(h.keychain.store.get("app/key"), CANARY);
  assert.ok(read.length > 0 && read.every((b) => b.disposed));
  await assertNoLeak(h, out.stdout);
});

test("S3/L12: a successful replacement keeps the new value, zeroes the old one and adds no restored field", async () => {
  for (const [argv, isolated] of [[READ, false], [GENERATE, false], [ISO_READ, true], [ISO_GENERATE, true]] as const) {
    const { h, read } = setup('ZKS_RESULT {"ok":true,"length":32}', { isolated });
    const out = await run([...argv], h.deps);
    assert.equal(out.exitCode, 0, out.stdout);
    const body = parse(out.stdout);
    assert.equal(body.ok, true);
    assert.equal(body.restored, undefined);
    assert.equal(h.keychain.store.get("app/key"), NEW_VALUE);
    assert.ok(read.length > 0 && read.every((b) => b.disposed));
    await assertNoLeak(h, out.stdout);
  }
});

test("S3/L12: a restore that fails is restore_failed, audited, and never echoes the value", async () => {
  const { h, read } = setup('ZKS_RESULT {"ok":false,"code":"origin_mismatch"}');
  h.keychain.keychain.set = async () => {
    throw new Error(`keychain write failed ${CANARY}`);
  };
  const out = await run(READ, h.deps);
  assert.equal(out.exitCode, 1, out.stdout);
  const body = parse(out.stdout);
  assert.equal(body.error.code, "restore_failed");
  assert.equal(
    body.error.message,
    "the capture failed (origin_mismatch) and the previous value of the Keychain item could not be written back; the item now holds whatever the capture left",
  );
  assert.equal(body.restored, undefined);
  const [record] = records(h);
  assert.deepEqual([record!.result, record!.errorCode], ["failed", "restore_failed"]);
  assert.ok(read.every((b) => b.disposed));
  await assertNoLeak(h, out.stdout);
});

test("S3/L12 (preserve): a denied replacement never reads the old value; a new item has nothing to restore", async () => {
  const denied = setup('ZKS_RESULT {"ok":true,"length":4}');
  denied.h.deps.human.approve = async () => false;
  const out = await run(READ, denied.h.deps);
  assert.equal(out.exitCode, 3, out.stdout);
  assert.equal(denied.read.length, 0);
  assert.equal(denied.h.keychain.store.get("app/key"), CANARY);

  const fresh = setup('ZKS_RESULT {"ok":false,"code":"not_found"}', { write: false });
  fresh.h.keychain.store.delete("app/key");
  const res = await run(READ, fresh.h.deps);
  assert.equal(res.exitCode, 1, res.stdout);
  const body = parse(res.stdout);
  assert.deepEqual([body.error.code, body.restored], ["not_found", undefined]);
  assert.equal(fresh.read.length, 0);
  assert.equal(fresh.h.human.approvals.length, 0);
});

test("S3/L12 (preserve): a failed fill --from replaces nothing and restores nothing", async () => {
  const { h, read } = setup('ZKS_RESULT {"ok":false,"code":"not_password_field"}', { write: false });
  const out = await run(["capture", "fill", "--space", "4", "--page", "p1", "--selector", "#pw", "--from", "app/key", "--origin", ORIGIN], h.deps);
  assert.equal(out.exitCode, 1, out.stdout);
  const body = parse(out.stdout);
  assert.deepEqual([body.error.code, body.restored], ["not_password_field", undefined]);
  assert.equal(read.length, 0);
  assert.equal(h.keychain.store.get("app/key"), CANARY);
});
