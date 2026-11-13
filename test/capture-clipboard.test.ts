import assert from "node:assert/strict";
import { test } from "node:test";
import { run } from "../src/run.ts";
import { HELP_TEXT } from "../src/help.ts";
import { CANARY, auditBytes, ghTokenExec, harness, parse, type ExecCall } from "./helpers.ts";

const PBPASTE = "/usr/bin/pbpaste";
const PBCOPY = "/usr/bin/pbcopy";
const CMD = ["capture", "clipboard", "--store", "app/key"];

function clipboardExec(clipboard: string, options: { pbpasteCode?: number; pbcopyCode?: number } = {}) {
  return (call: ExecCall) => {
    if (call.command === PBPASTE) return { code: options.pbpasteCode ?? 0, stdout: Buffer.from(clipboard, "utf8") };
    if (call.command === PBCOPY) return { code: options.pbcopyCode ?? 0 };
    return ghTokenExec(call);
  };
}

test("S3/S5: stores the clipboard in a new Keychain item after asking and clears the clipboard", async () => {
  const h = harness({ exec: clipboardExec(`${CANARY}\n`) });
  const out = await run(CMD, h.deps);
  assert.equal(out.exitCode, 0, out.stdout);
  const body = parse(out.stdout);
  assert.equal(body.ok, true);
  assert.equal(body.command, "capture");
  assert.equal(body.mode, "clipboard");
  assert.equal(body.store, "app/key");
  assert.equal(body.length, CANARY.length);
  assert.equal(body.clipboardCleared, true);
  assert.equal(h.keychain.store.get("app/key"), CANARY);
  assert.deepEqual(h.human.approvals, [["Store the clipboard in the Keychain item app/key?", "zks clears the clipboard afterwards"]]);
  assert.deepEqual(h.exec.calls.map((c) => [c.command, c.input]), [[PBPASTE, ""], [PBPASTE, ""], [PBCOPY, ""]]);
  assert.ok(!out.stdout.includes(CANARY));
  const audit = await auditBytes(h.auditDb);
  assert.ok(!audit.includes(CANARY));
  assert.ok(audit.includes("capture-clipboard"));
});

test("S3: replacing an existing item asks first; a denial reads nothing and keeps the item", async () => {
  const h = harness({ keychain: { "app/key": "old" }, approve: false, exec: clipboardExec(CANARY) });
  const out = await run(CMD, h.deps);
  assert.equal(out.exitCode, 3, out.stdout);
  assert.equal(parse(out.stdout).error.code, "not_approved");
  assert.equal(h.human.approvals.length, 1);
  assert.equal(h.keychain.store.get("app/key"), "old");
  assert.deepEqual(h.exec.calls, []);
});

test("S3: an approved replacement stores the new value", async () => {
  const h = harness({ keychain: { "app/key": "old" }, approve: true, exec: clipboardExec(CANARY) });
  const out = await run(CMD, h.deps);
  assert.equal(out.exitCode, 0, out.stdout);
  assert.equal(h.keychain.store.get("app/key"), CANARY);
  assert.deepEqual(h.human.approvals, [["Replace the Keychain item app/key?", "New value: read from the clipboard, which zks then clears"]]);
});

test("S3: an empty clipboard writes nothing", async () => {
  const h = harness({ exec: clipboardExec("\n") });
  const out = await run(CMD, h.deps);
  assert.equal(out.exitCode, 1, out.stdout);
  assert.equal(parse(out.stdout).error.code, "clipboard_empty");
  assert.equal(h.keychain.store.has("app/key"), false);
  assert.deepEqual(h.exec.calls.map((c) => c.command), [PBPASTE]);
});

test("S3: a failing pbpaste is clipboard_unavailable and writes nothing", async () => {
  const h = harness({ exec: clipboardExec(CANARY, { pbpasteCode: 1 }) });
  const out = await run(CMD, h.deps);
  assert.equal(out.exitCode, 1, out.stdout);
  assert.equal(parse(out.stdout).error.code, "clipboard_unavailable");
  assert.equal(h.keychain.store.has("app/key"), false);
});

test("S3: a failed clear is reported, the item is still stored", async () => {
  const h = harness({ exec: clipboardExec(CANARY, { pbcopyCode: 1 }) });
  const out = await run(CMD, h.deps);
  assert.equal(out.exitCode, 0, out.stdout);
  assert.equal(parse(out.stdout).clipboardCleared, false);
  assert.equal(h.keychain.store.get("app/key"), CANARY);
});

test("S3: a failed Keychain write puts the old value back", async () => {
  const h = harness({ keychain: { "app/key": "old" }, approve: true, exec: clipboardExec(CANARY) });
  const set = h.deps.keychain.set.bind(h.deps.keychain);
  let calls = 0;
  h.deps.keychain.set = async (service, account, value) => {
    calls++;
    if (calls === 1) throw new Error("denied");
    return set(service, account, value);
  };
  const out = await run(CMD, h.deps);
  assert.equal(out.exitCode, 1, out.stdout);
  const body = parse(out.stdout);
  assert.equal(body.error.code, "keychain_failed");
  assert.equal(body.restored, true);
  assert.equal(h.keychain.store.get("app/key"), "old");
});

test("S3: usage — needs --store, refuses the zks service and other flags", async () => {
  const h = harness();
  for (const argv of [
    ["capture", "clipboard"],
    ["capture", "clipboard", "--store", "zks/vercel"],
    ["capture", "clipboard", "--store", "ZKS/github"],
    ["capture", "clipboard", "--store", "app/key", "--origin", "https://x.com"],
  ]) {
    const out = await run(argv, h.deps);
    assert.equal(out.exitCode, 2, `${argv.join(" ")}: ${out.stdout}`);
  }
  assert.deepEqual(h.exec.calls, []);
  assert.equal(h.keychain.store.size, 0);
});

test("S3: help lists capture clipboard", () => {
  assert.ok(HELP_TEXT.includes("zks capture clipboard --store SERVICE/ACCOUNT"));
});

test("S3: a failed write and a failed restore is restore_failed, without the value, and the clipboard is kept", async () => {
  const h = harness({ keychain: { "app/key": "old" }, approve: true, exec: clipboardExec(CANARY) });
  h.deps.keychain.set = async () => {
    throw new Error(`boom ${CANARY}`);
  };
  const out = await run(CMD, h.deps);
  assert.equal(out.exitCode, 1, out.stdout);
  assert.equal(parse(out.stdout).error.code, "restore_failed");
  assert.ok(!out.stdout.includes(CANARY));
  assert.ok(!(await auditBytes(h.auditDb)).includes(CANARY));
  assert.deepEqual(h.exec.calls.map((c) => c.command), [PBPASTE]);
});

test("S3: a clipboard capture records no origin, so fill --from always asks", async () => {
  const h = harness({ exec: clipboardExec(CANARY) });
  assert.equal((await run(CMD, h.deps)).exitCode, 0);
  assert.equal(h.human.approvals.length, 1, "the capture asked");
  await run(["capture", "fill", "--space", "1", "--page", "p1", "--selector", "#p", "--from", "app/key", "--origin", "https://x.com"], h.deps);
  assert.equal(h.human.approvals.length, 2, "the fill asked too");
});

function records(h: ReturnType<typeof harness>) {
  const store = h.deps.openAudit();
  try {
    return store.list({ limit: 100 });
  } finally {
    store.close();
  }
}

test("S5: a denied capture of a new item reads nothing, exits 3 and is audited denied", async () => {
  const h = harness({ approve: false, exec: clipboardExec(CANARY) });
  const out = await run(CMD, h.deps);
  assert.equal(out.exitCode, 3, out.stdout);
  const body = parse(out.stdout);
  assert.equal(body.error.code, "not_approved");
  assert.equal(body.error.message, "storing the clipboard was not approved; the clipboard was not read");
  assert.deepEqual(h.human.approvals, [["Store the clipboard in the Keychain item app/key?", "zks clears the clipboard afterwards"]]);
  assert.deepEqual(h.exec.calls, []);
  assert.equal(h.keychain.store.has("app/key"), false);
  const [record] = records(h);
  assert.deepEqual([record!.result, record!.errorCode, record!.approval, record!.sourceKind], ["denied", "not_approved", "dialog", "capture-clipboard"]);
});

test("S5: a denied replacement keeps its message and is audited denied", async () => {
  const h = harness({ keychain: { "app/key": "old" }, approve: false, exec: clipboardExec(CANARY) });
  const out = await run(CMD, h.deps);
  assert.equal(parse(out.stdout).error.message, "replacing the Keychain item was not approved; the clipboard was not read");
  assert.equal(records(h)[0]!.result, "denied");
});

test("S5: a clipboard that changed after the read is not cleared", async () => {
  let n = 0;
  const h = harness({
    exec: (call: ExecCall) => {
      if (call.command === PBPASTE) return { code: 0, stdout: Buffer.from(n++ === 0 ? CANARY : "copied later") };
      return {};
    },
  });
  const out = await run(CMD, h.deps);
  assert.equal(out.exitCode, 0, out.stdout);
  assert.equal(parse(out.stdout).clipboardCleared, false);
  assert.equal(h.keychain.store.get("app/key"), CANARY);
  assert.deepEqual(h.exec.calls.map((c) => c.command), [PBPASTE, PBPASTE]);
});
