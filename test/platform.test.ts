import assert from "node:assert/strict";
import { test } from "node:test";
import { inspect } from "node:util";
import { appleScriptString, createMacDialogs } from "../src/gate/dialog.ts";
import { createKeychain } from "../src/platform/keychain.ts";
import { Redactor } from "../src/secret/redactor.ts";
import { SecretBuffer } from "../src/secret/secret-buffer.ts";
import { findDotenvValue, resolveValue } from "../src/sources/resolve.ts";
import { CANARY, TEST_TOOLS, fakeExec, fakeHuman, fakeKeychain } from "./helpers.ts";

test("SecretBuffer never renders its value and zeroes on dispose", () => {
  const s = SecretBuffer.fromString(CANARY);
  assert.equal(String(s), "[REDACTED]");
  assert.equal(JSON.stringify({ s }), '{"s":"[REDACTED]"}');
  assert.equal(inspect(s), "[REDACTED]");
  assert.equal(`${s}`, "[REDACTED]");
  assert.equal(s.reveal(), CANARY);
  s.dispose();
  assert.throws(() => s.reveal(), /disposed/);
});

test("Redactor removes raw, JSON-escaped, URL, base64 and hex forms", () => {
  const r = new Redactor();
  const value = 'p@ss"w/rd+1';
  r.register(SecretBuffer.fromString(value));
  const text = [value, JSON.stringify(value), encodeURIComponent(value), Buffer.from(value).toString("base64"), Buffer.from(value).toString("hex")].join(" ");
  assert.ok(!r.scrub(text).includes("ss"));
});

test("keychain reads with -w, writes through security -i stdin as hex, never argv", async () => {
  const f = fakeExec((call) => (call.args[0] === "find-generic-password" ? { stdout: Buffer.from(`${CANARY}\n`) } : {}));
  const keychain = createKeychain(f.exec);

  assert.equal((await keychain.get("zks", "vercel"))?.reveal(), CANARY);
  await keychain.set("zks", "vercel", SecretBuffer.fromString(CANARY));

  assert.deepEqual(f.calls[0]?.args, ["find-generic-password", "-s", "zks", "-a", "vercel", "-w"]);
  assert.deepEqual(f.calls[1]?.args, ["-i"]);
  assert.equal(f.calls[1]?.input, `add-generic-password -U -s zks -a vercel -X ${Buffer.from(CANARY).toString("hex")}\n`);
  assert.ok(f.calls.every((c) => !c.args.join(" ").includes(CANARY)));
});

test("keychain returns null for a missing item (exit 44)", async () => {
  const keychain = createKeychain(fakeExec(() => ({ code: 44 })).exec);
  assert.equal(await keychain.get("zks", "nope"), null);
});

test("approval dialog: only an explicit Approve passes; other platforms always deny", async () => {
  const approve = fakeExec(() => ({ stdout: Buffer.from("Approve\n") }));
  assert.equal(await createMacDialogs(approve.exec, "darwin").approve("t", ['say "hi"']), true);
  assert.equal(approve.calls[0]?.command, "/usr/bin/osascript");
  assert.deepEqual(approve.calls[0]?.args, ["-"]);
  assert.ok(approve.calls[0]?.input.includes('say \\"hi\\"'));

  for (const stdout of ["Deny\n", "timeout\n", ""]) {
    assert.equal(await createMacDialogs(fakeExec(() => ({ stdout: Buffer.from(stdout) })).exec, "darwin").approve("t", []), false);
  }
  assert.equal(await createMacDialogs(fakeExec(() => ({ code: 1 })).exec, "darwin").approve("t", []), false);
  const linux = fakeExec(() => ({ stdout: Buffer.from("Approve") }));
  assert.equal(await createMacDialogs(linux.exec, "linux").approve("t", []), false);
  assert.equal(linux.calls.length, 0);
});

test("hidden prompt returns the typed value, or null on cancel", async () => {
  const typed = createMacDialogs(fakeExec(() => ({ stdout: Buffer.from(`${CANARY}\n`) })).exec, "darwin");
  assert.equal((await typed.promptSecret("t", "m"))?.reveal(), CANARY);
  const cancelled = createMacDialogs(fakeExec(() => ({ code: 1 })).exec, "darwin");
  assert.equal(await cancelled.promptSecret("t", "m"), null);
});

test("appleScriptString escapes quotes and backslashes", () => {
  assert.equal(appleScriptString('a"b\\c'), '"a\\"b\\\\c"');
});

test("sources: op, generate and dotenv resolve without exposing values", async () => {
  const exec = fakeExec((call) => ({ stdout: Buffer.from(call.command === TEST_TOOLS.op ? CANARY : "") }));
  const deps = { exec: exec.exec, tools: TEST_TOOLS, keychain: fakeKeychain().keychain, human: fakeHuman().human, cwd: "/w" };

  const fromOp = await resolveValue("A", { sensitive: true, targets: [], source: { kind: "op", ref: "op://v/i/f" } }, deps);
  assert.equal(fromOp.reveal(), CANARY);
  assert.deepEqual(exec.calls[0]?.args, ["read", "--no-newline", "op://v/i/f"]);

  const generated = await resolveValue(
    "B",
    { sensitive: true, targets: [], source: { kind: "generate", bytes: 16, encoding: "hex" } },
    { ...deps, randomBytes: (n) => Buffer.alloc(n, 0xab) },
  );
  assert.equal(generated.reveal(), "ab".repeat(16));

  const fromFile = await resolveValue(
    "DB_URL",
    { sensitive: true, targets: [], source: { kind: "dotenv", path: ".env.local" } },
    { ...deps, readFile: async (p) => (p === "/w/.env.local" ? Buffer.from(`# c\nexport DB_URL="postgres://x"\n`) : Buffer.alloc(0)) },
  );
  assert.equal(fromFile.reveal(), "postgres://x");
});

test("findDotenvValue handles quotes, comments and missing keys", () => {
  const text = "A=1 # note\nB='two words'\nC=\"x\\ny\"\n";
  assert.equal(findDotenvValue(text, "A"), "1");
  assert.equal(findDotenvValue(text, "B"), "two words");
  assert.equal(findDotenvValue(text, "C"), "x\ny");
  assert.equal(findDotenvValue(text, "D"), null);
});
