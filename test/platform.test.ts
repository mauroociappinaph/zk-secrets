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

/** What `security find-generic-password -g` prints on stderr: quoted when printable, else 0x-hex. */
function securityG(value: string): Buffer {
  // Real security -g: only a backslash or a non-printable byte forces hex; quotes stay raw.
  const printable = /^[\x20-\x7e]*$/.test(value) && !/\\/.test(value);
  const line = printable ? `password: "${value}"` : `password: 0x${Buffer.from(value, "utf8").toString("hex").toUpperCase()}  "..."`;
  return Buffer.from(`${line}\n`);
}

test("keychain get returns the exact bytes of non-ASCII, quote/backslash, hex-looking and empty values", async () => {
  for (const value of ["contrase\u00f1a", 'abc"d\\e', "deadbeef", "a b", "", "line1\nline2"]) {
    const keychain = createKeychain(fakeExec(() => ({ stdout: Buffer.from("attributes:\n"), stderr: securityG(value) })).exec);
    assert.equal((await keychain.get("svc", "acct"))?.reveal(), value, JSON.stringify(value));
  }
});

test("keychain get parses real -g shapes: raw quotes, empty, trailing-space hex, attribute lines ignored", async () => {
  const cases: Array<[string, string]> = [
    ['password: "password: "x""\n', 'password: "x"'],
    ['password: """"\n', '""'],
    ["password: \n", ""],
    ["password: 0x7F \n", "\x7f"],
    ['password: 0x610962  "a\\011b"\n', "a\tb"],
  ];
  for (const [stderr, want] of cases) {
    const stdout = Buffer.from('    0x00000007 <blob>="password: \\"fake\\""\n');
    const kc = createKeychain(fakeExec(() => ({ stdout, stderr: Buffer.from(stderr) })).exec);
    assert.equal((await kc.get("svc", "acct"))?.reveal(), want, stderr);
  }
});

test("keychain get fails closed on an unparsable password line", async () => {
  for (const stderr of ["", "password: 0xZZ\n", "password: abc\n", 'password: "unterminated\n']) {
    const keychain = createKeychain(fakeExec(() => ({ stderr: Buffer.from(stderr) })).exec);
    await assert.rejects(keychain.get("svc", "acct"), /keychain read failed for svc\/acct \(unparsable output\)/, stderr);
  }
});

test("keychain reads with -g, writes through security -i stdin as hex, never argv", async () => {
  const f = fakeExec((call) => (call.args[0] === "find-generic-password" ? { stderr: securityG(CANARY) } : {}));
  const keychain = createKeychain(f.exec);

  assert.equal((await keychain.get("zks", "vercel"))?.reveal(), CANARY);
  await keychain.set("zks", "vercel", SecretBuffer.fromString(CANARY));

  assert.deepEqual(f.calls[0]?.args, ["find-generic-password", "-s", "zks", "-a", "vercel", "-g"]);
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

test("keychain modifiedAt parses mdat from attributes only", async () => {
  const { parseKeychainDate } = await import("../src/platform/keychain.ts");
  const attrs = '    "mdat"<timedate>=0x32303236313130343137353330325A00  "20261104175302Z\\000"\n';
  assert.equal(parseKeychainDate(attrs)?.toISOString(), "2026-11-04T17:53:02.000Z");
  assert.equal(parseKeychainDate("no dates here"), null);
  const f = fakeExec(() => ({ stdout: Buffer.from(attrs) }));
  assert.equal((await createKeychain(f.exec).modifiedAt("svc", "acct"))?.toISOString(), "2026-11-04T17:53:02.000Z");
  assert.deepEqual(f.calls[0]?.args, ["find-generic-password", "-s", "svc", "-a", "acct"]);
});
