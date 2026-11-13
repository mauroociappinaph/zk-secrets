import assert from "node:assert/strict";
import { existsSync, linkSync, mkdirSync, readFileSync, realpathSync, symlinkSync, writeFileSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { test } from "node:test";
import { HELP_TEXT } from "../src/help.ts";
import { run } from "../src/run.ts";
import { CANARY, auditBytes, harness, parse, tempDir } from "./helpers.ts";

const NAME = "service-account-key.json";
const CONTENT = `{"private_key":"${CANARY}"}\n`;

/** A harness with one key file under cwd/keys; counts reads and unlinks of the real fs calls. */
function setup(options: { keychain?: Record<string, string>; approve?: boolean; content?: string | Buffer } = {}) {
  const h = harness({ keychain: options.keychain, approve: options.approve });
  // The project directory (cwd) is an allowed root only strictly inside the home directory.
  h.deps.home = dirname(h.dir);
  mkdirSync(join(h.dir, "keys"));
  const file = join(h.dir, "keys", NAME);
  writeFileSync(file, options.content ?? CONTENT);
  const io = h.deps.fileIo;
  const counts = { reads: 0, unlinks: 0 };
  h.deps.fileIo = {
    ...io,
    readNoFollow: (path, expected) => {
      counts.reads++;
      return io.readNoFollow(path, expected);
    },
    unlink: (path) => {
      counts.unlinks++;
      return io.unlink(path);
    },
  };
  return { h, file, real: realpathSync(file), counts };
}

const cmd = (path: string, store = "app/key") => ["capture", "file", "--store", store, path];

function records(h: ReturnType<typeof harness>) {
  const store = h.deps.openAudit();
  try {
    return store.list({ limit: 100 });
  } finally {
    store.close();
  }
}

async function assertNoContents(h: ReturnType<typeof harness>, stdout: string) {
  assert.ok(!stdout.includes(CANARY));
  const audit = await auditBytes(h.auditDb);
  assert.ok(!audit.includes(CANARY), "no contents in the audit");
  assert.ok(!audit.includes(NAME), "no path in the audit");
}

test("S1: stores the exact bytes after one dialog, deletes the file, reports metadata only", async () => {
  const { h, file, real, counts } = setup();
  const out = await run(cmd("keys/" + NAME), h.deps);
  assert.equal(out.exitCode, 0, out.stdout);
  const body = parse(out.stdout);
  assert.deepEqual(
    [body.ok, body.command, body.mode, body.store, body.length, body.fileDeleted],
    [true, "capture", "file", "app/key", Buffer.byteLength(CONTENT), true],
  );
  assert.equal(typeof body.auditId, "string");
  assert.ok("mirror" in body);
  assert.equal(h.keychain.store.get("app/key"), CONTENT, "stored exactly, trailing newline kept");
  assert.equal(existsSync(file), false, "the file was deleted");
  assert.deepEqual(h.human.approvals, [
    [`Store the file ${real} (${Buffer.byteLength(CONTENT)} bytes) in the Keychain item app/key?`, "zks deletes the file afterwards"],
  ]);
  assert.deepEqual(counts, { reads: 1, unlinks: 1 });
  await assertNoContents(h, out.stdout);
  const [record] = records(h);
  assert.deepEqual(
    [record!.provider, record!.action, record!.sourceKind, record!.environment, record!.result, record!.approval, record!.target],
    ["keychain", "capture", "capture-file", "", "applied", "dialog", "app/key"],
  );
});

test("S1: an absolute path inside ~/Downloads is allowed", async () => {
  const h = harness();
  mkdirSync(join(h.deps.home, "Downloads"));
  const file = join(h.deps.home, "Downloads", "AuthKey_ABC123.p8");
  writeFileSync(file, CANARY);
  const out = await run(cmd(file), h.deps);
  assert.equal(out.exitCode, 0, out.stdout);
  assert.equal(h.keychain.store.get("app/key"), CANARY);
  assert.equal(existsSync(file), false);
});

test("S1: a denial exits 3, reads nothing, keeps the file and is audited denied", async () => {
  const { h, file, counts } = setup({ approve: false });
  const out = await run(cmd(file), h.deps);
  assert.equal(out.exitCode, 3, out.stdout);
  const body = parse(out.stdout);
  assert.equal(body.error.code, "not_approved");
  assert.equal(body.error.message, "storing the file was not approved; the file was not read");
  assert.equal(h.human.approvals.length, 1);
  assert.deepEqual(counts, { reads: 0, unlinks: 0 });
  assert.equal(readFileSync(file, "utf8"), CONTENT);
  assert.equal(h.keychain.store.has("app/key"), false);
  const [record] = records(h);
  assert.deepEqual([record!.result, record!.errorCode, record!.sourceKind], ["denied", "not_approved", "capture-file"]);
  await assertNoContents(h, out.stdout);
});

test("S1: an existing item uses the replace wording in the single dialog", async () => {
  const { h, real } = setup({ keychain: { "app/key": "old" } });
  const out = await run(cmd("keys/" + NAME), h.deps);
  assert.equal(out.exitCode, 0, out.stdout);
  assert.equal(h.keychain.store.get("app/key"), CONTENT);
  assert.deepEqual(h.human.approvals, [
    ["Replace the Keychain item app/key?", `New value: the file ${real} (${Buffer.byteLength(CONTENT)} bytes), which zks then deletes`],
  ]);
});

test("S1: a denied replacement keeps the item and the file", async () => {
  const { h, file } = setup({ keychain: { "app/key": "old" }, approve: false });
  const out = await run(cmd(file), h.deps);
  assert.equal(out.exitCode, 3, out.stdout);
  assert.equal(parse(out.stdout).error.message, "replacing the Keychain item was not approved; the file was not read");
  assert.equal(h.keychain.store.get("app/key"), "old");
  assert.equal(readFileSync(file, "utf8"), CONTENT);
});

async function assertInvalid(h: ReturnType<typeof harness>, counts: { reads: number; unlinks: number }, argv: string[], code: string) {
  const out = await run(argv, h.deps);
  assert.equal(out.exitCode, 1, out.stdout);
  const body = parse(out.stdout);
  assert.equal(body.ok, false);
  assert.equal(body.error.code, code, out.stdout);
  assert.deepEqual(h.human.approvals, [], "no dialog");
  assert.deepEqual(counts, { reads: 0, unlinks: 0 }, "nothing read or deleted");
  assert.equal(h.keychain.store.has("app/key"), false);
  assert.ok(!out.stdout.includes(CANARY));
  return body;
}

test("S1: a symlink is refused, even to a file inside cwd, and both are kept", async () => {
  const { h, file, counts } = setup();
  const link = join(h.dir, "keys", "link.json");
  symlinkSync(file, link);
  await assertInvalid(h, counts, cmd(link), "file_invalid");
  assert.equal(readFileSync(file, "utf8"), CONTENT);
  assert.equal(existsSync(link), true);
});

test("S1: a directory is refused", async () => {
  const { h, counts } = setup();
  await assertInvalid(h, counts, cmd("keys"), "file_invalid");
});

test("S1: an empty file and a file over 64 KiB are refused and kept; exactly 64 KiB is stored", async () => {
  const { h, counts } = setup();
  const empty = join(h.dir, "keys", "empty.json");
  writeFileSync(empty, "");
  await assertInvalid(h, counts, cmd(empty), "file_invalid");
  const big = join(h.dir, "keys", "big.json");
  writeFileSync(big, Buffer.alloc(65537, 0x61));
  await assertInvalid(h, counts, cmd(big), "file_invalid");
  assert.equal(existsSync(empty) && existsSync(big), true);
  const max = join(h.dir, "keys", "max.json");
  writeFileSync(max, Buffer.alloc(65536, 0x61));
  const out = await run(cmd(max), h.deps);
  assert.equal(out.exitCode, 0, out.stdout);
  assert.equal(parse(out.stdout).length, 65536);
});

test("S1: paths outside ~/Downloads and cwd are refused, including .. escapes and a symlinked parent", async () => {
  const { h, counts } = setup();
  const other = tempDir();
  const outside = join(other, NAME);
  writeFileSync(outside, CONTENT);
  await assertInvalid(h, counts, cmd("/etc/hosts"), "file_invalid");
  await assertInvalid(h, counts, cmd(outside), "file_invalid");
  await assertInvalid(h, counts, cmd(relative(h.dir, outside)), "file_invalid");
  await assertInvalid(h, counts, cmd(`keys/../../${relative(join(h.dir, ".."), outside)}`), "file_invalid");
  // A directory symlink inside cwd that points outside: the parent is compared after realpath.
  symlinkSync(other, join(h.dir, "escape"));
  await assertInvalid(h, counts, cmd(`escape/${NAME}`), "file_invalid");
  // ~ itself is not ~/Downloads.
  const homeFile = join(h.deps.home, NAME);
  writeFileSync(homeFile, CONTENT);
  await assertInvalid(h, counts, cmd(homeFile), "file_invalid");
  assert.equal(readFileSync(outside, "utf8"), CONTENT);
  assert.equal(readFileSync(homeFile, "utf8"), CONTENT);
});

test("S1: a missing file is file_not_found", async () => {
  const { h, counts } = setup();
  const body = await assertInvalid(h, counts, cmd("keys/missing.json"), "file_not_found");
  assert.ok(body.error.message.includes("missing.json"));
  await assertInvalid(h, counts, cmd("nodir/missing.json"), "file_not_found");
});

test("S1: a failed Keychain write restores the previous item and keeps the file", async () => {
  const { h, file, counts } = setup({ keychain: { "app/key": "old" } });
  const set = h.deps.keychain.set.bind(h.deps.keychain);
  let calls = 0;
  h.deps.keychain.set = async (service, account, value) => {
    if (++calls === 1) throw new Error(`boom ${CANARY}`);
    return set(service, account, value);
  };
  const out = await run(cmd(file), h.deps);
  assert.equal(out.exitCode, 1, out.stdout);
  const body = parse(out.stdout);
  assert.equal(body.error.code, "keychain_failed");
  assert.equal(body.restored, true);
  assert.equal(h.keychain.store.get("app/key"), "old");
  assert.equal(readFileSync(file, "utf8"), CONTENT);
  assert.equal(counts.unlinks, 0);
  await assertNoContents(h, out.stdout);
});

test("S1: a failed write and a failed restore is restore_failed and keeps the file", async () => {
  const { h, file } = setup({ keychain: { "app/key": "old" } });
  h.deps.keychain.set = async () => {
    throw new Error(`boom ${CANARY}`);
  };
  const out = await run(cmd(file), h.deps);
  assert.equal(out.exitCode, 1, out.stdout);
  assert.equal(parse(out.stdout).error.code, "restore_failed");
  assert.equal(readFileSync(file, "utf8"), CONTENT);
  await assertNoContents(h, out.stdout);
});

test("S1: a failed write of a new item is keychain_failed and keeps the file", async () => {
  const { h, file } = setup();
  h.deps.keychain.set = async () => {
    throw new Error("denied");
  };
  const out = await run(cmd(file), h.deps);
  assert.equal(out.exitCode, 1, out.stdout);
  assert.equal(parse(out.stdout).error.code, "keychain_failed");
  assert.equal(readFileSync(file, "utf8"), CONTENT);
});

test("S1: a failed unlink is fileDeleted false, still exit 0 with the item stored", async () => {
  const { h, file } = setup();
  h.deps.fileIo = {
    ...h.deps.fileIo,
    unlink: async () => {
      throw Object.assign(new Error("EPERM"), { code: "EPERM" });
    },
  };
  const out = await run(cmd(file), h.deps);
  assert.equal(out.exitCode, 0, out.stdout);
  assert.equal(parse(out.stdout).fileDeleted, false);
  assert.equal(h.keychain.store.get("app/key"), CONTENT);
  assert.equal(existsSync(file), true);
});

test("S1: a file that is not UTF-8 text is refused after the read and kept", async () => {
  const { h, file } = setup({ content: Buffer.from([0xff, 0xfe, 0x00, 0x80]) });
  const out = await run(cmd(file), h.deps);
  assert.equal(out.exitCode, 1, out.stdout);
  assert.equal(parse(out.stdout).error.code, "file_invalid");
  assert.equal(h.keychain.store.has("app/key"), false);
  assert.equal(existsSync(file), true);
});

test("S1: usage — needs --store and PATH, refuses the zks service, other flags and extra arguments", async () => {
  const { h, file, counts } = setup();
  for (const argv of [
    ["capture", "file", file],
    ["capture", "file", "--store", "app/key"],
    cmd(file, "zks/vercel"),
    cmd(file, "ZKS/github"),
    [...cmd(file), "--origin", "https://x.com"],
    [...cmd(file), "extra"],
    cmd("keys/a\nb"),
  ]) {
    const out = await run(argv, h.deps);
    assert.equal(out.exitCode, 2, `${argv.join(" ")}: ${out.stdout}`);
    assert.equal(parse(out.stdout).error.code, "usage");
  }
  assert.deepEqual(h.human.approvals, []);
  assert.deepEqual(counts, { reads: 0, unlinks: 0 });
  assert.equal(h.keychain.store.size, 0);
  assert.equal(readFileSync(file, "utf8"), CONTENT);
});

test("S1: a path too long for one dialog line is refused before the dialog and the file is kept", async () => {
  const { h, counts } = setup();
  const deep = join(h.dir, "keys", "d".repeat(200));
  mkdirSync(deep);
  const file = join(deep, NAME);
  writeFileSync(file, CONTENT);
  const out = await run(cmd(file), h.deps);
  assert.equal(out.exitCode, 2, out.stdout);
  assert.equal(parse(out.stdout).error.code, "dialog_too_long");
  assert.deepEqual(h.human.approvals, []);
  assert.deepEqual(counts, { reads: 0, unlinks: 0 });
  assert.equal(readFileSync(file, "utf8"), CONTENT);
});

test("S1: a file capture records no origin, so fill --from always asks", async () => {
  const { h, file } = setup();
  assert.equal((await run(cmd(file), h.deps)).exitCode, 0);
  assert.equal(h.human.approvals.length, 1);
  await run(["capture", "fill", "--space", "1", "--page", "p1", "--selector", "#p", "--from", "app/key", "--origin", "https://x.com"], h.deps);
  assert.equal(h.human.approvals.length, 2, "the fill asked too");
});

test("S1 preserve: capture clipboard still takes no PATH argument", async () => {
  const { h, file } = setup();
  const out = await run(["capture", "clipboard", "--store", "app/key", file], h.deps);
  assert.equal(out.exitCode, 2, out.stdout);
  assert.equal(parse(out.stdout).error.message, "unexpected argument");
  assert.deepEqual(h.exec.calls, []);
});

test("S1: help lists capture file", () => {
  assert.ok(HELP_TEXT.includes("zks capture file --store SERVICE/ACCOUNT PATH"));
});

test("S1/L4: a cwd that is the home directory, or above it, is not an allowed root", async () => {
  const h = harness();
  writeFileSync(join(h.dir, "id_ed25519"), CANARY);
  for (const home of [h.dir, join(h.dir, "nested-home")]) {
    h.deps.home = home;
    const out = await run(cmd("id_ed25519"), h.deps);
    assert.equal(out.exitCode, 1, out.stdout);
    assert.equal(parse(out.stdout).error.code, "file_invalid");
  }
  assert.equal(existsSync(join(h.dir, "id_ed25519")), true);
  assert.deepEqual(h.human.approvals, []);
});

test("S1/L4: a file inside a hidden directory is refused, in the project and in ~/Downloads", async () => {
  const { h } = setup();
  mkdirSync(join(h.dir, ".ssh"));
  writeFileSync(join(h.dir, ".ssh", "id_ed25519"), CANARY);
  const project = await run(cmd(".ssh/id_ed25519"), h.deps);
  assert.equal(project.exitCode, 1, project.stdout);
  assert.equal(parse(project.stdout).error.code, "file_invalid");

  const d = harness();
  mkdirSync(join(d.deps.home, "Downloads", ".hidden"), { recursive: true });
  const hidden = join(d.deps.home, "Downloads", ".hidden", "key.p8");
  writeFileSync(hidden, CANARY);
  const downloads = await run(cmd(hidden), d.deps);
  assert.equal(downloads.exitCode, 1, downloads.stdout);
  assert.equal(parse(downloads.stdout).error.code, "file_invalid");
  assert.equal(existsSync(hidden), true);
  assert.deepEqual([...h.human.approvals, ...d.human.approvals], []);
});

test("S1/L4: a project directory inside a hidden directory is not an allowed root", async () => {
  for (const sub of [".keysdir", join(".cfg", "proj")]) {
    const h = harness({ approve: true });
    const home = realpathSync(tempDir());
    h.deps.home = home;
    mkdirSync(join(home, sub), { recursive: true });
    const file = join(home, sub, "id_key");
    writeFileSync(file, CANARY);
    h.deps.cwd = join(home, sub);
    const out = await run(["capture", "file", "--store", "app/key", "id_key"], h.deps);
    assert.equal(out.exitCode, 1, sub);
    assert.equal(parse(out.stdout).error.code, "file_invalid");
    assert.equal(h.human.approvals.length, 0);
    assert.equal(h.keychain.store.has("app/key"), false);
    assert.equal(readFileSync(file, "utf8"), CANARY);
  }
});

test("S1/L7: a file with another hard link is refused and kept", async () => {
  const { h, file } = setup({ approve: true });
  linkSync(file, join(h.dir, "keys", "second-name.json"));
  const out = await run(cmd("keys/" + NAME), h.deps);
  assert.equal(out.exitCode, 1, out.stdout);
  assert.equal(parse(out.stdout).error.code, "file_invalid");
  assert.deepEqual(h.human.approvals, []);
  assert.equal(existsSync(file), true);
});
