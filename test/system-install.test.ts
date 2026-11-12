import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { test } from "node:test";
import { checkOwnership } from "../src/platform/integrity.ts";
import { SYSTEM_LIBEXEC, installLayout } from "../src/platform/paths.ts";

const REPO = join(import.meta.dirname, "..");

function install(args: string[]) {
  const r = spawnSync("/bin/sh", ["install.sh", ...args], {
    cwd: REPO,
    env: { PATH: process.env.PATH ?? "/usr/bin:/bin", HOME: process.env.HOME ?? "/tmp" },
    encoding: "utf8",
  });
  return { code: r.status, stdout: r.stdout, stderr: r.stderr };
}

test("v2 S1: an app under /usr/local/libexec/zks is a system install with a root-owned integrity manifest", () => {
  assert.equal(SYSTEM_LIBEXEC, "/usr/local/libexec/zks");
  assert.deepEqual(installLayout("/usr/local/libexec/zks/0.2.0", "/Users/u"), {
    mode: "system",
    integrityFile: "/usr/local/libexec/zks/integrity.json",
  });
  assert.deepEqual(installLayout("/Users/u/.local/libexec/zks/0.2.0", "/Users/u"), {
    mode: "user",
    integrityFile: "/Users/u/.config/zks/integrity.json",
  });
  // A look-alike prefix is not the system install.
  assert.equal(installLayout("/usr/local/libexec/zks-evil/0.2.0", "/Users/u").mode, "user");
});

type FakeStat = { uid: number; mode: number; kind: "file" | "dir" | "symlink" };
function fakeTree(entries: Record<string, FakeStat>) {
  return {
    lstat: (path: string) => {
      const e = entries[path];
      if (!e) throw new Error(`ENOENT ${path}`);
      return { uid: e.uid, mode: e.mode, isDirectory: () => e.kind === "dir", isSymbolicLink: () => e.kind === "symlink" };
    },
    readdir: (path: string) =>
      Object.keys(entries)
        .filter((p) => p !== path && p.startsWith(`${path}/`) && !p.slice(path.length + 1).includes("/"))
        .map((p) => p.slice(path.length + 1)),
  };
}

test("v2 S1: ownership check passes only when every entry is root-owned and not group/other writable", () => {
  const ok = fakeTree({
    "/r": { uid: 0, mode: 0o555, kind: "dir" },
    "/r/dist": { uid: 0, mode: 0o555, kind: "dir" },
    "/r/dist/cli.js": { uid: 0, mode: 0o444, kind: "file" },
  });
  assert.deepEqual(checkOwnership("/r", ok), { ok: true, issues: [] });

  const bad = fakeTree({
    "/r": { uid: 0, mode: 0o555, kind: "dir" },
    "/r/a.js": { uid: 501, mode: 0o444, kind: "file" },
    "/r/b.js": { uid: 0, mode: 0o664, kind: "file" },
    "/r/c": { uid: 0, mode: 0o777, kind: "symlink" },
    "/r/d": { uid: 0, mode: 0o757, kind: "dir" },
  });
  assert.deepEqual(checkOwnership("/r", bad), {
    ok: false,
    issues: [
      { path: "a.js", code: "not_root_owned" },
      { path: "b.js", code: "writable_by_group_or_other" },
      { path: "c", code: "symlink" },
      { path: "d", code: "writable_by_group_or_other" },
    ],
  });
  assert.deepEqual(checkOwnership("/missing", bad), { ok: false, issues: [{ path: ".", code: "unreadable" }] });
});

test("v2 S1: install.sh --system refuses to run without root and writes nothing", { skip: process.getuid?.() === 0 }, () => {
  const r = install(["--system"]);
  assert.equal(r.code, 1);
  assert.equal(r.stdout, "");
  assert.equal(r.stderr, "install.sh: --system installs as root: run sudo ./install.sh --system\n");
});

test("v2 S1: install.sh --system --dry-run prints the root-owned layout and writes nothing", { skip: process.getuid?.() === 0 }, () => {
  const r = install(["--system", "--dry-run"]);
  assert.equal(r.code, 0, r.stderr);
  assert.match(r.stdout, /^mode: system$/m);
  assert.match(r.stdout, /^app: \/usr\/local\/libexec\/zks\/\d+\.\d+\.\d+ \(root:wheel, read-only, with its own copy of node\)$/m);
  assert.match(r.stdout, /^launcher: \/usr\/local\/libexec\/zks\/bin\/zks \(root:wheel, 555\)$/m);
  assert.match(r.stdout, /^path: \/etc\/paths\.d\/zks \(root:wheel, 644\)$/m);
  assert.match(r.stdout, /^integrity: \/usr\/local\/libexec\/zks\/integrity\.json \(root:wheel, 444\)$/m);
  assert.match(r.stdout, /^user launcher: .*\/\.local\/bin\/zks \(removed if present\)$/m);
  assert.equal(r.stderr, "");
});

test("v2 S1: install.sh --dry-run without --system prints the user layout; an unknown option fails", () => {
  const r = install(["--dry-run"]);
  assert.equal(r.code, 0, r.stderr);
  assert.match(r.stdout, /^mode: user$/m);
  assert.match(r.stdout, /^app: .*\/\.local\/libexec\/zks\/\d+\.\d+\.\d+ /m);

  const bad = install(["--bogus"]);
  assert.equal(bad.code, 1);
  assert.equal(bad.stdout, "");
  assert.equal(bad.stderr, "install.sh: unknown option --bogus (use --system and/or --dry-run)\n");
});
