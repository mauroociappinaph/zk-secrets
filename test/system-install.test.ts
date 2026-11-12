import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
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

/** The AGENTS_UPDATE script install.sh runs as the user (never as root) to write ~/AGENTS.md. */
function agentsUpdate(file: string, block: string) {
  const source = readFileSync(join(REPO, "install.sh"), "utf8");
  const start = source.indexOf("AGENTS_UPDATE='");
  const end = source.indexOf("\nfi'\n", start) + "\nfi'\n".length;
  const script = `${source.slice(start, end)}\nprintf '%s' "$BLOCK" | /bin/sh -c "$AGENTS_UPDATE" sh "$1" '<!-- zks:begin -->' '<!-- zks:end -->'\n`;
  return spawnSync("/bin/sh", ["-c", script, "sh", file], { env: { PATH: "/usr/bin:/bin", BLOCK: block }, encoding: "utf8" });
}

test("v2 S1 (review R1): install.sh writes ~/AGENTS.md only through the user-run AGENTS_UPDATE script", () => {
  const source = readFileSync(join(REPO, "install.sh"), "utf8");
  assert.match(source, /^as_user \/bin\/sh -c "\$AGENTS_UPDATE" sh "\$AGENTS" "\$BEGIN_MARK" "\$END_MARK" <<'EOF'$/m);
  const start = source.indexOf("AGENTS_UPDATE='");
  const outside = source.slice(0, start) + source.slice(source.indexOf("\nfi'\n", start));
  assert.equal(outside.match(/>>?\s*"\$AGENTS"|cp [^\n]*"\$AGENTS"/g)?.length ?? 0, 0, "no root-shell write to $AGENTS outside the script");
  assert.doesNotMatch(source, /chown "\$USER_NAME" "\$AGENTS"/);

  const dir = mkdtempSync(join(tmpdir(), "zks-agents-"));
  const block = "<!-- zks:begin -->\nNEW\n<!-- zks:end -->\n";
  const fresh = join(dir, "a.md");
  assert.equal(agentsUpdate(fresh, block).status, 0);
  assert.equal(readFileSync(fresh, "utf8"), block);

  const append = join(dir, "b.md");
  writeFileSync(append, "hello");
  assert.equal(agentsUpdate(append, block).status, 0);
  assert.equal(readFileSync(append, "utf8"), `hello\n\n${block}`);

  const replace = join(dir, "c.md");
  writeFileSync(replace, "x\n<!-- zks:begin -->\nOLD\n<!-- zks:end -->\ny\n");
  assert.equal(agentsUpdate(replace, block).status, 0);
  assert.equal(readFileSync(replace, "utf8"), `x\n${block}y\n`);

  const broken = join(dir, "d.md");
  writeFileSync(broken, "<!-- zks:begin -->\nno end\n");
  const r = agentsUpdate(broken, block);
  assert.equal(r.status, 1);
  assert.equal(r.stderr, `install.sh: ${broken} has <!-- zks:begin --> without <!-- zks:end -->; fix it by hand\n`);
  assert.equal(readFileSync(broken, "utf8"), "<!-- zks:begin -->\nno end\n");
});

test("v2 S1 (review R3): the production install creates no node_modules/.bin symlinks", () => {
  const source = readFileSync(join(REPO, "install.sh"), "utf8");
  assert.match(source, /\(cd "\$DEST" && npm ci --omit=dev --ignore-scripts --no-bin-links\)/);
});
