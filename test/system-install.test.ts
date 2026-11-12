import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { type TestContext, test } from "node:test";
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

/**
 * Runs the install.sh slice that defines NPM_CLI and isolated_npm plus one `isolated_npm` call line
 * under /bin/sh, with $NODE_BIN a fake node that records its env, argv and working directory.
 */
function isolatedNpmStep(t: TestContext, callPrefix: string) {
  const source = readFileSync(join(REPO, "install.sh"), "utf8");
  const start = source.indexOf("NPM_CLI=");
  const fnEnd = source.indexOf("\n}\n", source.indexOf("isolated_npm() {", start)) + "\n}\n".length;
  const callStart = source.indexOf(`\n${callPrefix} `, fnEnd) + 1;
  const callEnd = source.indexOf("\n", callStart);
  assert.ok(start > 0 && fnEnd > start && callStart > fnEnd && callEnd > callStart, `install.sh has NPM_CLI, isolated_npm and ${callPrefix}`);
  const dir = mkdtempSync(join(tmpdir(), "zks-npmstep-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const fake = join(dir, "fakebin");
  const dest = join(dir, "dest");
  const repo = join(dir, "repo");
  const tmp = join(dir, "tmp");
  const buildTmp = join(dir, "buildtmp");
  spawnSync("/bin/mkdir", ["-p", fake, dest, repo, tmp, buildTmp, join(dir, "nodebin")]);
  // npm on PATH is a symlink (as in real installs); $NODE_BIN is a fake node that records env, argv and cwd.
  writeFileSync(join(fake, "npm-cli.js"), "", { mode: 0o755 });
  spawnSync("/bin/ln", ["-s", join(fake, "npm-cli.js"), join(fake, "npm")]);
  const nodeBin = join(dir, "nodebin", "node");
  writeFileSync(nodeBin, `#!/bin/sh\n/usr/bin/env >"${dir}/env"\nprintf '%s\\n' "$@" >"${dir}/argv"\npwd -P >"${dir}/cwd"\n`, { mode: 0o755 });
  // as_user stands in for sudo -u: it records the command it was given and runs it as is.
  const script = [
    "set -eu",
    `REPO="${repo}"; DEST="${dest}"; TMP_DIR="${tmp}"; BUILD_TMP="${buildTmp}"; SAFE_PATH=/usr/bin:/bin; NODE_BIN="${nodeBin}"`,
    `as_user() { printf '%s\\n' "$1" >>"${dir}/as_user"; "$@"; }`,
    source.slice(start, fnEnd) + source.slice(callStart, callEnd),
    "",
  ].join("\n");
  const r = spawnSync("/bin/sh", ["-c", script], {
    env: { PATH: `${fake}:${process.execPath.replace(/\/node$/, "")}:/usr/bin:/bin`, HOME: "/nonexistent-user-home" },
    encoding: "utf8",
  });
  assert.equal(r.status, 0, r.stderr);
  const read = (name: string) => (existsSync(join(dir, name)) ? readFileSync(join(dir, name), "utf8") : "");
  const env = Object.fromEntries(
    read("env").trim().split("\n").map((l) => [l.slice(0, l.indexOf("=")), l.slice(l.indexOf("=") + 1)]),
  );
  return {
    env,
    argv: read("argv").trim().split("\n"),
    cwd: read("cwd").trim(),
    asUser: read("as_user").trim().split("\n").filter(Boolean),
    npmCli: realpathSync(join(fake, "npm-cli.js")),
    nodeDir: join(dir, "nodebin"),
    dest: realpathSync(dest),
    repo: realpathSync(repo),
    tmp,
    buildTmp,
  };
}

function assertIsolatedEnv(step: ReturnType<typeof isolatedNpmStep>, scratch: string) {
  const { env } = step;
  // PWD, SHLVL and _ are set by the fake node's own /bin/sh, not passed by env -i.
  assert.deepEqual(Object.keys(env).filter((k) => !["PWD", "SHLVL", "_"].includes(k)).sort(), [
    "HOME",
    "PATH",
    "npm_config_cache",
    "npm_config_globalconfig",
    "npm_config_logs_dir",
    "npm_config_update_notifier",
    "npm_config_userconfig",
  ]);
  assert.equal(env.HOME, scratch);
  assert.equal(env.PATH, `${step.nodeDir}:/usr/bin:/bin`);
  assert.equal(env.npm_config_userconfig, "/dev/null");
  assert.equal(env.npm_config_globalconfig, join(scratch, "globalnpmrc"));
  assert.equal(readFileSync(join(scratch, "globalnpmrc"), "utf8"), "");
  assert.equal(env.npm_config_cache, join(scratch, "npm-cache"));
  assert.equal(env.npm_config_logs_dir, join(scratch, "npm-logs"));
  assert.equal(env.npm_config_update_notifier, "false");
  assert.ok(!Object.values(env).some((v) => v.includes("/nonexistent-user-home")));
}

test("v2 S1 (review R3, verify L11/B1): the root npm ci runs under $NODE_BIN with an isolated env and no bin links", (t) => {
  const step = isolatedNpmStep(t, 'isolated_npm command "$TMP_DIR"');
  assertIsolatedEnv(step, step.tmp);
  assert.deepEqual(step.argv, [step.npmCli, "ci", "--omit=dev", "--ignore-scripts", "--no-bin-links"]);
  assert.equal(step.cwd, step.dest);
  assert.deepEqual(step.asUser, [], "the production npm ci does not run through as_user");
  assert.ok(!existsSync(join(step.buildTmp, "globalnpmrc")), "the production step does not touch the build scratch");
});

test("v2 S1 (review R3-npm-ci-env-isolation-user-mode): the build npm ci runs as the user under $NODE_BIN with an isolated env", (t) => {
  const step = isolatedNpmStep(t, 'isolated_npm as_user "$BUILD_TMP"');
  assertIsolatedEnv(step, step.buildTmp);
  assert.deepEqual(step.argv, [step.npmCli, "ci"]);
  assert.equal(step.cwd, step.repo);
  assert.ok(step.asUser.includes("/usr/bin/env"), "the build npm ci runs through as_user");
  assert.ok(!existsSync(join(step.tmp, "globalnpmrc")), "the build step does not use the root-owned scratch");
  const source = readFileSync(join(REPO, "install.sh"), "utf8");
  assert.doesNotMatch(source, /^as_user npm ci\b/m, "no build npm ci with the user's npm config");
});
