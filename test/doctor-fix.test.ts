import assert from "node:assert/strict";
import { chmodSync, lstatSync, mkdirSync, readFileSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { fixPermissions } from "../src/platform/permissions.ts";
import { zksPaths } from "../src/platform/paths.ts";
import { run } from "../src/run.ts";
import { harness, parse, tempDir } from "./helpers.ts";

const mode = (path: string) => lstatSync(path).mode & 0o777;

// S10 — zks doctor --fix

const unhealthy = {
  version: "0.0.0-test",
  install: { root: "/app", mode: "user", status: "modified" },
  tools: { source: "tools.json", pins: { "ego-browser": "ok", gh: "changed", op: "missing" } },
  tokens: { vercel: true, railway: false, supabase: true, "sheets-hmac": false },
  audit: { path: "/s/audit.db", ok: false, count: 3, brokenAt: "X", anchored: true },
  mirror: { sheetsWebhook: false },
  trust: "invalid",
  trustedDestinations: 0,
};

test("S10: doctor --fix repairs permissions first, then reports what it cannot fix with the command to run", async () => {
  const h = harness();
  const order: string[] = [];
  h.deps.fixPermissions = async () => {
    order.push("fix");
    return { fixed: ["chmod 600 /h/.config/zks/config.json"], failed: [{ path: "/h/.config/zks/trust.json", reason: "symlink" }] };
  };
  h.deps.doctor = async () => {
    order.push("doctor");
    return structuredClone(unhealthy);
  };
  const out = await run(["doctor", "--fix"], h.deps);
  assert.equal(out.exitCode, 0, out.stdout);
  assert.deepEqual(order, ["fix", "doctor"]);
  assert.deepEqual(parse(out.stdout), {
    ok: true,
    ...unhealthy,
    fixed: ["chmod 600 /h/.config/zks/config.json"],
    notFixable: [
      { check: "permissions /h/.config/zks/trust.json", status: "symlink", command: "ls -l /h/.config/zks/trust.json" },
      { check: "install", status: "modified", command: "./install.sh" },
      { check: "tools.pins.gh", status: "changed", command: "./install.sh" },
      { check: "trust", status: "invalid", command: "zks trust list, then choose Always allow in the next apply to sign trust.json again" },
      { check: "audit", status: "broken", command: "zks audit verify" },
      { check: "tokens.railway", status: "missing", command: "zks auth set railway" },
    ],
  });
});

test("S10: a system install is reinstalled with sudo; a healthy report has nothing to fix", async () => {
  const h = harness();
  let fixes = 0;
  h.deps.fixPermissions = async () => {
    fixes++;
    return { fixed: [], failed: [] };
  };
  h.deps.doctor = async () => ({
    ...structuredClone(unhealthy),
    install: { root: "/usr/local/libexec/zks/0.1.0", mode: "system", status: "ownership" },
    tools: { pins: { gh: "ok" } },
    tokens: { vercel: true, railway: true, supabase: true, "sheets-hmac": false },
    audit: { ok: true, count: 0 },
    trust: "ok",
  });
  const body = parse((await run(["doctor", "--fix"], h.deps)).stdout);
  assert.equal(fixes, 1);
  assert.deepEqual(body.fixed, []);
  assert.deepEqual(body.notFixable, [{ check: "install", status: "ownership", command: "sudo ./install.sh --system" }]);
});

test("S10: doctor without --fix is unchanged and never fixes anything", async () => {
  const h = harness();
  let fixes = 0;
  h.deps.fixPermissions = async () => {
    fixes++;
    return { fixed: [], failed: [] };
  };
  const out = await run(["doctor"], h.deps);
  assert.equal(out.exitCode, 0);
  assert.deepEqual(parse(out.stdout), { ok: true, doctor: "fake" });
  assert.equal(fixes, 0);
  const valued = await run(["doctor", "--fix=yes"], h.deps);
  assert.equal(valued.exitCode, 2);
  assert.deepEqual(parse(valued.stdout).error, { code: "usage", message: "option --fix takes no value" });
  assert.equal(parse((await run(["plan", "--fix"], h.deps)).stdout).error.message, "option --fix is not valid for plan");
  assert.equal(fixes, 0);
});

test("S10: fixPermissions creates missing zks directories with 700", async () => {
  const home = tempDir();
  const paths = zksPaths(home);
  const report = await fixPermissions(paths);
  assert.deepEqual(report, { fixed: [`mkdir -m 700 ${paths.configDir}`, `mkdir -m 700 ${paths.stateDir}`], failed: [] });
  assert.equal(mode(paths.configDir), 0o700);
  assert.equal(mode(paths.stateDir), 0o700);
  assert.deepEqual(await fixPermissions(paths), { fixed: [], failed: [] });
});

test("S10: fixPermissions chmods zks files to 600 and directories to 700, never following symlinks", async () => {
  const home = tempDir();
  const paths = zksPaths(home);
  mkdirSync(paths.configDir, { recursive: true, mode: 0o755 });
  mkdirSync(paths.stateDir, { recursive: true, mode: 0o700 });
  chmodSync(paths.configDir, 0o755);
  writeFileSync(paths.configFile, "{}\n", { mode: 0o644 });
  chmodSync(paths.configFile, 0o644);
  const outside = join(home, "outside.json");
  writeFileSync(outside, "keep\n", { mode: 0o644 });
  chmodSync(outside, 0o644);
  symlinkSync(outside, paths.trustFile);
  for (const [suffix, m] of [["", 0o600], ["-wal", 0o666], ["-shm", 0o640]] as const) {
    writeFileSync(paths.auditDb + suffix, "x", { mode: m });
    chmodSync(paths.auditDb + suffix, m);
  }
  const integrity = join(paths.configDir, "integrity.json");
  writeFileSync(integrity, "{}", { mode: 0o644 });
  chmodSync(integrity, 0o644);

  const report = await fixPermissions(paths);
  assert.deepEqual(report, {
    fixed: [`chmod 700 ${paths.configDir}`, `chmod 600 ${paths.configFile}`, `chmod 600 ${paths.auditDb}-wal`, `chmod 600 ${paths.auditDb}-shm`],
    failed: [{ path: paths.trustFile, reason: "symlink" }],
  });
  assert.equal(mode(paths.configDir), 0o700);
  assert.equal(mode(paths.configFile), 0o600);
  assert.equal(mode(`${paths.auditDb}-wal`), 0o600);
  assert.equal(mode(`${paths.auditDb}-shm`), 0o600);
  assert.equal(statSync(outside).mode & 0o777, 0o644, "the symlink target must not change");
  assert.equal(readFileSync(outside, "utf8"), "keep\n");
  assert.equal(mode(integrity), 0o644, "integrity.json is never touched");
  assert.deepEqual(await fixPermissions(paths), { fixed: [], failed: [{ path: paths.trustFile, reason: "symlink" }] });
});

test("S10: a zks directory that is a symlink is reported, not followed", async () => {
  const home = tempDir();
  const paths = zksPaths(home);
  const elsewhere = join(home, "elsewhere");
  mkdirSync(elsewhere, { mode: 0o755 });
  chmodSync(elsewhere, 0o755);
  mkdirSync(join(home, ".config"), { mode: 0o700 });
  symlinkSync(elsewhere, paths.configDir);
  const report = await fixPermissions(paths);
  assert.deepEqual(report.failed, [{ path: paths.configDir, reason: "symlink" }]);
  assert.equal(statSync(elsewhere).mode & 0o777, 0o755);
});
