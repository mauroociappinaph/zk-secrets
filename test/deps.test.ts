import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

const SCRIPT = join(import.meta.dirname, "..", "scripts", "deps-check.ts");

type Fixture = { pkg: unknown; lock: unknown; audit: string; auditExit?: number };

function lockFor(deps: Record<string, string>, devDeps: Record<string, string> = {}, lockfileVersion = 3) {
  return { name: "x", lockfileVersion, packages: { "": { name: "x", dependencies: deps, devDependencies: devDeps } } };
}

const CLEAN_AUDIT = JSON.stringify({
  auditReportVersion: 2,
  vulnerabilities: {},
  metadata: { vulnerabilities: { info: 0, low: 0, moderate: 0, high: 0, critical: 0, total: 0 } },
});

function auditWith(counts: Partial<Record<"low" | "moderate" | "high" | "critical", number>>) {
  const v = { info: 0, low: 0, moderate: 0, high: 0, critical: 0, ...counts };
  return JSON.stringify({ auditReportVersion: 2, vulnerabilities: {}, metadata: { vulnerabilities: { ...v, total: 1 } } });
}

/** Runs scripts/deps-check.ts in a temp project whose `npm audit --json` is a fake that prints `audit`. */
function runCheck(fixture: Fixture, args: string[] = []) {
  const dir = mkdtempSync(join(tmpdir(), "zks-deps-"));
  writeFileSync(join(dir, "package.json"), JSON.stringify(fixture.pkg));
  writeFileSync(join(dir, "package-lock.json"), JSON.stringify(fixture.lock));
  const fakeNpm = join(dir, "npm");
  writeFileSync(join(dir, "audit.json"), fixture.audit);
  writeFileSync(fakeNpm, `#!/bin/sh\ncat "${join(dir, "audit.json")}"\nexit ${fixture.auditExit ?? 0}\n`, { mode: 0o755 });
  const result = spawnSync(process.execPath, ["--disable-warning=ExperimentalWarning", SCRIPT, ...args], {
    cwd: dir,
    env: { PATH: "/usr/bin:/bin", ZKS_NPM: fakeNpm },
    encoding: "utf8",
  });
  return { code: result.status, stdout: result.stdout, stderr: result.stderr, json: result.stdout ? JSON.parse(result.stdout) : null };
}

const PINNED_PKG = { name: "x", dependencies: { a: "1.2.3" }, devDependencies: { b: "4.5.6" } };

test("S4: pinned dependencies, matching lockfile and a clean audit pass", () => {
  const r = runCheck({ pkg: PINNED_PKG, lock: lockFor({ a: "1.2.3" }, { b: "4.5.6" }), audit: CLEAN_AUDIT });
  assert.equal(r.code, 0, r.stderr);
  assert.equal(r.stderr, "");
  assert.deepEqual(r.json, { ok: true, pinned: { ok: true, issues: [] }, audit: { status: "ok", high: 0, critical: 0 } });
});

test("S4: a range specifier in package.json fails as not_pinned", () => {
  for (const range of ["^1.2.3", "~1.2.3", ">=1", "*", "latest", "1.x", "1.2.3 - 2.0.0", "git+https://x/y"]) {
    const pkg = { name: "x", dependencies: { a: range } };
    const r = runCheck({ pkg, lock: lockFor({ a: range }), audit: CLEAN_AUDIT });
    assert.equal(r.code, 1, range);
    assert.equal(r.json.ok, false, range);
    assert.deepEqual(r.json.pinned.issues, [{ code: "not_pinned", name: "a", spec: range }], range);
  }
});

test("S4: a lockfile that disagrees with package.json or is older than v3 fails", () => {
  const drift = runCheck({ pkg: PINNED_PKG, lock: lockFor({ a: "1.2.4" }, { b: "4.5.6" }), audit: CLEAN_AUDIT });
  assert.equal(drift.code, 1);
  assert.deepEqual(drift.json.pinned.issues, [{ code: "lockfile_mismatch", name: "a", spec: "1.2.3", locked: "1.2.4" }]);

  const old = runCheck({ pkg: PINNED_PKG, lock: lockFor({ a: "1.2.3" }, { b: "4.5.6" }, 2), audit: CLEAN_AUDIT });
  assert.equal(old.code, 1);
  assert.deepEqual(old.json.pinned.issues, [{ code: "lockfile_version", found: 2, expected: 3 }]);
});

test("S4: high or critical production vulnerabilities fail; low and moderate pass", () => {
  const lock = lockFor({ a: "1.2.3" }, { b: "4.5.6" });
  const high = runCheck({ pkg: PINNED_PKG, lock, audit: auditWith({ high: 2 }), auditExit: 1 });
  assert.equal(high.code, 1);
  assert.deepEqual(high.json.audit, { status: "vulnerable", high: 2, critical: 0 });

  const critical = runCheck({ pkg: PINNED_PKG, lock, audit: auditWith({ critical: 1 }), auditExit: 1 });
  assert.equal(critical.code, 1);
  assert.deepEqual(critical.json.audit, { status: "vulnerable", high: 0, critical: 1 });

  const low = runCheck({ pkg: PINNED_PKG, lock, audit: auditWith({ low: 3, moderate: 1 }), auditExit: 1 });
  assert.equal(low.code, 0);
  assert.deepEqual(low.json.audit, { status: "ok", high: 0, critical: 0 });
});

test("S4: an unreachable registry warns and passes, but fails with --strict", () => {
  const lock = lockFor({ a: "1.2.3" }, { b: "4.5.6" });
  const offline = JSON.stringify({ error: { code: "ENOTFOUND", summary: "request failed" } });
  const r = runCheck({ pkg: PINNED_PKG, lock, audit: offline, auditExit: 1 });
  assert.equal(r.code, 0);
  assert.deepEqual(r.json.audit, { status: "unavailable", high: null, critical: null });
  assert.match(r.stderr, /^deps-check: npm audit unavailable \(ENOTFOUND\); rerun online or with --strict to fail\n$/);

  const strict = runCheck({ pkg: PINNED_PKG, lock, audit: offline, auditExit: 1 }, ["--strict"]);
  assert.equal(strict.code, 1);
  assert.equal(strict.json.ok, false);

  const garbage = runCheck({ pkg: PINNED_PKG, lock, audit: "not json", auditExit: 1 });
  assert.equal(garbage.code, 0);
  assert.equal(garbage.json.audit.status, "unavailable");
});

test("S4: the repository itself has every dependency pinned and a v3 lockfile", () => {
  const root = join(import.meta.dirname, "..");
  const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
  const lock = JSON.parse(readFileSync(join(root, "package-lock.json"), "utf8"));
  const r = runCheck({ pkg, lock, audit: CLEAN_AUDIT });
  assert.deepEqual(r.json.pinned, { ok: true, issues: [] });
  assert.equal(readFileSync(join(root, ".npmrc"), "utf8").includes("save-exact=true"), true);
});

test("S4: npm run sbom prints a CycloneDX SBOM of the production dependencies", () => {
  const root = join(import.meta.dirname, "..");
  const out = execFileSync("npm", ["run", "--silent", "sbom"], { cwd: root, encoding: "utf8" });
  const sbom = JSON.parse(out);
  assert.equal(sbom.bomFormat, "CycloneDX");
  const names = (sbom.components as { name: string }[]).map((c) => c.name);
  assert.ok(names.includes("libsodium-wrappers"));
  assert.ok(!names.includes("typescript"), "dev dependencies are omitted");
});
