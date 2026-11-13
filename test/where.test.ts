import assert from "node:assert/strict";
import { mkdirSync, symlinkSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { HELP_TEXT } from "../src/help.ts";
import { run } from "../src/run.ts";
import { CANARY, auditBytes, harness, parse, type ExecCall } from "./helpers.ts";

// S1 of odd/tasks/zks-v0.7.0.md — `zks where NAME`.

/** The dotenv file prefix, built so the literal never appears in this file. */
const DOT_ENV = "." + "env";
const GIT = "/usr/bin/git";

const policy = {
  version: 1,
  project: "acme",
  targets: {
    gh: { provider: "github", repo: "acme/web" },
    web: { provider: "vercel", projectId: "prj_1", environments: ["production"] },
    prod: { provider: "dotenv", path: `${DOT_ENV}.production` },
    sec: { provider: "compose", dir: "secrets" },
  },
  variables: {
    API_KEY: { sensitive: true, source: { kind: "keychain", service: "app", account: "api" }, targets: ["gh", "web", "prod", "sec"] },
    PLAIN: { sensitive: false, value: "x", targets: ["web"] },
  },
};

function write(dir: string, path: string, content: string | Buffer): void {
  mkdirSync(dirname(join(dir, path)), { recursive: true });
  writeFileSync(join(dir, path), content);
}

/** Every matching line also holds CANARY, so any leaked line text shows up in the assertions. */
const hit = (name: string) => `${name}=${CANARY}\n`;

const ref = (path: string, line: number, kind: string) => ({ path, line, kind });

function project(dir: string, name = "API_KEY"): void {
  write(dir, ".github/workflows/deploy.yml", `on: push\nenv:\n  ${name}: \${{ secrets.${name} }} # ${CANARY}\n`);
  write(dir, "docker-compose.yml", `services:\n  web:\n    environment:\n      - ${hit(name)}`);
  write(dir, "Dockerfile", `FROM node\nARG ${name}\n`);
  write(dir, "railway.toml", `[deploy]\n${hit(name)}`);
  write(dir, "vercel.json", `{"env": {"${name}": "${CANARY}"}}\n`);
  write(dir, "netlify.toml", `[build.environment]\n${hit(name)}`);
  write(dir, `${DOT_ENV}.production`, `OTHER=1\n${hit(name)}`);
  write(dir, `${DOT_ENV}.local`, hit(name));
  write(dir, `${DOT_ENV}.example`, `${name}=\n`);
  write(dir, `config/${DOT_ENV}.sample`, `\n\n${name}=\n`);
  write(dir, `${DOT_ENV}.template`, `${name}=\n`);
  write(dir, ".gitlab-ci.yml", `variables:\n  ${hit(name)}`);
  write(dir, "bitbucket-pipelines.yml", hit(name));
  write(dir, ".circleci/config.yml", `jobs:\n${hit(name)}`);
  write(dir, "deploy.sh", `#!/bin/sh\necho "$${name}" ${CANARY}\n`);
  write(dir, "Makefile", `all:\n\techo $(${name}) ${CANARY}\n`);
  write(dir, "package.json", `{"scripts": {"x": "echo $${name} ${CANARY}"}}\n`);
  // Whole-word only: a longer name, a prefix and a suffix never match; one line counts once.
  write(
    dir,
    "src/app.ts",
    [
      `const a = process.env.${name}; // ${CANARY}`,
      `const b = process.env.${name}_SUFFIX; // ${CANARY}`,
      `const c = process.env.X${name}; // ${CANARY}`,
      `const d = 1${name}; // ${CANARY}`,
      `const e = [${name}, ${name}]; // ${CANARY}`,
      `(${name})`,
      "",
    ].join("\n"),
  );
  write(dir, "README.md", "nothing here\n");
  // Skipped: dependency and build directories, symlinks, files over 1 MiB and binary files.
  write(dir, "node_modules/pkg/index.js", hit(name));
  write(dir, ".git/config", hit(name));
  write(dir, "dist/app.js", hit(name));
  write(dir, "build/app.js", hit(name));
  write(dir, "packages/lib/node_modules/x.js", hit(name));
  symlinkSync(join(dir, "src/app.ts"), join(dir, "link.ts"));
  write(dir, "big.ts", hit(name) + "x".repeat(1024 * 1024));
  write(dir, "bin.dat", Buffer.concat([Buffer.from(hit(name)), Buffer.from([0, 1, 2])]));
}

/** Files read by the scan in the project above (skipped ones excluded). */
const SCANNED = 19;

test("S1: where classifies every reference and splits managed, unmanaged and consumers without any line text", async () => {
  const h = harness({ policy });
  project(h.dir);
  // The policy itself names the variable: it is zks's own file, never a reference.
  write(h.dir, "zks.policy.json", JSON.stringify(policy));
  const out = await run(["where", "API_KEY"], h.deps);
  assert.equal(out.exitCode, 0, out.stdout);
  assert.ok(!out.stdout.includes(CANARY));
  assert.deepEqual(parse(out.stdout), {
    ok: true,
    name: "API_KEY",
    inPolicy: true,
    targets: [
      { target: "gh", provider: "github" },
      { target: "web", provider: "vercel" },
      { target: "prod", provider: "dotenv" },
      { target: "sec", provider: "compose" },
    ],
    managed: [
      ref(`${DOT_ENV}.example`, 1, "dotenv"),
      ref(`${DOT_ENV}.production`, 2, "dotenv"),
      ref(`${DOT_ENV}.template`, 1, "dotenv"),
      ref(".github/workflows/deploy.yml", 3, "github-workflow"),
      ref("Dockerfile", 2, "dockerfile"),
      ref(`config/${DOT_ENV}.sample`, 3, "dotenv"),
      ref("docker-compose.yml", 4, "compose"),
      ref("vercel.json", 1, "vercel"),
    ],
    unmanaged: [
      ref(".circleci/config.yml", 2, "ci-other"),
      ref(`${DOT_ENV}.local`, 1, "dotenv"),
      ref(".gitlab-ci.yml", 2, "ci-other"),
      ref("bitbucket-pipelines.yml", 1, "ci-other"),
      ref("netlify.toml", 2, "netlify"),
      ref("railway.toml", 2, "railway"),
    ],
    consumers: [
      ref("Makefile", 2, "script"),
      ref("deploy.sh", 2, "script"),
      ref("package.json", 1, "script"),
      ref("src/app.ts", 1, "code"),
      ref("src/app.ts", 5, "code"),
      ref("src/app.ts", 6, "code"),
    ],
    scanned: SCANNED,
    truncated: false,
  });
  // Read-only: nothing audited, no dialog, no network.
  assert.ok(!(await auditBytes(h.auditDb)).includes(CANARY));
  assert.equal(h.human.approvals.length, 0);
  assert.equal(h.human.prompts.length, 0);
  assert.equal(h.fetch.calls.length, 0);
});

test("S1: a NAME outside the policy is valid and every destination reference is unmanaged, templates included", async () => {
  const h = harness({ policy });
  project(h.dir, "OTHER_KEY");
  const out = await run(["where", "OTHER_KEY", "--policy", "zks.policy.json"], h.deps);
  assert.equal(out.exitCode, 0, out.stdout);
  assert.ok(!out.stdout.includes(CANARY));
  const body = parse(out.stdout);
  assert.equal(body.inPolicy, false);
  assert.deepEqual(body.targets, []);
  assert.deepEqual(body.managed, []);
  assert.deepEqual(
    body.unmanaged.map((r: { path: string }) => r.path),
    [
      ".circleci/config.yml",
      `${DOT_ENV}.example`,
      `${DOT_ENV}.local`,
      `${DOT_ENV}.production`,
      `${DOT_ENV}.template`,
      ".github/workflows/deploy.yml",
      ".gitlab-ci.yml",
      "Dockerfile",
      "bitbucket-pipelines.yml",
      `config/${DOT_ENV}.sample`,
      "docker-compose.yml",
      "netlify.toml",
      "railway.toml",
      "vercel.json",
    ],
  );
  assert.equal(body.consumers.length, 6);
  assert.equal(body.scanned, SCANNED);
});

test("S1: a variable whose targets cover none of the files leaves every reference unmanaged", async () => {
  const h = harness({ policy });
  write(h.dir, "vercel.json", hit("PLAIN"));
  write(h.dir, ".github/workflows/ci.yaml", hit("PLAIN"));
  write(h.dir, "compose.yaml", hit("PLAIN"));
  write(h.dir, `${DOT_ENV}.production`, hit("PLAIN"));
  const body = parse((await run(["where", "PLAIN"], h.deps)).stdout);
  assert.deepEqual(body.targets, [{ target: "web", provider: "vercel" }]);
  assert.deepEqual(body.managed, [ref("vercel.json", 1, "vercel")]);
  assert.deepEqual(body.unmanaged, [
    ref(`${DOT_ENV}.production`, 1, "dotenv"),
    ref(".github/workflows/ci.yaml", 1, "github-workflow"),
    ref("compose.yaml", 1, "compose"),
  ]);
});

test("S1: an invalid or missing NAME is a usage error (exit 2) that never echoes it", async () => {
  const h = harness({ policy });
  write(h.dir, "a.ts", hit("API_KEY"));
  for (const argv of [["where", "1BAD"], ["where", `${CANARY}`], ["where", "a-b"], ["where", "__x".padEnd(129, "x")]]) {
    const out = await run(argv, h.deps);
    assert.equal(out.exitCode, 2, out.stdout);
    assert.ok(!out.stdout.includes(argv[1] as string));
    assert.deepEqual(parse(out.stdout), {
      ok: false,
      error: { code: "usage", message: "NAME must match /^[A-Za-z_][A-Za-z0-9_]{0,127}$/" },
    });
  }
  const missing = await run(["where"], h.deps);
  assert.equal(missing.exitCode, 2);
  assert.deepEqual(parse(missing.stdout).error, { code: "usage", message: "usage: zks where NAME [--policy FILE]" });
  const extra = await run(["where", "API_KEY", CANARY], h.deps);
  assert.equal(extra.exitCode, 2);
  assert.ok(!extra.stdout.includes(CANARY));
  assert.equal(parse(extra.stdout).error.message, "unexpected argument");
  const flag = await run(["where", "API_KEY", "--only", "A"], h.deps);
  assert.equal(flag.exitCode, 2);
  assert.equal(parse(flag.stdout).error.message, "option --only is not valid for where");
  const noPolicy = await run(["where", "API_KEY", "--policy", "missing.json"], h.deps);
  assert.equal(noPolicy.exitCode, 2);
  assert.equal(parse(noPolicy.stdout).error.code, "invalid_policy");
});

test("S1: the scan stops at the file limit and reports truncated", async () => {
  const h = harness({ policy });
  for (const name of ["a.ts", "b.ts", "c.ts", "d.ts", "e.ts"]) write(h.dir, name, hit("API_KEY"));
  h.deps.whereMaxFiles = 3;
  const body = parse((await run(["where", "API_KEY"], h.deps)).stdout);
  assert.equal(body.scanned, 3);
  assert.equal(body.truncated, true);
  assert.deepEqual(body.consumers, [ref("a.ts", 1, "code"), ref("b.ts", 1, "code"), ref("c.ts", 1, "code")]);
  h.deps.whereMaxFiles = 5;
  const all = parse((await run(["where", "API_KEY"], h.deps)).stdout);
  assert.equal(all.scanned, 5);
  assert.equal(all.truncated, false);
});

test("S1: inside a Git work tree the files come from git ls-files, still skipping ignored directories and unsafe files", async () => {
  const listed = ["a.ts", "node_modules/m.js", "dist/d.js", "link.ts", "bin.dat", "gone.ts", "sub/vercel.json"];
  const h = harness({
    policy,
    exec: (call: ExecCall) => {
      if (call.command !== GIT) return {};
      if (call.args.includes("rev-parse")) return { stdout: Buffer.from("true\n") };
      if (call.args.includes("ls-files")) return { stdout: Buffer.from(listed.map((p) => `${p}\0`).join("")) };
      return { code: 1 };
    },
  });
  write(h.dir, "a.ts", hit("API_KEY"));
  write(h.dir, "ignored.ts", hit("API_KEY"));
  write(h.dir, "node_modules/m.js", hit("API_KEY"));
  write(h.dir, "dist/d.js", hit("API_KEY"));
  write(h.dir, "bin.dat", Buffer.concat([Buffer.from(hit("API_KEY")), Buffer.from([0])]));
  write(h.dir, "sub/vercel.json", `{}\n${hit("API_KEY")}`);
  symlinkSync(join(h.dir, "a.ts"), join(h.dir, "link.ts"));
  const out = await run(["where", "API_KEY"], h.deps);
  assert.equal(out.exitCode, 0, out.stdout);
  const body = parse(out.stdout);
  assert.deepEqual(body.consumers, [ref("a.ts", 1, "code")]);
  assert.deepEqual(body.managed, [ref("sub/vercel.json", 2, "vercel")]);
  assert.deepEqual(body.unmanaged, []);
  assert.equal(body.scanned, 2);
  assert.deepEqual(
    h.exec.calls.map((c) => [c.command, ...c.args]),
    [
      [GIT, "-C", h.dir, "rev-parse", "--is-inside-work-tree"],
      [GIT, "-C", h.dir, "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
    ],
  );
});

test("S1: outside a Git work tree (or when git fails) the scan walks the current directory", async () => {
  for (const exec of [() => ({ code: 128 }), () => { throw new Error("spawn ENOENT"); }]) {
    const h = harness({ policy, exec });
    write(h.dir, "nested/deep/a.ts", hit("API_KEY"));
    write(h.dir, "node_modules/m.js", hit("API_KEY"));
    const body = parse((await run(["where", "API_KEY"], h.deps)).stdout);
    assert.deepEqual(body.consumers, [ref("nested/deep/a.ts", 1, "code")]);
    assert.equal(body.scanned, 1);
    assert.deepEqual(h.exec.calls.map((c) => c.args), [["-C", h.dir, "rev-parse", "--is-inside-work-tree"]]);
  }
});

test("S1: help documents zks where", () => {
  assert.ok(HELP_TEXT.includes("zks where NAME [--policy FILE]"));
});
