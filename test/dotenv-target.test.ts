import assert from "node:assert/strict";
import { existsSync, lstatSync, mkdirSync, readFileSync, readdirSync, realpathSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { describeDestination, describeEffect } from "../src/policy/describe.ts";
import { describeTrustKey, trustKeyOf } from "../src/policy/trust.ts";
import type { Operation, TargetConfig } from "../src/policy/types.ts";
import { PolicyError, validatePolicy } from "../src/policy/validate.ts";
import { HELP_TEXT } from "../src/help.ts";
import { run } from "../src/run.ts";
import { SecretBuffer } from "../src/secret/secret-buffer.ts";
import { dotenvLine, dotenvSink, upsertDotenv } from "../src/sinks/dotenv.ts";
import { findDotenvValue } from "../src/sources/resolve.ts";
import { SinkError, type SinkContext } from "../src/sinks/types.ts";
import { CANARY, TEST_TOOLS, auditBytes, fakeAws, fakeExec, fakeFetch, fakeKeychain, harness, parse, tempDir } from "./helpers.ts";

function op(path: string, name = "API_KEY"): Operation {
  const target: TargetConfig = { provider: "dotenv", path };
  return { name, targetKey: "env", target, variable: { sensitive: true, targets: ["env"], source: { kind: "prompt" } }, sourceKind: "prompt" };
}

const context: SinkContext = { fetch: fakeFetch().fetch, exec: fakeExec().exec, aws: fakeAws().aws, keychain: fakeKeychain().keychain, tools: TEST_TOOLS };
const write = (path: string, value: string, name = "API_KEY") => dotenvSink.apply(op(path, name), SecretBuffer.fromString(value), context);

async function rejects(promise: Promise<unknown>, code: string, message: string): Promise<void> {
  await assert.rejects(promise, (error: unknown) => {
    assert.ok(error instanceof SinkError, String(error));
    assert.equal(error.code, code);
    assert.equal(error.message, message);
    return true;
  });
}

test("S13: dotenv creates the file with KEY=\"value\" and mode 600, leaving no temp file", async () => {
  const dir = tempDir();
  const path = join(dir, ".env.local");
  assert.deepEqual(await write(path, CANARY), {});
  assert.equal(readFileSync(path, "utf8"), `API_KEY="${CANARY}"\n`);
  assert.equal(statSync(path).mode & 0o777, 0o600);
  assert.deepEqual(readdirSync(dir), [".env.local"]);
});

test("S13: dotenv upserts the key, keeps every other line and tightens the mode to 600", async () => {
  const dir = tempDir();
  const path = join(dir, ".env");
  writeFileSync(path, "# app\nA=1\nexport API_KEY = old\n\nB='x'\nAPI_KEY=\"dup\"\n", { mode: 0o644 });
  await write(path, "new");
  assert.equal(readFileSync(path, "utf8"), "# app\nA=1\nexport API_KEY=\"new\"\n\nB='x'\n");
  assert.equal(statSync(path).mode & 0o777, 0o600);

  await write(path, "v", "OTHER");
  assert.equal(readFileSync(path, "utf8"), "# app\nA=1\nexport API_KEY=\"new\"\n\nB='x'\nOTHER=\"v\"\n");
  assert.deepEqual(readdirSync(dir), [".env"]);

  // A key that only prefixes another is a different key; a file without a final newline gets one.
  assert.equal(upsertDotenv("API_KEY_2=a\nZ=1", "API_KEY", dotenvLine("API_KEY", "b")), "API_KEY_2=a\nZ=1\nAPI_KEY=\"b\"\n");
  // A multi-line quoted old value is replaced as a whole.
  assert.equal(upsertDotenv('A=1\nAPI_KEY="line1\nline2"\nB=2\n', "API_KEY", 'API_KEY="n"'), 'A=1\nAPI_KEY="n"\nB=2\n');
  assert.equal(upsertDotenv("API_KEY='a\nb'\nB=2\n", "API_KEY", 'API_KEY="n"'), 'API_KEY="n"\nB=2\n');
  assert.equal(upsertDotenv('API_KEY="a\\"\nb"\nB=2\n', "API_KEY", 'API_KEY="n"'), 'API_KEY="n"\nB=2\n');
  // CRLF files keep CRLF.
  assert.equal(upsertDotenv("A=1\r\nAPI_KEY=x\r\n", "API_KEY", 'API_KEY="n"'), 'A=1\r\nAPI_KEY="n"\r\n');
  assert.equal(upsertDotenv("", "API_KEY", 'API_KEY="n"'), 'API_KEY="n"\n');
});

test("S13: dotenv refuses a non-UTF-8 file and leaves it unchanged, never writing U+FFFD", async () => {
  const dir = tempDir();
  const path = join(dir, ".env");
  const before = Buffer.concat([Buffer.from([0x23, 0x20, 0x63, 0x61, 0x66, 0xe9, 0x0a]), Buffer.from("API_KEY=old\n")]);
  writeFileSync(path, before, { mode: 0o600 });
  await rejects(write(path, "new"), "file_not_utf8", `${path} is not UTF-8 text; zks does not rewrite it`);
  assert.ok(readFileSync(path).equals(before));
  assert.deepEqual(readdirSync(dir), [".env"]);
});

test("S13: dotenv keeps each line's own ending and replaces the key once in a mixed-endings file", () => {
  assert.equal(upsertDotenv("A=1\nAPI_KEY=old\r\nB=2\r\n", "API_KEY", 'API_KEY="n"'), 'A=1\nAPI_KEY="n"\r\nB=2\r\n');
  assert.equal(upsertDotenv("A=1\r\nB=2\n", "API_KEY", 'API_KEY="n"'), 'A=1\r\nB=2\nAPI_KEY="n"\n');
});

test("S13: dotenv leaves a key-shaped line inside another key's multi-line value alone", () => {
  const text = 'OTHER="x\nAPI_KEY=inside\ny"\nAPI_KEY=old\n';
  assert.equal(upsertDotenv(text, "API_KEY", 'API_KEY="n"'), 'OTHER="x\nAPI_KEY=inside\ny"\nAPI_KEY="n"\n');
});

test("S13: what the dotenv target writes, the zks dotenv source reads back exactly", () => {
  for (const value of ['a\\b"c$d\ne', "x\\ny", "pw!#$%&", "cr\rx", "plain"]) {
    assert.equal(findDotenvValue(upsertDotenv("", "K", dotenvLine("K", value)), "K"), value);
  }
  // Existing source behaviour: plain, single-quoted and inline-comment values are unchanged.
  assert.equal(findDotenvValue("K=raw # note\n", "K"), "raw");
  assert.equal(findDotenvValue("K='a\\nb'\n", "K"), "a\\nb");
});

test("S13: dotenv escapes backslash, double quote, newline, carriage return and $", () => {
  assert.equal(dotenvLine("K", 'a\\b"c\nd\re$f'), 'K="a\\\\b\\"c\\nd\\re\\$f"');
  assert.equal(dotenvLine("K", "plain-123"), 'K="plain-123"');
});

test("S13: dotenv refuses a symlink or a non-file and writes nothing", async () => {
  const dir = tempDir();
  const real = join(dir, "real.env");
  writeFileSync(real, "A=1\n");
  symlinkSync(real, join(dir, ".env"));
  await rejects(write(join(dir, ".env"), CANARY), "symlink_refused", `${join(dir, ".env")} is a symlink; zks writes only to real files and directories`);
  assert.equal(readFileSync(real, "utf8"), "A=1\n");
  assert.ok(lstatSync(join(dir, ".env")).isSymbolicLink());

  mkdirSync(join(dir, ".env.dir"));
  await rejects(write(join(dir, ".env.dir"), CANARY), "not_a_file", `${join(dir, ".env.dir")} is not a regular file`);
  await rejects(write(join(dir, "missing", ".env"), CANARY), "file_write_failed", `cannot write ${join(dir, "missing", ".env")}`);
  assert.deepEqual(readdirSync(dir).sort(), [".env", ".env.dir", "real.env"]);
});

test("S13: dotenv targets need a .env* file name; dotenv sources validate as before", () => {
  const issues = (targets: unknown, source: unknown = { kind: "prompt" }) => {
    try {
      validatePolicy({ version: 1, project: "p", targets, variables: { A: { sensitive: true, source, targets: Object.keys(targets as object) } } });
      return [];
    } catch (error) {
      return (error as PolicyError).issues;
    }
  };
  assert.deepEqual(issues({ env: { provider: "dotenv", path: ".env.production" } }), []);
  assert.deepEqual(issues({ env: { provider: "dotenv", path: "/srv/app/.env" } }), []);
  const message = "targets.env.path: must be a path of 1 to 200 printable characters to a .env* file";
  assert.deepEqual(issues({ env: { provider: "dotenv", path: "config.json" } }), [message]);
  assert.deepEqual(issues({ env: { provider: "dotenv", path: "/Users/me/.zshrc" } }), [message]);
  assert.deepEqual(issues({ env: { provider: "dotenv", path: ".env/" } }), [message]);
  assert.deepEqual(issues({ env: { provider: "dotenv" } }), [message]);
  // PRESERVE: the dotenv source keeps its relative-only rule.
  assert.deepEqual(issues({ env: { provider: "dotenv", path: ".env" } }, { kind: "dotenv", path: "../.env" }), [
    "variables.A.source.path: must be a relative .env* file inside the project",
  ]);
  assert.deepEqual(issues({ env: { provider: "dotenv", path: ".env" } }, { kind: "dotenv", path: ".env.source" }), []);
});

test("S13: dotenv trust key, destination, effect and help", () => {
  assert.equal(trustKeyOf(op("/w/.env")), "dotenv:/w/.env");
  assert.equal(describeTrustKey("dotenv:/w/a:b/.env"), "dotenv file /w/a:b/.env");
  assert.equal(describeDestination(op("/w/.env")), "dotenv file /w/.env");
  assert.equal(describeEffect(op("/w/.env")), "restart processes that read the file");
  assert.ok(HELP_TEXT.includes("dotenv {path}"));
});

test("S13 S1 S5: apply from a dotenv source to a dotenv target asks first, resolves the path against cwd and audits no value", async () => {
  const policy = {
    version: 1,
    project: "web",
    targets: { local: { provider: "dotenv", path: "app/.env.local" } },
    variables: { API_KEY: { sensitive: true, source: { kind: "dotenv", path: ".env.source" }, targets: ["local"] } },
  };
  // The dotenv source checks real paths, so this project lives on disk.
  const onDisk = (approve: boolean) => {
    const h = harness({ approve });
    const cwd = realpathSync(h.dir);
    writeFileSync(join(cwd, "zks.policy.json"), JSON.stringify(policy));
    writeFileSync(join(cwd, ".env.source"), `API_KEY=${CANARY}\n`);
    mkdirSync(join(cwd, "app"));
    h.deps.cwd = cwd;
    h.deps.readFile = (file) => readFile(file);
    return { h, path: join(cwd, "app", ".env.local") };
  };
  const { h, path } = onDisk(true);

  const plan = await run(["plan"], h.deps);
  assert.equal(parse(plan.stdout).operations[0].destination, `dotenv file ${path}`);

  const denied = onDisk(false);
  assert.equal((await run(["apply"], denied.h.deps)).exitCode, 3);
  assert.equal(existsSync(denied.path), false);

  const out = await run(["apply"], h.deps);
  assert.equal(out.exitCode, 0, out.stdout);
  assert.ok(h.human.approvals[0]!.some((line) => line.includes(`dotenv file ${path}`) && line.includes("[NEW destination]")));
  assert.equal(readFileSync(path, "utf8"), `API_KEY="${CANARY}"\n`);
  assert.ok(!out.stdout.includes(CANARY));
  assert.ok(!h.human.approvals.flat().join("\n").includes(CANARY));
  assert.ok(!(await auditBytes(h.auditDb)).includes(CANARY));
});
