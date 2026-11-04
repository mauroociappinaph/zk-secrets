import assert from "node:assert/strict";
import { test } from "node:test";
import { SAFE_PATH } from "../src/platform/exec.ts";
import { NO_TOOLS, findOnSafePath, parseToolsFile, resolveTools } from "../src/platform/tools.ts";
import { run } from "../src/run.ts";
import { githubSink } from "../src/sinks/github.ts";
import { SecretBuffer } from "../src/secret/secret-buffer.ts";
import { resolveValue } from "../src/sources/resolve.ts";
import { CANARY, TEST_TOOLS, fakeAws, fakeExec, fakeFetch, fakeHuman, fakeKeychain, harness, parse } from "./helpers.ts";

const EGO = "/Applications/ego lite.app/Contents/Helpers/ego-browser";

test("S11: tools.json gives absolute paths for ego-browser, gh and op", () => {
  const tools = parseToolsFile(JSON.stringify({ "ego-browser": EGO, gh: "/opt/homebrew/bin/gh", op: null }));
  assert.deepEqual(tools, { egoBrowser: EGO, gh: "/opt/homebrew/bin/gh", op: null });
});

test("S11: tools.json entries that are not absolute plain paths resolve to null", () => {
  for (const bad of ["ego-browser", "./bin/ego", "", "/bin/a\nb", "/bin/\u0000x", 7, ["/bin/x"], `/${"x".repeat(1024)}`]) {
    assert.deepEqual(parseToolsFile(JSON.stringify({ "ego-browser": bad, gh: bad, op: bad })), NO_TOOLS, String(bad));
  }
  assert.deepEqual(parseToolsFile("{ not json"), NO_TOOLS);
  assert.deepEqual(parseToolsFile("[]"), NO_TOOLS);
  assert.deepEqual(parseToolsFile("null"), NO_TOOLS);
});

test("S11: without tools.json each tool is looked up on SAFE_PATH only, first match wins", () => {
  const checked: string[] = [];
  const executables = new Set(["/usr/local/bin/gh", "/usr/bin/gh", "/opt/homebrew/bin/op"]);
  const isExecutable = (path: string) => {
    checked.push(path);
    return executables.has(path);
  };
  assert.equal(findOnSafePath("gh", isExecutable), "/usr/local/bin/gh");
  assert.deepEqual(resolveTools(null, isExecutable), { egoBrowser: null, gh: "/usr/local/bin/gh", op: "/opt/homebrew/bin/op" });
  const dirs = SAFE_PATH.split(":");
  for (const path of checked) assert.ok(dirs.some((dir) => path === `${dir}/${path.split("/").pop()}`), path);
});

test("S11: a present tools.json is used as is, with no PATH lookup", () => {
  let lookups = 0;
  const tools = resolveTools(JSON.stringify({ "ego-browser": EGO, gh: null, op: null }), () => {
    lookups++;
    return true;
  });
  assert.deepEqual(tools, { egoBrowser: EGO, gh: null, op: null });
  assert.equal(lookups, 0);
});

test("S11: the GitHub sink runs gh from its resolved absolute path, and reports github_unavailable without one", async () => {
  const exec = fakeExec((call) => (call.args[0] === "auth" ? { stdout: Buffer.from("gho_x\n") } : {}));
  const fetch = fakeFetch(() => ({ status: 201 }));
  const op = {
    name: "LOG_LEVEL",
    targetKey: "gh",
    target: { provider: "github" as const, repo: "acme/web" },
    variable: { sensitive: false, targets: ["gh"], value: "info" },
    sourceKind: "literal" as const,
  };
  const ctx = { fetch: fetch.fetch, exec: exec.exec, keychain: fakeKeychain().keychain, aws: fakeAws().aws };
  await githubSink.apply(op, SecretBuffer.fromString("info"), { ...ctx, tools: TEST_TOOLS });
  assert.equal(exec.calls[0]?.command, TEST_TOOLS.gh);

  const none = fakeExec();
  await assert.rejects(
    githubSink.apply(op, SecretBuffer.fromString("info"), { ...ctx, exec: none.exec, tools: { ...TEST_TOOLS, gh: null } }),
    (e: Error & { code?: string }) => e.code === "github_unavailable",
  );
  assert.equal(none.calls.length, 0);
});

test("S11: op sources run op from its resolved absolute path, and report source_unavailable without one", async () => {
  const exec = fakeExec(() => ({ stdout: Buffer.from(CANARY) }));
  const base = { keychain: fakeKeychain().keychain, human: fakeHuman().human, cwd: "/w" };
  const spec = { sensitive: true, targets: [], source: { kind: "op" as const, ref: "op://v/i/f" } };
  assert.equal((await resolveValue("A", spec, { ...base, exec: exec.exec, tools: TEST_TOOLS })).reveal(), CANARY);
  assert.equal(exec.calls[0]?.command, TEST_TOOLS.op);

  const none = fakeExec();
  await assert.rejects(
    resolveValue("A", spec, { ...base, exec: none.exec, tools: { ...TEST_TOOLS, op: null } }),
    (e: Error & { code?: string }) => e.code === "source_unavailable",
  );
  assert.equal(none.calls.length, 0);
});

test("S11: capture without a resolved ego-browser fails with browser_failed and runs nothing", async () => {
  const h = harness();
  h.deps.tools = { ...TEST_TOOLS, egoBrowser: null };
  const out = await run(["capture", "read", "--space", "4", "--page", "p1", "--selector", "#tok", "--store", "app/key"], h.deps);
  assert.equal(out.exitCode, 1, out.stdout);
  assert.equal(parse(out.stdout).error.code, "browser_failed");
  assert.equal(h.exec.calls.length, 0);
});
