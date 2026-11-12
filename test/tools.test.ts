import assert from "node:assert/strict";
import { test } from "node:test";
import { SAFE_PATH } from "../src/platform/exec.ts";
import { NO_TOOLS, findOnSafePath, parseToolPins, parseToolsFile, pinnedExec, resolveTools } from "../src/platform/tools.ts";
import { run } from "../src/run.ts";
import { githubSink } from "../src/sinks/github.ts";
import { SecretBuffer } from "../src/secret/secret-buffer.ts";
import { resolveValue } from "../src/sources/resolve.ts";
import { CANARY, TEST_TOOLS, fakeAws, fakeExec, fakeFetch, fakeHuman, fakeKeychain, harness, parse } from "./helpers.ts";

const EGO = "/Applications/ego lite.app/Contents/Helpers/ego-browser";

test("S11: tools.json gives absolute paths for ego-browser, gh and op", () => {
  const tools = parseToolsFile(JSON.stringify({ "ego-browser": EGO, gh: "/opt/homebrew/bin/gh", op: null }));
  assert.deepEqual(tools, { egoBrowser: EGO, gh: "/opt/homebrew/bin/gh", op: null, docker: null });
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
  assert.deepEqual(resolveTools(null, isExecutable), { egoBrowser: null, gh: "/usr/local/bin/gh", op: "/opt/homebrew/bin/op", docker: null });
  const dirs = SAFE_PATH.split(":");
  for (const path of checked) assert.ok(dirs.some((dir) => path === `${dir}/${path.split("/").pop()}`), path);
});

test("S11: a present tools.json is used as is, with no PATH lookup", () => {
  let lookups = 0;
  const tools = resolveTools(JSON.stringify({ "ego-browser": EGO, gh: null, op: null }), () => {
    lookups++;
    return true;
  });
  assert.deepEqual(tools, { egoBrowser: EGO, gh: null, op: null, docker: null });
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

// S2 (odd/tasks/zks-v2.md): tools are pinned by the sha256 of their binary.
const PIN_GH = "a".repeat(64);
const PIN_OP = "b".repeat(64);

test("v2 S2: tools.json entries may carry a sha256 pin; legacy string entries stay unpinned", () => {
  const text = JSON.stringify({
    "ego-browser": { path: EGO, sha256: "c".repeat(64) },
    gh: { path: "/opt/homebrew/bin/gh", sha256: PIN_GH },
    op: "/opt/homebrew/bin/op",
  });
  assert.deepEqual(parseToolsFile(text), { egoBrowser: EGO, gh: "/opt/homebrew/bin/gh", op: "/opt/homebrew/bin/op", docker: null });
  assert.deepEqual(parseToolPins(text), { egoBrowser: "c".repeat(64), gh: PIN_GH, op: null, docker: null });
});

test("v2 S2: a malformed pin makes the tool unavailable instead of unpinned", () => {
  for (const bad of ["A".repeat(64), "a".repeat(63), "", 7, null]) {
    const text = JSON.stringify({ "ego-browser": null, gh: { path: "/opt/homebrew/bin/gh", sha256: bad }, op: null });
    assert.equal(parseToolsFile(text).gh, null, String(bad));
  }
});

test("v2 S2: pinned exec runs a tool whose binary hash matches, hashing it once per process", async () => {
  const hashed: string[] = [];
  const warnings: string[] = [];
  const base = fakeExec(() => ({ stdout: Buffer.from("ok") }));
  const exec = pinnedExec(base.exec, { egoBrowser: null, gh: "/opt/homebrew/bin/gh", op: null, docker: null }, { egoBrowser: null, gh: PIN_GH, op: null, docker: null }, {
    hashFile: async (path) => (hashed.push(path), PIN_GH),
    warn: (line) => warnings.push(line),
  });
  assert.equal((await exec("/opt/homebrew/bin/gh", ["auth", "token"])).code, 0);
  await exec("/opt/homebrew/bin/gh", ["auth", "token"]);
  await exec("/usr/bin/security", ["help"]);
  assert.deepEqual(hashed, ["/opt/homebrew/bin/gh"]);
  assert.equal(base.calls.length, 3);
  assert.deepEqual(warnings, []);
});

test("v2 S2: an unpinned (legacy) tool runs without hashing", async () => {
  const hashed: string[] = [];
  const base = fakeExec();
  const exec = pinnedExec(base.exec, { egoBrowser: null, gh: "/opt/homebrew/bin/gh", op: null, docker: null }, { egoBrowser: null, gh: null, op: null, docker: null }, {
    hashFile: async (path) => (hashed.push(path), PIN_GH),
    warn: () => undefined,
  });
  await exec("/opt/homebrew/bin/gh", ["auth", "token"]);
  assert.deepEqual(hashed, []);
  assert.equal(base.calls.length, 1);
});

test("v2 S2: a tool whose binary changed since install is refused with a warning and never runs", async () => {
  const warnings: string[] = [];
  const base = fakeExec();
  const exec = pinnedExec(base.exec, { egoBrowser: null, gh: null, op: "/opt/homebrew/bin/op", docker: null }, { egoBrowser: null, gh: null, op: PIN_OP, docker: null }, {
    hashFile: async () => "d".repeat(64),
    warn: (line) => warnings.push(line),
  });
  await assert.rejects(exec("/opt/homebrew/bin/op", ["read", "op://v/i/f"]), { code: "tool_changed" });
  await assert.rejects(exec("/opt/homebrew/bin/op", ["read", "op://v/i/f"]), { code: "tool_changed" });
  assert.equal(base.calls.length, 0);
  assert.deepEqual(warnings, ["zks: op changed since install (sha256 mismatch); rerun ./install.sh to pin the new binary\n"]);
});

test("v2 S2: a missing pinned binary is refused like a changed one", async () => {
  const base = fakeExec();
  const exec = pinnedExec(base.exec, { egoBrowser: null, gh: "/opt/homebrew/bin/gh", op: null, docker: null }, { egoBrowser: null, gh: PIN_GH, op: null, docker: null }, {
    hashFile: async () => {
      throw new Error("ENOENT");
    },
    warn: () => undefined,
  });
  await assert.rejects(exec("/opt/homebrew/bin/gh", []), { code: "tool_changed" });
  assert.equal(base.calls.length, 0);
});

test("v2 S2: a changed op makes an op source fail as source_unavailable without running op", async () => {
  const base = fakeExec(() => ({ stdout: Buffer.from(CANARY) }));
  const exec = pinnedExec(base.exec, TEST_TOOLS, { egoBrowser: null, gh: null, op: PIN_OP, docker: null }, {
    hashFile: async () => "d".repeat(64),
    warn: () => undefined,
  });
  const deps = { keychain: fakeKeychain().keychain, human: fakeHuman().human, cwd: "/w", exec, tools: TEST_TOOLS };
  const spec = { sensitive: true, targets: [], source: { kind: "op" as const, ref: "op://v/i/f" } };
  await assert.rejects(resolveValue("A", spec, deps), (e: Error & { code?: string }) => e.code === "source_unavailable");
  assert.equal(base.calls.length, 0);
});
