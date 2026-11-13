import assert from "node:assert/strict";
import { test } from "node:test";
import { run } from "../src/run.ts";
import { resolveValue } from "../src/sources/resolve.ts";
import { CANARY, TEST_TOOLS, auditBytes, fakeExec, fakeHuman, fakeKeychain, ghTokenExec, harness, openSealed, parse, type ExecCall } from "./helpers.ts";

const PBPASTE = "/usr/bin/pbpaste";
const PBCOPY = "/usr/bin/pbcopy";

/** gh answers its token; pbpaste answers `clipboard`; pbcopy accepts anything. */
function clipboardExec(clipboard: string | null, pbpasteCode = 0) {
  return (call: ExecCall) => {
    if (call.command === PBPASTE) return { code: pbpasteCode, stdout: Buffer.from(clipboard ?? "", "utf8") };
    if (call.command === PBCOPY) return {};
    return ghTokenExec(call);
  };
}

const githubPolicy = {
  version: 1,
  project: "acme",
  targets: { gh: { provider: "github", repo: "acme/web" } },
  variables: { API_KEY: { sensitive: true, source: { kind: "clipboard" }, targets: ["gh"] } },
};

function deps(exec: ReturnType<typeof fakeExec>) {
  return { exec: exec.exec, tools: TEST_TOOLS, keychain: fakeKeychain({}).keychain, human: fakeHuman().human, cwd: "/tmp" };
}

test("S1: the clipboard source reads pbpaste, drops one trailing newline and clears the clipboard", async () => {
  const exec = fakeExec(clipboardExec(`${CANARY}\r\n`));
  const value = await resolveValue("API_KEY", { sensitive: true, source: { kind: "clipboard" }, targets: [] }, deps(exec));
  assert.equal(value.reveal(), CANARY);
  value.dispose();
  assert.deepEqual(exec.calls, [
    { command: PBPASTE, args: [], input: "" },
    { command: PBCOPY, args: [], input: "" },
  ]);
});

test("S1: only one trailing newline is dropped", async () => {
  const exec = fakeExec(clipboardExec(`${CANARY}\n\n`));
  const value = await resolveValue("API_KEY", { sensitive: true, source: { kind: "clipboard" }, targets: [] }, deps(exec));
  assert.equal(value.reveal(), `${CANARY}\n`);
  value.dispose();
});

test("S1: an empty clipboard is source_missing and is not cleared", async () => {
  for (const clip of ["", "\n"]) {
    const exec = fakeExec(clipboardExec(clip));
    await assert.rejects(
      resolveValue("API_KEY", { sensitive: true, source: { kind: "clipboard" }, targets: [] }, deps(exec)),
      (error: Error & { code?: string }) => error.code === "source_missing" && error.message === "the clipboard is empty",
    );
    assert.deepEqual(exec.calls.map((c) => c.command), [PBPASTE]);
  }
});

test("S1: a failing pbpaste is source_failed", async () => {
  const exec = fakeExec(clipboardExec(CANARY, 1));
  await assert.rejects(
    resolveValue("API_KEY", { sensitive: true, source: { kind: "clipboard" }, targets: [] }, deps(exec)),
    (error: Error & { code?: string }) => error.code === "source_failed" && !error.message.includes(CANARY),
  );
  assert.deepEqual(exec.calls.map((c) => c.command), [PBPASTE]);
});

test("S1: validation needs sensitive and allows a single clipboard variable", async () => {
  const policy = {
    ...githubPolicy,
    variables: {
      A: { sensitive: false, source: { kind: "clipboard" }, targets: ["gh"] },
      B: { sensitive: true, source: { kind: "clipboard" }, targets: ["gh"] },
    },
  };
  const h = harness({ policy });
  const out = await run(["validate"], h.deps);
  assert.equal(out.exitCode, 2, out.stdout);
  const issues = parse(out.stdout).error.issues as string[];
  assert.ok(issues.some((i) => i.startsWith("variables.A")), issues.join("\n"));
  assert.ok(issues.includes("variables.B.source: only one variable can use the clipboard source"), issues.join("\n"));
});

test("S1: plan describes the clipboard source", async () => {
  const h = harness({ policy: githubPolicy });
  const out = await run(["plan"], h.deps);
  assert.equal(out.exitCode, 0, out.stdout);
  assert.ok(out.stdout.includes("the clipboard (cleared after reading)"), out.stdout);
  assert.equal(h.exec.calls.filter((c) => c.command === PBPASTE).length, 0, "plan never reads the clipboard");
});

test("S2: a clipboard value is sealed into a GitHub Actions secret, never in plaintext", async () => {
  const h = harness({ policy: githubPolicy, exec: clipboardExec(`${CANARY}\n`) });
  const out = await run(["apply"], h.deps);
  assert.equal(out.exitCode, 0, out.stdout);
  assert.ok(!out.stdout.includes(CANARY));
  const put = h.fetch.calls.find((c) => c.init.method === "PUT")!;
  assert.equal(put.url, "https://api.github.com/repos/acme/web/actions/secrets/API_KEY");
  assert.ok(!put.body.includes(CANARY));
  assert.equal(openSealed(JSON.parse(put.body).encrypted_value), CANARY);
  assert.ok(h.exec.calls.some((c) => c.command === PBCOPY), "clipboard cleared");
  for (const call of h.exec.calls) assert.ok(!`${call.args.join(" ")} ${call.input}`.includes(CANARY));
  assert.ok(!(await auditBytes(h.auditDb)).includes(CANARY));
});
