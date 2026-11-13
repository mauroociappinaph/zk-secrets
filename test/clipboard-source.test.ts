import assert from "node:assert/strict";
import { join } from "node:path";
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
  assert.ok(out.stdout.includes("the clipboard (cleared once used, if unchanged)"), out.stdout);
  assert.ok(!out.stdout.includes("cleared after reading"), out.stdout);
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

test("S1: a lone trailing CR is kept (only \\n or \\r\\n is dropped)", async () => {
  const exec = fakeExec(clipboardExec(`${CANARY}\r`));
  const value = await resolveValue("API_KEY", { sensitive: true, source: { kind: "clipboard" }, targets: [] }, deps(exec));
  assert.equal(value.reveal(), `${CANARY}\r`);
  value.dispose();
});

test("S1: pbpaste that cannot start is source_unavailable and nothing is cleared", async () => {
  const exec = fakeExec((c) => {
    if (c.command === PBPASTE) throw new Error(`spawn ${CANARY}`);
    return {};
  });
  await assert.rejects(
    resolveValue("API_KEY", { sensitive: true, source: { kind: "clipboard" }, targets: [] }, deps(exec)),
    (e: Error & { code?: string }) => e.code === "source_unavailable" && !e.message.includes(CANARY),
  );
  assert.deepEqual(exec.calls.map((c) => c.command), [PBPASTE]);
});

test("S1: apply clears the clipboard only after every write succeeded and reports clipboardCleared", async () => {
  const h = harness({ policy: githubPolicy, exec: clipboardExec(CANARY) });
  const out = await run(["apply"], h.deps);
  assert.equal(out.exitCode, 0, out.stdout);
  assert.equal(parse(out.stdout).clipboardCleared, true);
  const order = h.exec.calls.map((c) => c.command);
  assert.equal(order.at(-1), PBCOPY, "cleared after the GitHub write");
  assert.ok(h.fetch.calls.some((c) => c.init.method === "PUT"));
});

test("S1: a failed write keeps the clipboard for a retry", async () => {
  const h = harness({ policy: githubPolicy, exec: clipboardExec(CANARY) });
  h.deps.fetch = async () => new Response("{}", { status: 500 });
  const out = await run(["apply"], h.deps);
  assert.equal(out.exitCode, 1, out.stdout);
  assert.equal(parse(out.stdout).clipboardCleared, false);
  assert.ok(!out.stdout.includes(CANARY));
  assert.deepEqual(h.exec.calls.filter((c) => c.command === PBCOPY), []);
});

test("S1: a denied apply never reads the clipboard", async () => {
  const h = harness({ policy: githubPolicy, approve: false, exec: clipboardExec(CANARY) });
  const out = await run(["apply"], h.deps);
  assert.equal(out.exitCode, 3, out.stdout);
  assert.deepEqual(h.exec.calls.filter((c) => c.command === PBPASTE || c.command === PBCOPY), []);
});

test("S1: an apply without a clipboard variable has no clipboardCleared field", async () => {
  const policy = { ...githubPolicy, variables: { API_KEY: { sensitive: true, source: { kind: "prompt" }, targets: ["gh"] } } };
  const h = harness({ policy, prompt: CANARY });
  const out = await run(["apply"], h.deps);
  assert.equal(out.exitCode, 0, out.stdout);
  assert.equal("clipboardCleared" in parse(out.stdout), false);
});

/** pbpaste answers each of `reads` in turn (the last one repeats); pbcopy accepts anything. */
function changingClipboardExec(reads: string[]) {
  let n = 0;
  return (call: ExecCall) => {
    if (call.command === PBPASTE) return { code: 0, stdout: Buffer.from(reads[Math.min(n++, reads.length - 1)] as string, "utf8") };
    if (call.command === PBCOPY) return {};
    return ghTokenExec(call);
  };
}

const promptPolicy = { ...githubPolicy, variables: { OTHER: { sensitive: true, source: { kind: "prompt" }, targets: ["gh"] } } };

/** A harness whose GitHub owner acme is already trusted ("Always allow" on a first apply without the clipboard). */
async function trustedHarness(policy: unknown) {
  const h = harness({ policy: promptPolicy, prompt: "typed-value", decision: "always", exec: clipboardExec(CANARY) });
  const first = await run(["apply"], h.deps);
  assert.equal(first.exitCode, 0, first.stdout);
  assert.deepEqual(parse(first.stdout).trusted, ["github:acme"]);
  h.files.set(join(h.dir, "zks.policy.json"), JSON.stringify(policy));
  return h;
}

test("S5: a clipboard value always opens the dialog, even for a trusted destination, and the dialog names the clipboard", async () => {
  const h = await trustedHarness(githubPolicy);
  const out = await run(["apply"], h.deps);
  assert.equal(out.exitCode, 0, out.stdout);
  assert.equal(parse(out.stdout).approval, "dialog");
  assert.equal(h.human.approvals.length, 2);
  assert.ok(h.human.approvals[1]!.includes("Reads the clipboard: API_KEY"), h.human.approvals[1]!.join("\n"));
  assert.equal(parse(out.stdout).clipboardCleared, true);
});

test("S5: a denied dialog for a trusted destination reads no clipboard", async () => {
  const h = await trustedHarness(githubPolicy);
  h.deps.human.approveWithTrust = async () => "deny";
  const out = await run(["apply"], h.deps);
  assert.equal(out.exitCode, 3, out.stdout);
  assert.deepEqual(h.exec.calls.filter((c) => c.command === PBPASTE || c.command === PBCOPY), []);
});

test("S5: a trusted destination without a clipboard value still skips the dialog", async () => {
  const h = await trustedHarness(promptPolicy);
  const out = await run(["apply"], h.deps);
  assert.equal(out.exitCode, 0, out.stdout);
  assert.equal(parse(out.stdout).approval, "trusted");
  assert.equal(h.human.approvals.length, 1, "no second dialog");
  assert.equal("clipboardCleared" in parse(out.stdout), false);
});

test("S5: a template that uses a clipboard value also always asks", async () => {
  const policy = {
    ...githubPolicy,
    variables: {
      RAW: { sensitive: true, source: { kind: "clipboard" }, targets: ["gh"] },
      URL: { sensitive: true, source: { kind: "template", template: "https://u:${RAW:url}@db" }, targets: ["gh"] },
    },
  };
  const h = await trustedHarness(policy);
  const out = await run(["apply", "--only", "URL"], h.deps);
  assert.equal(out.exitCode, 0, out.stdout);
  assert.equal(parse(out.stdout).approval, "dialog");
  assert.equal(h.human.approvals.length, 2);
  assert.ok(h.human.approvals[1]!.includes("Reads the clipboard: URL"), h.human.approvals[1]!.join("\n"));
  const put = h.fetch.calls.filter((c) => c.init.method === "PUT").at(-1)!;
  assert.equal(put.url, "https://api.github.com/repos/acme/web/actions/secrets/URL");
  assert.equal(openSealed(JSON.parse(put.body).encrypted_value), `https://u:${CANARY}@db`);
  assert.equal(parse(out.stdout).clipboardCleared, true);
});

test("S5: apply leaves a clipboard that changed after the read alone", async () => {
  const h = harness({ policy: githubPolicy, exec: changingClipboardExec([CANARY, "copied later"]) });
  const out = await run(["apply"], h.deps);
  assert.equal(out.exitCode, 0, out.stdout);
  assert.equal(parse(out.stdout).clipboardCleared, false);
  assert.deepEqual(h.exec.calls.filter((c) => c.command === PBCOPY), []);
  assert.equal(h.exec.calls.filter((c) => c.command === PBPASTE).length, 2);
  assert.ok(!out.stdout.includes(CANARY));
});

test("S5: apply compares after the same newline trim, so an unchanged clipboard with its newline is cleared", async () => {
  const h = harness({ policy: githubPolicy, exec: clipboardExec(`${CANARY}\r\n`) });
  const out = await run(["apply"], h.deps);
  assert.equal(parse(out.stdout).clipboardCleared, true);
  assert.deepEqual(h.exec.calls.map((c) => c.command).slice(-2), [PBPASTE, PBCOPY]);
});

test("S5: the run/resolver read leaves a changed clipboard alone", async () => {
  for (const later of ["copied later", `${CANARY}x`, CANARY.slice(1), ""]) {
    const exec = fakeExec(changingClipboardExec([CANARY, later]));
    const value = await resolveValue("API_KEY", { sensitive: true, source: { kind: "clipboard" }, targets: [] }, deps(exec));
    assert.equal(value.reveal(), CANARY);
    value.dispose();
    assert.deepEqual(exec.calls.map((c) => c.command), [PBPASTE, PBPASTE], later);
  }
});

test("S5: a failing re-read leaves the clipboard alone", async () => {
  let n = 0;
  const exec = fakeExec((call) => {
    if (call.command === PBPASTE) return n++ === 0 ? { code: 0, stdout: Buffer.from(CANARY) } : { code: 1 };
    return {};
  });
  const value = await resolveValue("API_KEY", { sensitive: true, source: { kind: "clipboard" }, targets: [] }, deps(exec));
  value.dispose();
  assert.deepEqual(exec.calls.map((c) => c.command), [PBPASTE, PBPASTE]);
});

// S3 of odd/tasks/zks-v0.5.0.md — 0.4.0 review follow-ups.

/** pbpaste answers the raw bytes of each of `reads` in turn (the last one repeats); pbcopy accepts anything. */
function rawClipboardExec(reads: Buffer[]) {
  let n = 0;
  return (call: ExecCall) => {
    if (call.command === PBPASTE) return { code: 0, stdout: Buffer.from(reads[Math.min(n++, reads.length - 1)] as Buffer) };
    if (call.command === PBCOPY) return {};
    return ghTokenExec(call);
  };
}

test("S3: an unchanged non-UTF-8 clipboard is compared byte for byte and cleared", async () => {
  const raw = Buffer.from([0xff, 0xfe, 0x41]);
  const exec = fakeExec(rawClipboardExec([raw]));
  const value = await resolveValue("API_KEY", { sensitive: true, source: { kind: "clipboard" }, targets: [] }, deps(exec));
  assert.equal(value.length, 3, "the raw bytes are kept");
  value.dispose();
  assert.deepEqual(exec.calls.map((c) => c.command), [PBPASTE, PBPASTE, PBCOPY]);

  const h = harness({ policy: githubPolicy, exec: rawClipboardExec([Buffer.concat([raw, Buffer.from("\n")])]) });
  const out = await run(["apply"], h.deps);
  assert.equal(out.exitCode, 0, out.stdout);
  assert.equal(parse(out.stdout).clipboardCleared, true);
  assert.equal(h.exec.calls.at(-1)!.command, PBCOPY);
});

test("S3: a different non-UTF-8 clipboard that decodes to the same text is left alone", async () => {
  // Both decode to "\uFFFDA": a string round trip would call them equal.
  const exec = fakeExec(rawClipboardExec([Buffer.from([0xff, 0x41]), Buffer.from([0xfe, 0x41])]));
  const value = await resolveValue("API_KEY", { sensitive: true, source: { kind: "clipboard" }, targets: [] }, deps(exec));
  value.dispose();
  assert.deepEqual(exec.calls.map((c) => c.command), [PBPASTE, PBPASTE]);
});

/** A `zks run` harness whose child is faked: it records the env it was given and exits 0. */
function runHarness(options: { approve?: boolean; exec: (call: ExecCall) => Partial<{ code: number; stdout: Buffer }> }) {
  const h = harness({ policy: githubPolicy, approve: options.approve, exec: options.exec });
  const spawned: { path: string; env: Record<string, string> }[] = [];
  h.deps.spawnInherited = (path, _args, opts) => {
    spawned.push({ path, env: { ...opts.env } });
    return { spawned: Promise.resolve(null), exited: Promise.resolve({ code: 0, signal: null }), kill: () => undefined };
  };
  // pbpaste/pbcopy calls made before the dialog answered.
  const beforeApproval: string[][] = [];
  const approve = h.deps.human.approve.bind(h.deps.human);
  h.deps.human = {
    ...h.deps.human,
    approve: async (title, lines) => {
      beforeApproval.push(h.exec.calls.map((c) => c.command).filter((c) => c === PBPASTE || c === PBCOPY));
      return approve(title, lines);
    },
  };
  return { h, spawned, beforeApproval };
}

test("S3: zks run reads a clipboard variable only after approval and clears the clipboard on read", async () => {
  const { h, spawned, beforeApproval } = runHarness({ exec: clipboardExec(`${CANARY}\n`) });
  const out = await run(["run", "--only", "API_KEY", "--", "/usr/bin/true"], h.deps);
  assert.equal(out.exitCode, 0, out.stdout);
  assert.equal(out.stdout, "");
  assert.deepEqual(beforeApproval, [[]], "nothing read before the dialog");
  assert.ok(h.human.approvals[0]!.some((l) => l.includes("API_KEY") && l.includes("the clipboard (cleared once used, if unchanged)")));
  assert.deepEqual(h.exec.calls.map((c) => c.command), [PBPASTE, PBPASTE, PBCOPY], "read, re-read, cleared");
  assert.equal(spawned.length, 1);
  assert.equal(spawned[0]!.env.API_KEY, CANARY);
  for (const call of h.exec.calls) assert.ok(!`${call.args.join(" ")} ${call.input}`.includes(CANARY));
  assert.ok(!(await auditBytes(h.auditDb)).includes(CANARY));
});

test("S3: a denied zks run never reads or clears the clipboard and starts nothing", async () => {
  const { h, spawned } = runHarness({ approve: false, exec: clipboardExec(CANARY) });
  const out = await run(["run", "--only", "API_KEY", "--", "/usr/bin/true"], h.deps);
  assert.equal(out.exitCode, 3, out.stdout);
  assert.equal(parse(out.stdout).error.code, "not_approved");
  assert.deepEqual(h.exec.calls.filter((c) => c.command === PBPASTE || c.command === PBCOPY), []);
  assert.deepEqual(spawned, []);
});

test("S3: zks rotate refuses a clipboard variable (only generated values rotate) without reading the clipboard", async () => {
  const h = await trustedHarness(githubPolicy);
  const out = await run(["rotate", "API_KEY"], h.deps);
  assert.equal(out.exitCode, 2, out.stdout);
  assert.deepEqual(parse(out.stdout).error, {
    code: "not_rotatable",
    message: "API_KEY is not generated by zks; only variables with a generate source can be rotated",
  });
  assert.equal(h.human.approvals.length, 1, "no dialog for a refused rotation");
  assert.deepEqual(h.exec.calls.filter((c) => c.command === PBPASTE || c.command === PBCOPY), []);
});

test("S3: rotating a generated value whose derived variable reads the clipboard shows the dialog for a trusted destination", async () => {
  const policy = {
    ...githubPolicy,
    variables: {
      GEN: { sensitive: true, source: { kind: "generate" }, targets: ["gh"] },
      RAW: { sensitive: true, source: { kind: "clipboard" }, targets: ["gh"] },
      URL: { sensitive: true, source: { kind: "template", template: "${GEN}-${RAW}" }, targets: ["gh"] },
    },
  };
  const h = await trustedHarness(policy);
  const out = await run(["rotate", "GEN"], h.deps);
  assert.equal(out.exitCode, 0, out.stdout);
  const body = parse(out.stdout);
  assert.equal(body.approval, "dialog");
  assert.deepEqual(body.dependents, ["URL"]);
  assert.equal(h.human.approvals.length, 2, "the trusted destination still gets the dialog");
  assert.ok(h.human.approvals[1]!.includes("Reads the clipboard: URL"), h.human.approvals[1]!.join("\n"));
  assert.equal(body.clipboardCleared, true);
  assert.ok(!out.stdout.includes(CANARY));
});

test("S3: a denied rotation never reads the clipboard", async () => {
  const policy = {
    ...githubPolicy,
    variables: {
      GEN: { sensitive: true, source: { kind: "generate" }, targets: ["gh"] },
      RAW: { sensitive: true, source: { kind: "clipboard" }, targets: ["gh"] },
      URL: { sensitive: true, source: { kind: "template", template: "${GEN}-${RAW}" }, targets: ["gh"] },
    },
  };
  const h = await trustedHarness(policy);
  h.deps.human.approveWithTrust = async () => "deny";
  const out = await run(["rotate", "GEN"], h.deps);
  assert.equal(out.exitCode, 3, out.stdout);
  assert.deepEqual(h.exec.calls.filter((c) => c.command === PBPASTE || c.command === PBCOPY), []);
});
