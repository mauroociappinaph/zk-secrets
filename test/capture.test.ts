import assert from "node:assert/strict";
import { chmodSync, existsSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { CAPTURE_WAIT_MS, buildCaptureScript, parseCaptureOutput, type CaptureScriptSpec } from "../src/capture/script.ts";
import { HELP_TEXT } from "../src/help.ts";
import { run } from "../src/run.ts";
import { CANARY, TEST_TOOLS, auditBytes, harness, parse, tempDir, type ExecCall } from "./helpers.ts";

const ORIGIN = "http://127.0.0.1:8123";
const READ = ["capture", "read", "--space", "4", "--page", "p1", "--selector", "#tok", "--store", "app/key"];
const GENERATE = ["capture", "fill", "--space", "4", "--page", "p1", "--selector", "#pw", "--store", "app/password", "--generate", "24", "--origin", ORIGIN];
const FROM = ["capture", "fill", "--space", "4", "--page", "p1", "--selector", "#pw", "--from", "app/password", "--origin", ORIGIN];
const NO_MIRROR = (pending: number) => ({ configured: false, pushed: 0, pending });

/** ego-browser answers with noise around one marker line, like the real runtime can. */
function ego(marker: string, code = 0) {
  return (call: ExecCall) =>
    call.command === TEST_TOOLS.egoBrowser
      ? { code, stdout: Buffer.from(`[ego-browser:notice] update available\n${CANARY}\n${marker}\nZKS_RESULTX {"ok":true,"length":1}\n`) }
      : {};
}
const OK = (length: number) => ego(`ZKS_RESULT {"ok":true,"length":${length}}`);

function egoCalls(h: ReturnType<typeof harness>): ExecCall[] {
  return h.exec.calls.filter((c) => c.command === TEST_TOOLS.egoBrowser);
}

function records(h: ReturnType<typeof harness>) {
  const store = h.deps.openAudit();
  try {
    return store.list({ limit: 100 });
  } finally {
    store.close();
  }
}

// Script builder

const spec = (over: Partial<CaptureScriptSpec> = {}): CaptureScriptSpec => ({
  mode: "read",
  space: 4,
  page: "p1",
  selector: "#tok",
  click: "#gen",
  origin: ORIGIN,
  service: "app",
  account: "key",
  waitMs: CAPTURE_WAIT_MS,
  ...over,
});

const AsyncFunction = Object.getPrototypeOf(async () => undefined).constructor as new (...args: string[]) => (...a: unknown[]) => Promise<void>;

/** A stand-in for /usr/bin/security: `-i` swallows stdin, find-generic-password -g prints CANARY's password line on stderr. */
function fakeSecurity(exitCode = 0): string {
  const path = join(tempDir(), "security");
  writeFileSync(path, `#!/bin/sh\nif [ "$1" = "-i" ]; then cat >/dev/null; exit ${exitCode}; fi\nprintf 'password: "%s"\\n' '${CANARY}' >&2\nexit ${exitCode}\n`);
  chmodSync(path, 0o700);
  return path;
}
const MISSING_SECURITY = "/nonexistent/zks-test/security";

/** Minimal DOM classes the in-page functions check with instanceof. */
class FakeElement {
  textContent = "";
  events: Array<{ type: string; bubbles: boolean }> = [];
  focus() {
    (globalThis as Record<string, unknown>).__zksFocused = this;
  }
  dispatchEvent(event: Event) {
    this.events.push({ type: event.type, bubbles: event.bubbles });
    return true;
  }
}
class FakeInput extends FakeElement {
  type = "text";
  #value = "";
  nativeSets = 0;
  get value() {
    return this.#value;
  }
  set value(v: string) {
    this.#value = v;
  }
}
// The native setter the fill uses; a page-level override on the instance would not be called.
const nativeValue = Object.getOwnPropertyDescriptor(FakeInput.prototype, "value")!;
Object.defineProperty(FakeInput.prototype, "value", {
  get: nativeValue.get,
  set(this: FakeInput, v: string) {
    this.nativeSets++;
    nativeValue.set!.call(this, v);
  },
});
class FakeTextArea extends FakeElement {
  value = "";
}

/** A fake page whose evaluate runs the real in-page function against a fake document. */
function domPage(options: { nodes: FakeElement[]; origin?: string; url?: () => string; over?: Record<string, unknown> }) {
  const calls: string[] = [];
  const evaluateArgs: unknown[] = [];
  (globalThis as Record<string, unknown>).__zksFocused = undefined;
  const page: Record<string, unknown> = {
    keyboard: {
      insertText: async (text: string) => {
        calls.push("insertText");
        const target = (globalThis as Record<string, unknown>).__zksFocused;
        if (target instanceof FakeInput) {
          nativeValue.set!.call(target, target.value + text);
          target.events.push({ type: "input", bubbles: true });
        }
      },
    },
    url: async () => (options.url ? options.url() : ORIGIN),
    waitForSelector: async () => void calls.push("wait"),
    click: async () => void calls.push("click"),
    fill: async () => void calls.push("fill"),
    goto: async (url: string) => void calls.push(`goto:${url}`),
    evaluate: async (fn: (arg: unknown) => unknown, arg: unknown) => {
      calls.push("evaluate");
      evaluateArgs.push(arg);
      const g = globalThis as Record<string, unknown>;
      const saved = { document: g.document, HTMLInputElement: g.HTMLInputElement, HTMLTextAreaElement: g.HTMLTextAreaElement };
      g.document = {
        location: { origin: options.origin ?? ORIGIN },
        querySelectorAll: () => options.nodes,
        // Like a real automated ego tab without OS focus: fill must not depend on hasFocus().
        hasFocus: () => false,
        get activeElement() {
          return g.__zksFocused;
        },
      };
      g.HTMLInputElement = FakeInput;
      g.HTMLTextAreaElement = FakeTextArea;
      try {
        return await fn(arg);
      } finally {
        Object.assign(g, saved);
      }
    },
    ...options.over,
  };
  return { page, calls, evaluateArgs };
}

/** Runs a generated script against a fake ego API and returns what it printed and what the page saw. */
async function runScript(script: string, page: Record<string, unknown>) {
  const printed: string[] = [];
  const spaces: unknown[] = [];
  const labels: unknown[] = [];
  const fakeConsole = { log: (...args: unknown[]) => printed.push(args.map(String).join(" ")) };
  const taskSpace = async (id: unknown) => {
    spaces.push(id);
    return {
      page: (label: unknown) => {
        labels.push(label);
        return page;
      },
    };
  };
  await new AsyncFunction("taskSpace", "console", script)(taskSpace, fakeConsole);
  return { printed, spaces, labels };
}

test("S11: the script embeds every input once through JSON.stringify", () => {
  const s = spec();
  const script = buildCaptureScript(s);
  assert.ok(script.includes(`const spec = ${JSON.stringify(s)};`));
  assert.equal(script.split(JSON.stringify(s)).length, 2);
  assert.ok(script.includes('await import("node:child_process")'));
  assert.ok(script.includes('"/usr/bin/security"'));
});

test("S11: a selector with quotes, backticks and ${} cannot break out of the script", async () => {
  const hostile = "#a\"]'`${globalThis.zksPwned=1}`\\\";globalThis.zksPwned=2;//";
  const script = buildCaptureScript(spec({ selector: hostile, click: hostile, origin: null, waitMs: 50 }));
  new AsyncFunction("taskSpace", "console", script);
  const seen: string[] = [];
  const page = {
    url: async () => ORIGIN,
    click: async (selector: string) => void seen.push(`click:${selector}`),
    waitForSelector: async (selector: string) => void seen.push(`wait:${selector}`),
    evaluate: async (_fn: unknown, arg: unknown) => {
      seen.push(`eval:${String(arg)}`);
      return 0;
    },
  };
  const { printed, spaces, labels } = await runScript(script, { ...page });
  assert.equal((globalThis as { zksPwned?: number }).zksPwned, undefined);
  assert.deepEqual(spaces, [4]);
  assert.deepEqual(labels, ["p1"]);
  assert.ok(seen.length >= 3);
  for (const entry of seen) assert.equal(entry.slice(entry.indexOf(":") + 1), hostile);
  assert.deepEqual(printed, ['ZKS_RESULT {"ok":false,"code":"not_found"}']);
});

test("S11: the script checks the origin before it clicks or reads", async () => {
  const actions: string[] = [];
  const page = {
    url: async () => "https://evil.example/tokens",
    click: async () => void actions.push("click"),
    waitForSelector: async () => void actions.push("wait"),
    evaluate: async () => void actions.push("evaluate"),
    fill: async () => void actions.push("fill"),
  };
  for (const mode of ["read", "fill"] as const) {
    const { printed } = await runScript(buildCaptureScript(spec({ mode })), page);
    assert.deepEqual(printed, ['ZKS_RESULT {"ok":false,"code":"origin_mismatch"}']);
  }
  assert.deepEqual(actions, []);
});

test("S11: any ego error inside the script becomes browser_failed, never its message", async () => {
  const page = {
    url: async () => ORIGIN,
    click: async () => {
      throw new Error(`boom ${CANARY}`);
    },
  };
  const { printed } = await runScript(buildCaptureScript(spec()), page);
  assert.deepEqual(printed, ['ZKS_RESULT {"ok":false,"code":"browser_failed"}']);
});

test("S1: a fill script never contains the value it fills; it reads the Keychain inside ego", () => {
  const script = buildCaptureScript(spec({ mode: "fill", click: null, service: "app", account: "password" }));
  assert.ok(script.includes('"find-generic-password"'));
  assert.ok(!script.includes("page.fill"), "page.fill can reach cross-origin frames");
  assert.ok(script.includes("page.keyboard.insertText("));
  assert.ok(!script.includes(CANARY));
});

// Script: fill only into one password input of the main frame, origin re-checked in the same evaluate

const fillSpec = (over: Partial<CaptureScriptSpec> = {}) => spec({ mode: "fill", click: null, selector: "#pw", account: "password", ...over });

test("S11: fill sets one password input with the native setter and input/change events, printing only the length", async () => {
  const input = new FakeInput();
  input.type = "password";
  const { page, calls } = domPage({ nodes: [input] });
  const { printed } = await runScript(buildCaptureScript(fillSpec(), fakeSecurity()), page);
  assert.deepEqual(printed, [`ZKS_RESULT {"ok":true,"length":${CANARY.length}}`]);
  assert.equal(input.value, CANARY);
  assert.equal(input.nativeSets, 1, "only the clear goes through the setter");
  assert.deepEqual(input.events, [{ type: "input", bubbles: true }, { type: "change", bubbles: true }]);
  assert.deepEqual(calls, ["wait", "evaluate", "evaluate", "insertText", "evaluate"]);
});

test("S1 (N1): the secret is typed through the keyboard and never passed into the page's JavaScript", async () => {
  const input = Object.assign(new FakeInput(), { type: "password" });
  const { page, evaluateArgs } = domPage({ nodes: [input] });
  const { printed } = await runScript(buildCaptureScript(fillSpec(), fakeSecurity()), page);
  assert.deepEqual(printed, [`ZKS_RESULT {"ok":true,"length":${CANARY.length}}`]);
  assert.equal(evaluateArgs.length, 3);
  assert.ok(!JSON.stringify(evaluateArgs).includes(CANARY), "evaluate received the secret");
});

test("S1 (N1): if the page leaves the origin before the Keychain read, the secret is never read", async () => {
  const input = Object.assign(new FakeInput(), { type: "password" });
  const urls = [ORIGIN, "https://evil.example"];
  const { page, calls } = domPage({ nodes: [input], url: () => urls.shift() ?? "https://evil.example" });
  const { printed } = await runScript(buildCaptureScript(fillSpec(), MISSING_SECURITY), page);
  assert.deepEqual(printed, ['ZKS_RESULT {"ok":false,"code":"origin_mismatch"}']);
  assert.ok(!calls.includes("insertText"));
});

test("S1 (N1): if the page leaves the origin after the Keychain read, nothing is typed", async () => {
  const input = Object.assign(new FakeInput(), { type: "password" });
  const urls = [ORIGIN, ORIGIN, "https://evil.example"];
  const { page, calls } = domPage({ nodes: [input], url: () => urls.shift() ?? "https://evil.example" });
  const { printed } = await runScript(buildCaptureScript(fillSpec(), fakeSecurity()), page);
  assert.deepEqual(printed, ['ZKS_RESULT {"ok":false,"code":"origin_mismatch"}']);
  assert.ok(!calls.includes("insertText"));
  assert.equal(input.value, "");
});

test("S11: fill refuses a textarea, a text input or several matches with not_password_field and sets nothing", async () => {
  const text = new FakeInput();
  const area = new FakeTextArea();
  const pw1 = Object.assign(new FakeInput(), { type: "password" });
  const pw2 = Object.assign(new FakeInput(), { type: "password" });
  for (const nodes of [[area], [text], [pw1, pw2], []]) {
    const { page, calls } = domPage({ nodes });
    const { printed } = await runScript(buildCaptureScript(fillSpec(), fakeSecurity()), page);
    assert.deepEqual(printed, ['ZKS_RESULT {"ok":false,"code":"not_password_field"}']);
    assert.deepEqual(calls, ["wait", "evaluate"]);
  }
  for (const node of [text, area, pw1, pw2]) {
    assert.equal(node.value, "");
    assert.deepEqual(node.events, []);
  }
  assert.equal(pw1.nativeSets + pw2.nativeSets + text.nativeSets, 0);
});

test("S11: fill re-checks the document origin inside the evaluate that sets the value", async () => {
  const input = Object.assign(new FakeInput(), { type: "password" });
  // page.url() still says ORIGIN, but the document navigated during the wait.
  const { page } = domPage({ nodes: [input], origin: "https://evil.example" });
  const { printed } = await runScript(buildCaptureScript(fillSpec(), fakeSecurity()), page);
  assert.deepEqual(printed, ['ZKS_RESULT {"ok":false,"code":"origin_mismatch"}']);
  assert.equal(input.value, "");
  assert.equal(input.nativeSets, 0);

  // A fill spec without an origin never fills.
  const { page: page2 } = domPage({ nodes: [input] });
  const noOrigin = await runScript(buildCaptureScript(fillSpec({ origin: null }), fakeSecurity()), page2);
  assert.deepEqual(noOrigin.printed, ['ZKS_RESULT {"ok":false,"code":"origin_mismatch"}']);
  assert.equal(input.value, "");
});

test("S1: an evaluate that returns anything but the expected shape is browser_failed, never relayed", async () => {
  const { page } = domPage({ nodes: [], over: { evaluate: async () => ({ ok: true, length: 3, value: CANARY }) } });
  const { printed } = await runScript(buildCaptureScript(fillSpec(), fakeSecurity()), page);
  assert.deepEqual(printed, [`ZKS_RESULT {"ok":true,"length":${CANARY.length}}`]);
  const { page: weird } = domPage({ nodes: [], over: { evaluate: async () => ({ ok: false, code: CANARY }) } });
  assert.deepEqual((await runScript(buildCaptureScript(fillSpec(), fakeSecurity()), weird)).printed, [
    'ZKS_RESULT {"ok":false,"code":"browser_failed"}',
  ]);
});

// Script: after a reveal click the page always leaves the token

test("S11: read with --click navigates to about:blank on success and on every failure path", async () => {
  const token = () => Object.assign(new FakeElement(), { textContent: CANARY });
  let n = 0;
  const cases: Array<[string, () => ReturnType<typeof domPage>, string]> = [
    ["success", () => domPage({ nodes: [token()] }), fakeSecurity()],
    ["click throws", () => domPage({ nodes: [token()], over: { click: async () => { throw new Error(CANARY); } } }), fakeSecurity()],
    ["element never attached", () => domPage({ nodes: [], over: { waitForSelector: async () => { throw new Error("timeout"); } } }), fakeSecurity()],
    ["element stays empty", () => domPage({ nodes: [new FakeElement()] }), fakeSecurity()],
    ["origin changes after the click", () => { n = 0; return domPage({ nodes: [token()], url: () => (n++ === 0 ? ORIGIN : "https://evil.example") }); }, fakeSecurity()],
    ["keychain missing", () => domPage({ nodes: [token()] }), MISSING_SECURITY],
    ["keychain refuses", () => domPage({ nodes: [token()] }), fakeSecurity(1)],
    ["evaluate throws", () => domPage({ nodes: [token()], over: { evaluate: async () => { throw new Error(CANARY); } } }), fakeSecurity()],
  ];
  const expected: Record<string, string> = {
    success: `{"ok":true,"length":${CANARY.length}}`,
    "click throws": '{"ok":false,"code":"browser_failed"}',
    "element never attached": '{"ok":false,"code":"not_found"}',
    "element stays empty": '{"ok":false,"code":"not_found"}',
    "origin changes after the click": '{"ok":false,"code":"origin_mismatch"}',
    "keychain missing": '{"ok":false,"code":"keychain_failed"}',
    "keychain refuses": '{"ok":false,"code":"keychain_failed"}',
    "evaluate throws": '{"ok":false,"code":"browser_failed"}',
  };
  for (const [name, make, security] of cases) {
    const { page, calls } = make();
    const { printed } = await runScript(buildCaptureScript(spec({ waitMs: 50 }), security), page);
    assert.deepEqual(printed, [`ZKS_RESULT ${expected[name]}`], name);
    assert.deepEqual(calls.filter((c) => c.startsWith("goto:")), ["goto:about:blank"], name);
    assert.equal(calls[calls.length - 1], "goto:about:blank", `${name}: blanked last`);
  }
});

test("S11: a read without --click still blanks after success; a failed goto is not an error", async () => {
  const { page, calls } = domPage({ nodes: [Object.assign(new FakeElement(), { textContent: CANARY })] });
  const { printed } = await runScript(buildCaptureScript(spec({ click: null }), fakeSecurity()), page);
  assert.deepEqual(printed, [`ZKS_RESULT {"ok":true,"length":${CANARY.length}}`]);
  assert.deepEqual(calls.filter((c) => c.startsWith("goto:")), ["goto:about:blank"]);

  const failingGoto = domPage({ nodes: [], over: { goto: async () => { throw new Error("nav"); } } });
  const blank = await runScript(buildCaptureScript(spec({ waitMs: 50 }), fakeSecurity()), failingGoto.page);
  assert.deepEqual(blank.printed, ['ZKS_RESULT {"ok":false,"code":"not_found"}']);
});

// Output parser

test("S1: the parser accepts only the one marker line and ignores every other line", () => {
  const noise = `ghp_${"a".repeat(36)}\nZKS_RESULT_FAKE {"ok":true,"length":9}\n  ZKS_RESULT {"ok":true,"length":8}\n`;
  assert.deepEqual(parseCaptureOutput(`${noise}ZKS_RESULT {"ok":true,"length":40}\n${CANARY}\n`), { ok: true, length: 40 });
  assert.deepEqual(parseCaptureOutput('ZKS_RESULT {"ok":false,"code":"origin_mismatch"}\r\n'), { ok: false, code: "origin_mismatch" });
  assert.deepEqual(parseCaptureOutput('ZKS_RESULT {"ok":false,"code":"not_password_field"}'), { ok: false, code: "not_password_field" });
  for (const bad of [
    "",
    noise,
    'ZKS_RESULT {"ok":true,"length":4}\nZKS_RESULT {"ok":true,"length":4}',
    "ZKS_RESULT not-json",
    'ZKS_RESULT {"ok":true}',
    'ZKS_RESULT {"ok":true,"length":0}',
    'ZKS_RESULT {"ok":true,"length":1.5}',
    `ZKS_RESULT {"ok":true,"length":4,"value":"${CANARY}"}`,
    'ZKS_RESULT {"ok":false,"code":"something_else"}',
    'ZKS_RESULT {"ok":false,"code":"not_approved"}',
    `ZKS_RESULT {"ok":false,"code":"not_found","detail":"${CANARY}"}`,
    'ZKS_RESULT ["ok"]',
  ]) {
    assert.deepEqual(parseCaptureOutput(bad), { ok: false, code: "browser_failed" }, bad);
  }
});

// CLI: read

test("S11: capture read runs its own script on ego-browser stdin and stores only metadata", async () => {
  const h = harness({ exec: OK(40) });
  const out = await run([...READ, "--click", "#gen", "--origin", ORIGIN], h.deps);
  assert.equal(out.exitCode, 0, out.stdout);
  const body = parse(out.stdout);
  assert.deepEqual(body, {
    ok: true,
    command: "capture",
    mode: "read",
    store: "app/key",
    origin: ORIGIN,
    length: 40,
    auditId: body.auditId,
    mirror: NO_MIRROR(1),
  });
  assert.equal(h.mirrorCalls, 1, "a capture syncs the audit mirror like apply");
  assert.ok(!out.stdout.includes(CANARY));

  const calls = egoCalls(h);
  assert.equal(calls.length, 1);
  assert.deepEqual(calls[0]!.args, ["nodejs"]);
  assert.equal(
    calls[0]!.input,
    buildCaptureScript({ mode: "read", space: 4, page: "p1", selector: "#tok", click: "#gen", origin: ORIGIN, service: "app", account: "key", waitMs: CAPTURE_WAIT_MS }),
  );
  assert.equal(h.human.approvals.length, 0);

  const [record] = records(h);
  assert.equal(record!.auditId, body.auditId);
  assert.deepEqual(
    {
      provider: record!.provider,
      action: record!.action,
      target: record!.target,
      environment: record!.environment,
      project: record!.project,
      variableName: record!.variableName,
      sourceKind: record!.sourceKind,
      result: record!.result,
      sensitive: record!.sensitive,
      actorAgent: record!.actorAgent,
      approval: record!.approval,
    },
    {
      provider: "keychain",
      action: "capture",
      target: "app/key",
      environment: ORIGIN,
      project: "app",
      variableName: "key",
      sourceKind: "capture-read",
      result: "applied",
      sensitive: true,
      actorAgent: "pi:test-session",
      approval: "",
    },
  );
  assert.ok(h.keychain.store.has("zks/audit-head"), "audit anchor not stored");
  const verify = parse((await run(["audit", "verify"], h.deps)).stdout);
  assert.deepEqual(verify, { ok: true, count: 1, anchored: true });
  assert.ok(!(await auditBytes(h.auditDb)).includes(CANARY));
});

test("S11: capture read without --origin reports origin null and audits an empty environment", async () => {
  const h = harness({ exec: OK(12) });
  const body = parse((await run(READ, h.deps)).stdout);
  assert.equal(body.origin, null);
  assert.equal(records(h)[0]!.environment, "");
  assert.ok(egoCalls(h)[0]!.input.includes('"origin":null'));
});

test("S11: script results map to error codes with exit 1 and a failed audit record", async () => {
  const cases: Array<[ReturnType<typeof ego>, string]> = [
    [ego('ZKS_RESULT {"ok":false,"code":"origin_mismatch"}'), "origin_mismatch"],
    [ego('ZKS_RESULT {"ok":false,"code":"not_found"}'), "not_found"],
    [ego('ZKS_RESULT {"ok":false,"code":"keychain_failed"}'), "keychain_failed"],
    [ego('ZKS_RESULT {"ok":false,"code":"not_password_field"}'), "not_password_field"],
    [ego('ZKS_RESULT {"ok":true,"length":4}', 1), "browser_failed"],
    [ego("no marker at all"), "browser_failed"],
  ];
  for (const [handler, code] of cases) {
    const h = harness({ exec: handler });
    const out = await run([...READ, "--origin", ORIGIN], h.deps);
    assert.equal(out.exitCode, 1, out.stdout);
    const body = parse(out.stdout);
    assert.equal(body.ok, false);
    assert.equal(body.command, "capture");
    assert.equal(body.error.code, code);
    assert.ok(!out.stdout.includes(CANARY), "ego output was relayed");
    assert.ok(!out.stdout.includes("ego-browser:notice"), "ego output was relayed");
    const [record] = records(h);
    assert.deepEqual([record!.result, record!.errorCode, record!.auditId], ["failed", code, body.auditId]);
    assert.deepEqual(body.mirror, NO_MIRROR(1));
    assert.equal(h.mirrorCalls, 1);
  }
});

test("S11: ego-browser prints script output on stderr; the marker is read there too, and one marker in total", async () => {
  const onStderr = harness({
    exec: (call) => (call.command === TEST_TOOLS.egoBrowser ? { stderr: Buffer.from(`${CANARY}\nZKS_RESULT {"ok":true,"length":40}\n\n`) } : {}),
  });
  const out = await run(READ, onStderr.deps);
  assert.equal(out.exitCode, 0, out.stdout);
  assert.equal(parse(out.stdout).length, 40);
  assert.ok(!out.stdout.includes(CANARY));

  const twice = harness({
    exec: (call) =>
      call.command === TEST_TOOLS.egoBrowser
        ? { stdout: Buffer.from('ZKS_RESULT {"ok":true,"length":4}\n'), stderr: Buffer.from('ZKS_RESULT {"ok":true,"length":4}\n') }
        : {},
  });
  assert.equal(parse((await run(READ, twice.deps)).stdout).error.code, "browser_failed");
});

test("S11: an exec error running ego-browser is browser_failed", async () => {
  const h = harness();
  h.deps.exec = async () => {
    throw new Error("ENOENT");
  };
  const out = await run(READ, h.deps);
  assert.equal(out.exitCode, 1);
  assert.equal(parse(out.stdout).error.code, "browser_failed");
});

// Replace approval

test("S5: replacing an existing Keychain item asks first; deny runs nothing and is audited", async () => {
  const h = harness({ exec: OK(10), keychain: { "app/key": "old" }, approve: false });
  const out = await run([...READ, "--origin", ORIGIN], h.deps);
  assert.equal(out.exitCode, 3, out.stdout);
  const body = parse(out.stdout);
  assert.equal(body.error.code, "not_approved");
  assert.deepEqual(h.human.approvals, [
    ["Replace the Keychain item app/key?", `New value: read from ${ORIGIN} (TaskSpace 4, page p1)`],
  ]);
  assert.equal(egoCalls(h).length, 0);
  assert.equal(h.keychain.store.get("app/key"), "old");
  const [record] = records(h);
  assert.deepEqual([record!.result, record!.errorCode, record!.approval], ["denied", "not_approved", "dialog"]);
  assert.deepEqual(body.mirror, NO_MIRROR(1));
});

test("S5: an approved replacement runs the capture and records approval dialog", async () => {
  const h = harness({ exec: OK(10), keychain: { "app/key": "old" } });
  const out = await run(READ, h.deps);
  assert.equal(out.exitCode, 0, out.stdout);
  assert.deepEqual(h.human.approvals, [
    ["Replace the Keychain item app/key?", "New value: read from the current page, origin not checked (TaskSpace 4, page p1)"],
  ]);
  assert.equal(records(h)[0]!.approval, "dialog");
});

// CLI: fill

test("S1: fill --generate stores a random password in zks, then ego fills it without it in the script", async () => {
  const h = harness({ exec: OK(32) });
  const out = await run(GENERATE, h.deps);
  assert.equal(out.exitCode, 0, out.stdout);
  const body = parse(out.stdout);
  assert.deepEqual(body, {
    ok: true,
    command: "capture",
    mode: "fill",
    store: "app/password",
    origin: ORIGIN,
    length: 32,
    auditId: body.auditId,
    mirror: NO_MIRROR(1),
  });
  const generated = Buffer.alloc(24, 7).toString("base64url");
  assert.equal(h.keychain.store.get("app/password"), generated);
  const [call] = egoCalls(h);
  assert.equal(
    call!.input,
    buildCaptureScript({ mode: "fill", space: 4, page: "p1", selector: "#pw", click: null, origin: ORIGIN, service: "app", account: "password", waitMs: CAPTURE_WAIT_MS }),
  );
  for (const form of [generated, Buffer.from(generated).toString("hex"), Buffer.alloc(24, 7).toString("hex")]) {
    assert.ok(!call!.input.includes(form));
    assert.ok(!out.stdout.includes(form));
    assert.ok(call!.args.every((a) => !a.includes(form)));
  }
  assert.equal(records(h)[0]!.sourceKind, "capture-generate");
});

test("S5: fill --generate over an existing item needs approval", async () => {
  const h = harness({ exec: OK(32), keychain: { "app/password": "old" }, approve: false });
  const out = await run(replace(GENERATE, "--origin", "https://example.com"), h.deps);
  assert.equal(out.exitCode, 3);
  assert.deepEqual(h.human.approvals, [
    ["Replace the Keychain item app/password?", "New value: a random password zks generates, filled into https://example.com (TaskSpace 4, page p1)"],
  ]);
  assert.equal(h.keychain.store.get("app/password"), "old");
  assert.equal(egoCalls(h).length, 0);
});

/** An audit record as a successful capture-read/capture-generate of app/password from `origin` leaves it. */
function capturedFrom(h: ReturnType<typeof harness>, origin: string, sourceKind: "capture-read" | "capture-generate" | "capture-from" = "capture-generate") {
  const store = h.deps.openAudit();
  try {
    store.append({
      ts: "2026-11-04T11:00:00.000Z",
      actorHuman: "tester",
      actorAgent: "pi:earlier",
      project: "app",
      provider: "keychain",
      target: "app/password",
      environment: origin,
      variableName: "password",
      action: "capture",
      sensitive: true,
      sourceKind,
      result: "applied",
      // zks records the Keychain item's modification time; the fake keychain seeds items at epoch 0.
      providerVersion: new Date(0).toISOString(),
      errorCode: "",
    });
  } finally {
    store.close();
  }
}

test("S11: fill --from is silent only into the origin the item was captured or generated from", async () => {
  const h = harness({ exec: OK(14), keychain: { "app/password": "stored" } });
  capturedFrom(h, ORIGIN);
  const out = await run(FROM, h.deps);
  assert.equal(out.exitCode, 0, out.stdout);
  const body = parse(out.stdout);
  assert.deepEqual(body, {
    ok: true,
    command: "capture",
    mode: "fill",
    store: "app/password",
    origin: ORIGIN,
    length: 14,
    auditId: body.auditId,
    mirror: NO_MIRROR(2),
  });
  assert.equal(h.human.approvals.length, 0);
  assert.equal(egoCalls(h).length, 1);
  assert.equal(h.keychain.store.get("app/password"), "stored");
  const [record] = records(h);
  assert.deepEqual([record!.sourceKind, record!.environment, record!.approval], ["capture-from", ORIGIN, ""]);
});

test("S11: fill --from into another origin asks first; deny is exit 3, audited, and runs no ego", async () => {
  const other = "http://localhost:8123";
  const h = harness({ exec: OK(14), keychain: { "app/password": "stored" }, approve: false });
  capturedFrom(h, ORIGIN);
  const out = await run(replace(FROM, "--origin", other), h.deps);
  assert.equal(out.exitCode, 3, out.stdout);
  const body = parse(out.stdout);
  assert.deepEqual(body.error, { code: "not_approved", message: "filling the stored item into this origin was not approved" });
  assert.deepEqual(h.human.approvals, [[`Fill app/password into ${other}?`, `It was captured from ${ORIGIN}.`]]);
  assert.equal(egoCalls(h).length, 0);
  const [record] = records(h);
  assert.deepEqual([record!.result, record!.errorCode, record!.approval, record!.environment], ["denied", "not_approved", "dialog", other]);
  assert.equal(h.mirrorCalls, 1);
});

test("S11: an approved fill --from runs, records approval dialog and does not make the next one silent", async () => {
  const other = "https://example.com";
  const h = harness({ exec: OK(14), keychain: { "app/password": "stored" } });
  capturedFrom(h, ORIGIN);
  for (let i = 0; i < 2; i++) {
    const out = await run(replace(FROM, "--origin", other), h.deps);
    assert.equal(out.exitCode, 0, out.stdout);
    assert.equal(records(h)[0]!.approval, "dialog");
  }
  assert.equal(h.human.approvals.length, 2);
  assert.equal(egoCalls(h).length, 2);
  assert.ok(egoCalls(h)[0]!.input.includes(`"origin":"${other}"`));
});

test("S11: fill --from of an item with no capture record, or one read without --origin, asks with origin unknown", async () => {
  const none = harness({ exec: OK(14), keychain: { "app/password": "stored" }, approve: false });
  assert.equal((await run(FROM, none.deps)).exitCode, 3);
  assert.deepEqual(none.human.approvals, [[`Fill app/password into ${ORIGIN}?`, "It was captured from unknown."]]);

  const blank = harness({ exec: OK(14), keychain: { "app/password": "stored" }, approve: false });
  capturedFrom(blank, "", "capture-read");
  assert.equal((await run(FROM, blank.deps)).exitCode, 3);
  assert.deepEqual(blank.human.approvals, [[`Fill app/password into ${ORIGIN}?`, "It was captured from unknown."]]);

  // A previous fill of the item is not where it came from.
  const filled = harness({ exec: OK(14), keychain: { "app/password": "stored" }, approve: false });
  capturedFrom(filled, ORIGIN, "capture-from");
  assert.equal((await run(FROM, filled.deps)).exitCode, 3);
  assert.equal(egoCalls(filled).length, 0);
});

test("S11: fill --from of a missing item is not_found with no dialog and no ego", async () => {
  const missing = harness({ exec: OK(14) });
  const miss = await run(FROM, missing.deps);
  assert.equal(miss.exitCode, 1);
  assert.equal(parse(miss.stdout).error.code, "not_found");
  assert.equal(egoCalls(missing).length, 0);
  assert.equal(missing.human.approvals.length, 0);
  assert.deepEqual([records(missing)[0]!.result, records(missing)[0]!.errorCode], ["failed", "not_found"]);
});

test("S11: capture fill needs --origin, with --generate and with --from", async () => {
  const without = (argv: string[]) => argv.slice(0, argv.indexOf("--origin"));
  await refused(without(GENERATE), "capture fill needs --origin");
  await refused(without(FROM), "capture fill needs --origin", harness({ exec: OK(4), keychain: {} }));
});

// Validation

const usage = (message: string) => ({ ok: false, error: { code: "usage", message } });

async function refused(argv: string[], message: string, h = harness({ exec: OK(4) })) {
  const out = await run(argv, h.deps);
  assert.equal(out.exitCode, 2, `${argv.join(" ")}\n${out.stdout}`);
  assert.deepEqual(parse(out.stdout), usage(message), argv.join(" "));
  assert.equal(h.exec.calls.length, 0);
  assert.equal(h.human.approvals.length, 0);
  assert.equal(existsSync(h.auditDb), false);
  assert.equal(h.keychain.store.size, 0);
  return out;
}

const replace = (argv: string[], flag: string, value: string) => {
  const i = argv.indexOf(flag);
  return [...argv.slice(0, i + 1), value, ...argv.slice(i + 2)];
};

test("S11: --space must be a positive integer", async () => {
  for (const bad of ["0", "-1", "1.5", "abc", "01", "99999999999"]) {
    await refused(replace(READ, "--space", bad), "--space must be a positive integer (the TaskSpace id)");
  }
});

test("S11: --page must be a short ego page label", async () => {
  await run(replace(READ, "--page", "a".repeat(32)), harness({ exec: OK(4) }).deps).then((o) => assert.equal(o.exitCode, 0, o.stdout));
  for (const bad of ["a".repeat(33), "p 1", "p1;x", "p/1"]) {
    await refused(replace(READ, "--page", bad), "--page must be an ego page label (letters, digits, _ or -, at most 32)");
  }
});

test("S1: selectors are 1-300 printable ASCII characters and a bad one is never echoed", async () => {
  await run(replace(READ, "--selector", "s".repeat(300)), harness({ exec: OK(4) }).deps).then((o) => assert.equal(o.exitCode, 0, o.stdout));
  for (const bad of ["s".repeat(301), `#a\n${CANARY}`, `#é${CANARY}`, ""]) {
    const out = await refused(replace(READ, "--selector", bad), "--selector must be 1-300 printable ASCII characters");
    assert.ok(!out.stdout.includes(CANARY));
  }
  await refused([...READ, "--click", "\t"], "--click must be 1-300 printable ASCII characters");
});

test("S11: --store and --from are SERVICE/ACCOUNT with safe identifiers", async () => {
  for (const bad of ["app", "app/", "/key", "app/key/x", "a b/key", `app/${"k".repeat(129)}`]) {
    await refused(replace(READ, "--store", bad), "--store must be SERVICE/ACCOUNT, each matching ^[A-Za-z0-9_.-]{1,128}$");
  }
  await refused(replace(FROM, "--from", "app"), "--from must be SERVICE/ACCOUNT, each matching ^[A-Za-z0-9_.-]{1,128}$");
});

test("S11: --origin is an https origin or a loopback http origin", async () => {
  for (const good of ["https://vercel.com", "https://a.b-c.io:8443", "http://127.0.0.1:9000", "http://localhost"]) {
    await run([...READ, "--origin", good], harness({ exec: OK(4) }).deps).then((o) => assert.equal(o.exitCode, 0, `${good} ${o.stdout}`));
  }
  for (const bad of ["http://vercel.com", "https://vercel.com/", "https://Vercel.com", "https://vercel.com/x", "https://u@vercel.com", "http://127.0.0.2", "javascript:1", `https://${"a".repeat(200)}.com`]) {
    await refused([...READ, "--origin", bad], "--origin must be https://host[:port] or http://127.0.0.1|localhost[:port]");
  }
});

test("S11: fill takes --store with --generate 16-128, or --from alone", async () => {
  const fillBase = ["capture", "fill", "--space", "4", "--page", "p1", "--selector", "#pw"];
  const message = "capture fill takes --store with --generate, or --from alone";
  await refused([...fillBase, "--store", "app/pw"], message);
  await refused([...fillBase, "--generate", "24"], message);
  await refused([...fillBase, "--store", "app/pw", "--generate", "24", "--from", "app/x"], message);
  await refused([...fillBase, "--store", "app/pw", "--from", "app/x"], message);
  await refused(fillBase, message);
  for (const bad of ["15", "129", "2x", "24.0"]) {
    await refused(replace(GENERATE, "--generate", bad), "--generate must be an integer between 16 and 128");
  }
  for (const good of ["16", "128"]) {
    await run(replace(GENERATE, "--generate", good), harness({ exec: OK(4) }).deps).then((o) => assert.equal(o.exitCode, 0, o.stdout));
  }
});

test("S11: required options and per-command flags", async () => {
  const usageText =
    "usage: zks capture read --space ID --page LABEL --selector CSS --store SERVICE/ACCOUNT [--click SELECTOR] [--origin ORIGIN] | " +
    "zks capture fill --space ID --page LABEL --selector CSS (--store SERVICE/ACCOUNT --generate BYTES | --from SERVICE/ACCOUNT) --origin ORIGIN";
  await refused(["capture"], usageText);
  await refused(["capture", "peek"], usageText);
  for (const flag of ["--space", "--page", "--selector", "--store"]) {
    const i = READ.indexOf(flag);
    await refused([...READ.slice(0, i), ...READ.slice(i + 2)], usageText);
  }
  await refused([...READ, "--generate", "24"], "option --generate is not valid for capture read");
  await refused([...READ, "--from", "a/b"], "option --from is not valid for capture read");
  await refused([...FROM, "--click", "#x"], "option --click is not valid for capture fill");
  await refused([...READ, "--policy", "x.json"], "option --policy is not valid for capture read");
  await refused([...READ, "extra"], "unexpected argument");
  await refused([...READ, "--value", CANARY], "zks never accepts secret values on the command line; declare a source in zks.policy.json or use `zks auth set`");
});

test("S11: other commands still refuse the capture options with exit 2 and touch nothing", async () => {
  const policy = { version: 1, project: "p", targets: { gh: { provider: "github", repo: "acme/web" } }, variables: {} };
  for (const argv of [["apply", "--space", "1"], ["plan", "--origin", "https://a.com"], ["trust", "list", "--from", "a/b"]]) {
    const h = harness({ policy });
    const out = await run(argv, h.deps);
    assert.equal(out.exitCode, 2, out.stdout);
    assert.deepEqual(parse(out.stdout), usage(`option ${argv[argv.length - 2]} is not valid for ${argv.slice(0, -2).join(" ")}`));
    assert.equal(h.exec.calls.length + h.human.approvals.length + h.fetch.calls.length, 0);
    assert.equal(existsSync(h.auditDb), false);
  }
});

// Reserved service zks

const PINNED: Record<string, string> = {
  vercel: "https://vercel.com",
  railway: "https://railway.com",
  supabase: "https://supabase.com",
  "sheets-hmac": "https://script.google.com",
};

test("S11: zks provider tokens are captured only from their pinned origin", async () => {
  for (const [account, origin] of Object.entries(PINNED)) {
    const h = harness({ exec: OK(30) });
    const out = await run([...replace(READ, "--store", `zks/${account}`), "--origin", origin], h.deps);
    assert.equal(out.exitCode, 0, out.stdout);
    assert.ok(egoCalls(h)[0]!.input.includes(`"origin":"${origin}"`));

    const pinned = `zks/${account} can only be captured with --origin ${origin}`;
    await refused(replace(READ, "--store", `zks/${account}`), pinned);
    await refused([...replace(READ, "--store", `zks/${account}`), "--origin", "https://evil.example"], pinned);
  }
});

test("S11: other zks accounts and every zks fill are refused", async () => {
  const message = "the Keychain service zks only takes captured provider tokens: vercel, railway, supabase, sheets-hmac";
  for (const account of ["trust-hmac", "audit-head", "Vercel", "github"]) {
    await refused([...replace(READ, "--store", `zks/${account}`), "--origin", "https://vercel.com"], message);
    await refused([...replace(READ, "--store", `Zks/${account}`), "--origin", "https://vercel.com"], message);
  }
  // Any other spelling of the service would store a token zks never reads.
  await refused([...replace(READ, "--store", "ZKS/vercel"), "--origin", "https://vercel.com"], message);
  const fillMessage = "capture fill cannot use the Keychain service zks";
  await refused(replace(GENERATE, "--store", "zks/vercel"), fillMessage);
  await refused(replace(FROM, "--from", "zks/vercel"), fillMessage);
  await refused(replace(FROM, "--from", "ZKS/trust-hmac"), fillMessage);
});

// Help

test("S11: help lists both capture forms", () => {
  assert.ok(HELP_TEXT.includes("zks capture read --space ID --page LABEL --selector CSS --store SERVICE/ACCOUNT"));
  assert.ok(HELP_TEXT.includes("zks capture fill --space ID --page LABEL --selector CSS"));
  assert.ok(HELP_TEXT.includes("| --from SERVICE/ACCOUNT) --origin ORIGIN"));
  assert.ok(!HELP_TEXT.includes("--from SERVICE/ACCOUNT) [--origin ORIGIN]"));
});

test("S1 (N2): fill --from asks again when the Keychain item changed after its recorded capture", async () => {
  const h = harness({ exec: OK(14), keychain: { "app/password": "stored" }, approve: false });
  capturedFrom(h, ORIGIN);
  h.keychain.modified.set("app/password", new Date("2026-11-04T11:30:00.000Z"));
  const out = await run(FROM, h.deps);
  assert.equal(out.exitCode, 3, out.stdout);
  assert.deepEqual(h.human.approvals, [[`Fill app/password into ${ORIGIN}?`, `It was captured from ${ORIGIN}, but the item changed after that capture.`]]);
  assert.equal(egoCalls(h).length, 0);

  const unknown = harness({ exec: OK(14), keychain: { "app/password": "stored" }, approve: false });
  capturedFrom(unknown, ORIGIN);
  unknown.keychain.modified.delete("app/password");
  assert.equal((await run(FROM, unknown.deps)).exitCode, 3);
});

test("S11 (N3): the capture process timeout covers every wait inside the script", async () => {
  const { CAPTURE_TIMEOUT_MS } = await import("../src/capture/run.ts");
  assert.ok(CAPTURE_TIMEOUT_MS >= 120_000);
});

test("S1 (B1): focus moved off the password input before typing leaves no secret anywhere", async () => {
  const pw = Object.assign(new FakeInput(), { type: "password" });
  const text = Object.assign(new FakeInput(), { type: "text" });
  let n = 0;
  const { page, calls } = domPage({
    nodes: [pw],
    url: () => {
      if (++n === 3) (globalThis as Record<string, unknown>).__zksFocused = text;
      return ORIGIN;
    },
  });
  const { printed } = await runScript(buildCaptureScript(fillSpec(), fakeSecurity()), page);
  assert.deepEqual(printed, ['ZKS_RESULT {"ok":false,"code":"not_password_field"}']);
  assert.ok(!calls.includes("insertText"));
  assert.ok(!text.value.includes(CANARY) && !pw.value.includes(CANARY));
});

test("S1 (B1): if the typed text lands anywhere else, zks clears it and leaves the page", async () => {
  const pw = Object.assign(new FakeInput(), { type: "password" });
  const text = Object.assign(new FakeInput(), { type: "text" });
  const { page, calls } = domPage({ nodes: [pw] });
  // The page steals focus exactly while the browser types.
  page.keyboard = {
    insertText: async (value: string) => {
      calls.push("insertText");
      (globalThis as Record<string, unknown>).__zksFocused = text;
      text.value += value;
    },
  };
  const { printed } = await runScript(buildCaptureScript(fillSpec(), fakeSecurity()), page);
  assert.deepEqual(printed, ['ZKS_RESULT {"ok":false,"code":"browser_failed"}']);
  assert.equal(text.value, "");
  assert.ok(calls.includes("goto:about:blank"));
});

test("S1 (A1): a forged mdat inside another attribute is ignored", async () => {
  const { parseKeychainDate } = await import("../src/platform/keychain.ts");
  const attrs =
    '    0x00000007 <blob>=""mdat"<timedate>=x "19700101000000Z"\n' +
    '    "mdat"<timedate>=0x32303236313130343137353330325A00  "20261104175302Z\\000"\n';
  assert.equal(parseKeychainDate(attrs)?.toISOString(), "2026-11-04T17:53:02.000Z");
});

test("S5 (A2): fill --from asks again when the item's modification time differs from the recorded one", async () => {
  const h = harness({ exec: OK(14), keychain: { "app/password": "stored" }, approve: false });
  capturedFrom(h, ORIGIN);
  h.keychain.modified.set("app/password", new Date("2026-11-04T11:00:00.000Z"));
  assert.equal((await run(FROM, h.deps)).exitCode, 3);
});

test("S5 (A2): a capture records the stored item's modification time as its version", async () => {
  const h = harness({ exec: OK(32) });
  const out = await run(["capture", "fill", "--space", "4", "--page", "p1", "--selector", "#pw", "--store", "app/new", "--generate", "24", "--origin", ORIGIN], h.deps);
  assert.equal(out.exitCode, 0, out.stdout);
  const [record] = records(h);
  assert.equal(record!.providerVersion, h.keychain.modified.get("app/new")!.toISOString());
});


test("S1: a split typing that lands in both fields leaves both empty and leaves the page", async () => {
  const pw = Object.assign(new FakeInput(), { type: "password" });
  const text = Object.assign(new FakeInput(), { type: "text" });
  const { page, calls } = domPage({ nodes: [pw] });
  page.keyboard = {
    insertText: async (value: string) => {
      calls.push("insertText");
      pw.value += value.slice(0, 5);
      (globalThis as Record<string, unknown>).__zksFocused = text;
      text.value += value.slice(5);
    },
  };
  const { printed } = await runScript(buildCaptureScript(fillSpec(), fakeSecurity()), page);
  assert.deepEqual(printed, ['ZKS_RESULT {"ok":false,"code":"browser_failed"}']);
  assert.equal(pw.value, "");
  assert.equal(text.value, "");
  assert.ok(calls.includes("goto:about:blank"));
});

test("S1: the focus check itself re-checks the document origin", async () => {
  const pw = Object.assign(new FakeInput(), { type: "password" });
  let reads = 0;
  const { page, calls } = domPage({ nodes: [pw] });
  const evaluate = page.evaluate as (fn: unknown, arg: unknown) => Promise<unknown>;
  page.evaluate = async (fn: unknown, arg: unknown) => {
    const result = await evaluate(fn, arg);
    return result;
  };
  // document.location.origin turns evil from the 2nd evaluate (the focus check) on, while page.url() still matches.
  const g = globalThis as Record<string, unknown>;
  const realEvaluate = page.evaluate;
  page.evaluate = async (fn: unknown, arg: unknown) => {
    reads++;
    const run = realEvaluate as (fn: unknown, arg: unknown) => Promise<unknown>;
    if (reads < 2) return run(fn, arg);
    const saved = g.document;
    const res = await (async () => {
      const inner = evaluate as (fn: unknown, arg: unknown) => Promise<unknown>;
      const wrapped = (a: unknown) => {
        const doc = g.document as Record<string, unknown>;
        g.document = { ...doc, location: { origin: "https://evil.example" }, querySelectorAll: doc.querySelectorAll, get activeElement() { return g.__zksFocused; }, hasFocus: () => false };
        try {
          return (fn as (a: unknown) => unknown)(a);
        } finally {
          g.document = doc;
        }
      };
      return inner(wrapped, arg);
    })();
    g.document = saved;
    return res;
  };
  const { printed } = await runScript(buildCaptureScript(fillSpec(), fakeSecurity()), page);
  assert.deepEqual(printed, ['ZKS_RESULT {"ok":false,"code":"not_password_field"}']);
  assert.ok(!calls.includes("insertText"));
  assert.ok(!pw.value.includes(CANARY));
});

test("S5: fill --from with a capture record that has no item time asks first", async () => {
  const h = harness({ exec: OK(14), keychain: { "app/password": "stored" }, approve: false });
  capturedFrom(h, ORIGIN);
  const store = h.deps.openAudit();
  store.close();
  // Re-record the capture without an item time, as an older zks version would have.
  const s2 = h.deps.openAudit();
  try {
    s2.append({ ts: "2026-11-04T11:30:00.000Z", actorHuman: "tester", actorAgent: "pi:old", project: "app", provider: "keychain", target: "app/password", environment: ORIGIN, variableName: "password", action: "capture", sensitive: true, sourceKind: "capture-generate", result: "applied", providerVersion: "", errorCode: "" });
  } finally {
    s2.close();
  }
  assert.equal((await run(FROM, h.deps)).exitCode, 3);
});

test("S1 (N4): a contenteditable that received the typed text is cleared too", async () => {
  const pw = Object.assign(new FakeInput(), { type: "password" });
  const editable = Object.assign(new FakeElement(), { isContentEditable: true, textContent: "" });
  const { page } = domPage({ nodes: [pw] });
  page.keyboard = {
    insertText: async (value: string) => {
      (globalThis as Record<string, unknown>).__zksFocused = editable;
      editable.textContent += value;
    },
  };
  const { printed } = await runScript(buildCaptureScript(fillSpec(), fakeSecurity()), page);
  assert.deepEqual(printed, ['ZKS_RESULT {"ok":false,"code":"browser_failed"}']);
  assert.equal(editable.textContent, "");
});
