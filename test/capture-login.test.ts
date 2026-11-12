import assert from "node:assert/strict";
import { chmodSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { LOGIN_RECIPES } from "../src/capture/recipes.ts";
import { CAPTURE_WAIT_MS, buildCaptureScript, parseCaptureOutput, parseLoginOutput, type CaptureScriptSpec } from "../src/capture/script.ts";
import { HELP_TEXT } from "../src/help.ts";
import { run } from "../src/run.ts";
import { CANARY, TEST_TOOLS, auditBytes, harness, parse, tempDir, type ExecCall } from "./helpers.ts";

// zks capture login: log a browser session into a site with a stored password the agent never sees.

const ORIGIN = "http://127.0.0.1:8123";
const URL_ = `${ORIGIN}/login`;
const USER = "admin@example.com";
const ITEM = "site/password";
const PROFILE = "zks-capture";
const SUBMIT = "button[type=submit]";
const LOGIN = [
  "capture", "login", "--space", "4", "--page", "p1", "--origin", ORIGIN, "--url", URL_, "--user", USER,
  "--user-selector", "#email", "--password-selector", "#pw", "--submit-selector", SUBMIT, "--from", ITEM,
];
const ISO_LOGIN = ["capture", "login", "--isolated", ...LOGIN.slice(6)];
const NO_MIRROR = (pending: number) => ({ configured: false, pushed: 0, pending });
const LOGIN_USAGE =
  "usage: zks capture login --origin ORIGIN --url URL --user USERNAME --user-selector CSS --password-selector CSS " +
  "--submit-selector SELECTOR --from SERVICE/ACCOUNT [--success-selector CSS] [--recipe NAME] [--agent LABEL] " +
  "(--isolated | --space ID --page LABEL)";

function ego(marker: string) {
  return (call: ExecCall) => (call.command === TEST_TOOLS.egoBrowser ? { stdout: Buffer.from(`${CANARY}\n${marker}\n`) } : {});
}
const LOGGED_IN = ego(`ZKS_RESULT {"ok":true,"loggedIn":true,"finalOrigin":"${ORIGIN}"}`);

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

function withItem(options: Parameters<typeof harness>[0] = {}) {
  return harness({ keychain: { [ITEM]: CANARY }, exec: LOGGED_IN, ...options });
}

function replace(argv: string[], flag: string, value: string): string[] {
  const i = argv.indexOf(flag);
  return [...argv.slice(0, i + 1), value, ...argv.slice(i + 2)];
}

function without(argv: string[], flag: string): string[] {
  const i = argv.indexOf(flag);
  return [...argv.slice(0, i), ...argv.slice(i + 2)];
}

function dialog(browser: string, provenance = "The item was captured from unknown."): string[] {
  return [
    `Log in to ${ORIGIN}?`,
    `Page: ${URL_}`,
    `User: ${USER}`,
    `Password: Keychain item ${ITEM}, typed into the password field, then the form is submitted (log in).`,
    provenance,
    `Browser: ${browser}; the logged-in session then stays in that browser profile.`,
    "zks asks on every login.",
  ];
}
const AGENT_BROWSER = "TaskSpace 4, page p1";

async function refused(argv: string[], message: string) {
  const h = withItem();
  const out = await run(argv, h.deps);
  assert.equal(out.exitCode, 2, out.stdout);
  assert.deepEqual(parse(out.stdout), { ok: false, error: { code: "usage", message } });
  assert.equal(h.exec.calls.length + h.human.approvals.length, 0);
  assert.equal(existsSync(h.auditDb), false);
  assert.ok(!out.stdout.includes(CANARY));
}

// zks side: dialog, denial, outcomes, audit

test("S1/S2/S5: a login asks every time, runs zks's own script and audits metadata only", async () => {
  const h = withItem();
  for (let i = 1; i <= 2; i++) {
    const out = await run(LOGIN, h.deps);
    assert.equal(out.exitCode, 0, out.stdout);
    const body = parse(out.stdout);
    assert.deepEqual(body, {
      ok: true,
      command: "capture",
      mode: "login",
      origin: ORIGIN,
      from: ITEM,
      loggedIn: true,
      finalOrigin: ORIGIN,
      auditId: body.auditId,
      mirror: NO_MIRROR(i),
    });
    assert.ok(!out.stdout.includes(CANARY));
    assert.ok(!out.stdout.includes(USER), "the username stays out of the output");
  }
  assert.deepEqual(h.human.approvals, [dialog(AGENT_BROWSER), dialog(AGENT_BROWSER)], "S2: no trust, no silent login");

  const calls = egoCalls(h);
  assert.equal(calls.length, 2);
  assert.deepEqual(calls[0]!.args, ["nodejs"]);
  const expected: CaptureScriptSpec = {
    mode: "login",
    space: 4,
    page: "p1",
    selector: "#pw",
    click: null,
    origin: ORIGIN,
    service: "site",
    account: "password",
    waitMs: CAPTURE_WAIT_MS,
    login: { url: URL_, user: USER, userSelector: "#email", submitSelector: SUBMIT, successSelector: null },
  };
  assert.equal(calls[0]!.input, buildCaptureScript(expected));
  assert.ok(calls[0]!.input.includes(`"login":{"url":${JSON.stringify(URL_)},"user":${JSON.stringify(USER)},"userSelector":"#email"`));
  assert.ok(!calls[0]!.input.includes(CANARY), "S1: the password is never in the script");

  const [record] = records(h);
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
      errorCode: record!.errorCode,
      approval: record!.approval,
      actorAgent: record!.actorAgent,
    },
    {
      provider: "capture",
      action: "capture",
      target: ORIGIN,
      environment: "",
      project: "site",
      variableName: ITEM,
      sourceKind: "capture-login",
      result: "applied",
      errorCode: "",
      approval: "dialog",
      actorAgent: "pi:test-session",
    },
  );
  const bytes = await auditBytes(h.auditDb);
  assert.ok(!bytes.includes(CANARY), "S1: the password never reaches the audit db or -wal");
  assert.ok(!bytes.includes(USER), "S5: the username stays out of the audit");
});

test("S1: --agent labels the audit record", async () => {
  const h = withItem();
  assert.equal((await run([...LOGIN, "--agent", "claude:t1"], h.deps)).exitCode, 0);
  assert.equal(records(h)[0]!.actorAgent, "claude:t1");
});

test("S2: denial reads nothing, runs no ego, exits 3 and is audited denied", async () => {
  const h = withItem({ approve: false });
  const out = await run(LOGIN, h.deps);
  assert.equal(out.exitCode, 3, out.stdout);
  const body = parse(out.stdout);
  assert.deepEqual(body, {
    ok: false,
    command: "capture",
    mode: "login",
    origin: ORIGIN,
    from: ITEM,
    error: { code: "not_approved", message: "the login was not approved; nothing was read" },
    auditId: body.auditId,
    mirror: NO_MIRROR(1),
  });
  assert.equal(egoCalls(h).length, 0);
  const [record] = records(h);
  assert.deepEqual([record!.result, record!.errorCode, record!.approval, record!.sourceKind], ["denied", "not_approved", "dialog", "capture-login"]);
});

test("S2: the dialog names where the item was captured, and a changed item", async () => {
  const h = withItem();
  const store = h.deps.openAudit();
  try {
    store.append({
      ts: "2026-11-04T11:00:00.000Z", actorHuman: "tester", actorAgent: "a", project: "site", provider: "keychain", target: ITEM,
      environment: "https://portal.example", variableName: "password", action: "capture", sensitive: true, sourceKind: "capture-generate",
      result: "applied", providerVersion: new Date(0).toISOString(), errorCode: "",
    });
  } finally {
    store.close();
  }
  await run(LOGIN, h.deps);
  h.keychain.modified.set(ITEM, new Date("2026-11-04T11:30:00.000Z"));
  await run(LOGIN, h.deps);
  assert.deepEqual(h.human.approvals, [
    dialog(AGENT_BROWSER, "The item was captured from https://portal.example."),
    dialog(AGENT_BROWSER, "The item was captured from https://portal.example, but it changed after that capture."),
  ]);
});

test("S1: a missing item is not_found with no dialog and no ego", async () => {
  const h = harness({ exec: LOGGED_IN });
  const out = await run(LOGIN, h.deps);
  assert.equal(out.exitCode, 1, out.stdout);
  assert.deepEqual(parse(out.stdout).error, { code: "not_found", message: "the element or the Keychain item was not found" });
  assert.equal(egoCalls(h).length + h.human.approvals.length, 0);
  assert.deepEqual([records(h)[0]!.result, records(h)[0]!.errorCode], ["failed", "not_found"]);
});

test("S3: pending 2fa, captcha or unknown is exit 0 with loggedIn false", async () => {
  for (const pending of ["2fa", "captcha", "unknown"]) {
    const h = withItem({ exec: ego(`ZKS_RESULT {"ok":true,"loggedIn":false,"finalOrigin":"${ORIGIN}","pending":"${pending}"}`) });
    const out = await run(LOGIN, h.deps);
    assert.equal(out.exitCode, 0, out.stdout);
    const body = parse(out.stdout);
    assert.deepEqual(body, {
      ok: true, command: "capture", mode: "login", origin: ORIGIN, from: ITEM,
      loggedIn: false, finalOrigin: ORIGIN, pending, auditId: body.auditId, mirror: NO_MIRROR(1),
    });
    assert.deepEqual([records(h)[0]!.result, records(h)[0]!.errorCode], ["applied", ""]);
  }
});

test("S3: leaving the origin is login_redirected with the final origin only", async () => {
  const h = withItem({ exec: ego('ZKS_RESULT {"ok":false,"code":"login_redirected","finalOrigin":"https://sso.example"}') });
  const out = await run(LOGIN, h.deps);
  assert.equal(out.exitCode, 1, out.stdout);
  const body = parse(out.stdout);
  assert.deepEqual(body, {
    ok: false, command: "capture", mode: "login", origin: ORIGIN, from: ITEM,
    error: { code: "login_redirected", message: "the page left --origin during the login (final origin https://sso.example)" },
    finalOrigin: "https://sso.example",
    auditId: body.auditId,
    mirror: NO_MIRROR(1),
  });
  assert.deepEqual([records(h)[0]!.result, records(h)[0]!.errorCode], ["failed", "login_redirected"]);
});

test("S3: only the expected result shapes are accepted; anything else is browser_failed", () => {
  const ok = (o: unknown) => parseLoginOutput(`noise\nZKS_RESULT ${JSON.stringify(o)}\n`);
  assert.deepEqual(ok({ ok: true, loggedIn: true, finalOrigin: ORIGIN }), { ok: true, loggedIn: true, finalOrigin: ORIGIN });
  assert.deepEqual(ok({ ok: true, loggedIn: false, finalOrigin: ORIGIN, pending: "2fa" }), { ok: true, loggedIn: false, finalOrigin: ORIGIN, pending: "2fa" });
  assert.deepEqual(ok({ ok: false, code: "not_found" }), { ok: false, code: "not_found" });
  const failed = { ok: false, code: "browser_failed" };
  for (const bad of [
    { ok: true, loggedIn: true, finalOrigin: ORIGIN, pending: "2fa" },
    { ok: true, loggedIn: false, finalOrigin: ORIGIN },
    { ok: true, loggedIn: false, finalOrigin: ORIGIN, pending: "sms" },
    { ok: true, loggedIn: "yes", finalOrigin: ORIGIN },
    { ok: true, loggedIn: true, finalOrigin: `${ORIGIN}/${CANARY} x` },
    { ok: true, loggedIn: true, finalOrigin: ORIGIN, user: USER },
    { ok: true, length: 4 },
    { ok: false, code: "login_redirected" },
    { ok: false, code: "nope" },
  ]) {
    assert.deepEqual(ok(bad), failed, JSON.stringify(bad));
  }
  assert.deepEqual(parseLoginOutput("ZKS_RESULT {}\nZKS_RESULT {}"), failed);
});

test("S1: zks capture fill and read still reject the login result shape (preserve)", async () => {
  const h = harness({ exec: LOGGED_IN });
  const out = await run(["capture", "read", "--space", "4", "--page", "p1", "--selector", "#t", "--store", "app/key"], h.deps);
  assert.equal(out.exitCode, 1, out.stdout);
  assert.equal(parse(out.stdout).error.code, "browser_failed");
});

test("R3-005: parseCaptureOutput rejects a read/fill result carrying the login_redirected code", () => {
  const failed = { ok: false, code: "browser_failed" };
  assert.deepEqual(parseCaptureOutput('ZKS_RESULT {"ok":false,"code":"login_redirected"}\n'), failed);
  assert.deepEqual(parseCaptureOutput(`ZKS_RESULT {"ok":false,"code":"login_redirected","finalOrigin":"${ORIGIN}"}\n`), failed);
  assert.deepEqual(parseCaptureOutput('ZKS_RESULT {"ok":false,"code":"not_found"}\n'), { ok: false, code: "not_found" });
});

// Usage

test("S1: required flags, validation and refusals never echo a value", async () => {
  await refused(["capture", "login"], LOGIN_USAGE);
  for (const flag of ["--origin", "--url", "--user", "--user-selector", "--password-selector", "--submit-selector", "--from"]) {
    await refused(without(LOGIN, flag), LOGIN_USAGE);
  }
  await refused(without(without(LOGIN, "--space"), "--page"), LOGIN_USAGE);
  await refused([...ISO_LOGIN, "--space", "4"], "--isolated cannot be combined with --space or --page");
  await refused(replace(LOGIN, "--url", "https://evil.example/login"), "--url must be on --origin");
  await refused(replace(LOGIN, "--url", "javascript:alert(1)"), "--url must be an http(s) URL of at most 1000 printable ASCII characters");
  await refused(replace(LOGIN, "--origin", "ftp://x"), "--origin must be https://host[:port] or http://127.0.0.1|localhost[:port]");
  for (const bad of [`${CANARY}\u0001`, "", "a".repeat(255), " lead"]) {
    await refused(replace(LOGIN, "--user", bad || " "), "--user must be 1-254 printable ASCII characters");
  }
  for (const flag of ["--user-selector", "--password-selector", "--submit-selector"]) {
    await refused(replace(LOGIN, flag, `${CANARY}\n`), `${flag} must be 1-300 printable ASCII characters`);
  }
  await refused([...LOGIN, "--success-selector", "x".repeat(301)], "--success-selector must be 1-300 printable ASCII characters");
  await refused(replace(LOGIN, "--from", "zks/vercel"), "capture login cannot use the Keychain service zks");
  await refused(replace(LOGIN, "--from", "bad"), "--from must be SERVICE/ACCOUNT, each matching ^[A-Za-z0-9_.-]{1,128}$");
  await refused([...LOGIN, "--store", "a/b"], "option --store is not valid for capture login");
  await refused([...LOGIN, "--password", CANARY], "zks never accepts secret values on the command line; declare a source in zks.policy.json or use `zks auth set`");
  await refused([...LOGIN, "--recipe", CANARY], "unknown recipe; `zks capture recipes` lists them");
  await refused([...LOGIN, "extra"], "unexpected argument");
});

test("S2: a dialog line over 300 characters is dialog_too_long; nothing is read", async () => {
  const h = withItem();
  const out = await run(replace(LOGIN, "--url", `${URL_}?${"a".repeat(400)}`), h.deps);
  assert.equal(out.exitCode, 2, out.stdout);
  assert.deepEqual(parse(out.stdout), {
    ok: false,
    error: { code: "dialog_too_long", message: TOO_LONG },
  });
  assert.equal(egoCalls(h).length + h.human.approvals.length, 0);
});

const TOO_LONG = "the approval text is too long for one dialog (a line over 300 characters: shorten --url, --user or the --from item name)";

test("R3-003: dialog_too_long names every flag that can make a line long, including the --from item name", async () => {
  for (const argv of [replace(LOGIN, "--from", `${"s".repeat(128)}/${"a".repeat(128)}`)]) {
    const h = withItem({ keychain: { [argv[argv.indexOf("--from") + 1]!]: CANARY } });
    const out = await run(argv, h.deps);
    assert.equal(out.exitCode, 2, out.stdout);
    assert.deepEqual(parse(out.stdout), { ok: false, error: { code: "dialog_too_long", message: TOO_LONG } });
    assert.equal(egoCalls(h).length + h.human.approvals.length, 0);
  }
});

test("S1 (preserve): capture read/fill usage and the forbidden --password flag are unchanged", async () => {
  const h = harness();
  const out = await run(["capture", "peek"], h.deps);
  assert.equal(parse(out.stdout).error.message,
    "usage: zks capture read --space ID --page LABEL --selector CSS --store SERVICE/ACCOUNT [--click SELECTOR] [--origin ORIGIN] | " +
    "zks capture fill --space ID --page LABEL --selector CSS (--store SERVICE/ACCOUNT --generate BYTES | --from SERVICE/ACCOUNT) --origin ORIGIN");
  const fill = await run(["capture", "fill", "--space", "4", "--page", "p1", "--selector", "#pw", "--from", ITEM, "--origin", ORIGIN, "--user", USER], h.deps);
  assert.equal(parse(fill.stdout).error.message, "option --user is not valid for capture fill");
});

// Isolated

test("S1: an isolated login runs in the capture profile; no profile is isolated_profile_unset before any dialog", async () => {
  const h = withItem();
  h.config = { capture: { profileId: PROFILE } };
  const out = await run(ISO_LOGIN, h.deps);
  assert.equal(out.exitCode, 0, out.stdout);
  assert.equal(parse(out.stdout).isolated, true);
  assert.deepEqual(h.human.approvals, [dialog(`isolated ego-browser profile ${PROFILE}`)]);
  const script = egoCalls(h)[0]!.input;
  assert.ok(script.includes(`"isolated":{"profileId":"${PROFILE}","url":"${URL_}","name":"zks-capture-0707070707070707"}`));

  assert.equal(parse(out.stdout).space, undefined, "a finished login reports no space");

  const unset = withItem();
  const res = await run(ISO_LOGIN, unset.deps);
  assert.equal(res.exitCode, 1, res.stdout);
  assert.equal(parse(res.stdout).error.code, "isolated_profile_unset");
  assert.equal(egoCalls(unset).length + unset.human.approvals.length, 0);
});

test("R3-002: an isolated pending login reports the space and page it left open; a pending --space login does not", async () => {
  for (const pending of ["2fa", "captcha", "unknown"]) {
    const marker = ego(`ZKS_RESULT {"ok":true,"loggedIn":false,"finalOrigin":"${ORIGIN}","pending":"${pending}"}`);
    const h = withItem({ exec: marker });
    h.config = { capture: { profileId: PROFILE } };
    const out = await run(ISO_LOGIN, h.deps);
    assert.equal(out.exitCode, 0, out.stdout);
    const body = parse(out.stdout);
    assert.deepEqual(body, {
      ok: true, command: "capture", mode: "login", origin: ORIGIN, from: ITEM, isolated: true,
      loggedIn: false, finalOrigin: ORIGIN, pending, space: "zks-capture-0707070707070707", page: "p1",
      auditId: body.auditId, mirror: NO_MIRROR(1),
    });
    const own = withItem({ exec: marker });
    assert.equal(parse((await run(LOGIN, own.deps)).stdout).space, undefined);
  }
});

// Recipes

test("S4: capture recipes lists every recipe with its fields and verified flag", async () => {
  const out = await run(["capture", "recipes"], harness().deps);
  assert.equal(out.exitCode, 0, out.stdout);
  assert.deepEqual(parse(out.stdout), {
    ok: true,
    recipes: [
      {
        name: "hostgator",
        origin: "https://portal.hostgator.com",
        url: "https://portal.hostgator.com/login",
        userSelector: "input[name=email]",
        passwordSelector: "input[name=password]",
        submitSelector: "button[type=submit]",
        successSelector: null,
        requiresOrigin: false,
        verified: false,
      },
      {
        name: "cpanel",
        origin: null,
        url: null,
        userSelector: "#user",
        passwordSelector: "#pass",
        submitSelector: "#login_submit",
        successSelector: null,
        requiresOrigin: true,
        verified: false,
      },
    ],
  });
  assert.deepEqual(Object.keys(LOGIN_RECIPES), ["hostgator", "cpanel"]);
  await refused(["capture", "recipes", "--origin", ORIGIN], "option --origin is not valid for capture recipes");
});

test("S4: --recipe fills the missing flags; explicit flags win", async () => {
  const base = ["capture", "login", "--recipe", "hostgator", "--space", "4", "--page", "p1", "--user", USER, "--from", ITEM];
  const h = withItem({ exec: ego('ZKS_RESULT {"ok":true,"loggedIn":true,"finalOrigin":"https://portal.hostgator.com"}') });
  const out = await run(base, h.deps);
  assert.equal(out.exitCode, 0, out.stdout);
  assert.equal(parse(out.stdout).origin, "https://portal.hostgator.com");
  const script = egoCalls(h)[0]!.input;
  assert.ok(script.includes('"selector":"input[name=password]"'));
  assert.ok(script.includes('"origin":"https://portal.hostgator.com"'));
  assert.ok(script.includes('"login":{"url":"https://portal.hostgator.com/login","user":"admin@example.com","userSelector":"input[name=email]","submitSelector":"button[type=submit]","successSelector":null}'));
  assert.equal(h.human.approvals[0]![0], "Log in to https://portal.hostgator.com?");

  const own = withItem({ exec: ego('ZKS_RESULT {"ok":true,"loggedIn":true,"finalOrigin":"https://portal.hostgator.com"}') });
  await run([...base, "--submit-selector", "#go", "--success-selector", "#dashboard"], own.deps);
  const ownScript = egoCalls(own)[0]!.input;
  assert.ok(ownScript.includes('"submitSelector":"#go","successSelector":"#dashboard"'));

  await refused(["capture", "login", "--recipe", "cpanel", "--space", "4", "--page", "p1", "--user", USER, "--from", ITEM], "recipe cpanel needs --origin");
  const cp = withItem({ exec: ego('ZKS_RESULT {"ok":true,"loggedIn":true,"finalOrigin":"https://host.example:2083"}') });
  const cpOut = await run(["capture", "login", "--recipe", "cpanel", "--origin", "https://host.example:2083", "--space", "4", "--page", "p1", "--user", USER, "--from", ITEM], cp.deps);
  assert.equal(cpOut.exitCode, 0, cpOut.stdout);
  assert.ok(egoCalls(cp)[0]!.input.includes('"login":{"url":"https://host.example:2083/","user":"admin@example.com","userSelector":"#user","submitSelector":"#login_submit"'));
});

// Help

test("S6: help documents capture login and capture recipes", () => {
  assert.ok(HELP_TEXT.includes("zks capture login --origin ORIGIN --url URL --user USERNAME --user-selector CSS --password-selector CSS"));
  assert.ok(HELP_TEXT.includes("zks capture recipes"));
  assert.ok(HELP_TEXT.includes("--recipe NAME"));
});

// Script, run against a fake ego page and a fake security; never the real ones.

class FakeNode {
  readonly sel: string[];
  constructor(sel: string[]) {
    this.sel = sel;
  }
}
class FakeInput extends FakeNode {
  type: string;
  #value = "";
  events: string[] = [];
  constructor(sel: string[], type = "text") {
    super(sel);
    this.type = type;
  }
  get value() {
    return this.#value;
  }
  set value(v: string) {
    this.#value = v;
  }
  focus() {
    (globalThis as Record<string, unknown>).__zksLoginFocused = this;
  }
  dispatchEvent(event: Event) {
    this.events.push(event.type);
    return true;
  }
}
class FakeTextArea extends FakeNode {
  value = "";
}
class FakeIframe extends FakeNode {
  readonly src: string;
  constructor(src: string) {
    super(["iframe"]);
    this.src = src;
  }
  getAttribute(name: string) {
    return name === "src" ? this.src : null;
  }
}

const OTP = 'input[type="tel"], input[type="number"], input[autocomplete="one-time-code"]';

/** Fake security: records each call; find-generic-password -g prints CANARY's password line on stderr. */
function fakeSecurity(): { path: string; log: string } {
  const dir = tempDir();
  const log = join(dir, "calls.log");
  const path = join(dir, "security");
  writeFileSync(path, `#!/bin/sh\necho "$1" >>'${log}'\nprintf 'password: "%s"\\n' '${CANARY}' >&2\nexit 0\n`);
  chmodSync(path, 0o700);
  return { path, log };
}

interface PageState {
  url: string;
  nodes: FakeNode[];
}

/** A fake ego page; evaluate runs the real in-page function against a fake document built from state. */
function loginPage(options: { landing?: string; afterSubmit?: (s: PageState) => void; clickThrows?: boolean; extra?: FakeNode[] } = {}) {
  const user = new FakeInput(["#email"]);
  const password = new FakeInput(["#pw"], "password");
  const state: PageState = { url: "about:blank", nodes: [user, password, ...(options.extra ?? [])] };
  const events: string[] = [];
  const evaluateArgs: unknown[] = [];
  (globalThis as Record<string, unknown>).__zksLoginFocused = undefined;
  const page = {
    goto: async (to: string) => {
      events.push(`goto:${to}`);
      state.url = to === "about:blank" ? to : (options.landing ?? to);
    },
    url: async () => state.url,
    waitForSelector: async (sel: string) => void events.push(`wait:${sel}`),
    click: async (sel: string) => {
      events.push(`click:${sel}`);
      if (options.clickThrows) throw new Error(`timeout ${CANARY}`);
      options.afterSubmit?.(state);
    },
    keyboard: {
      insertText: async (text: string) => {
        events.push("insertText");
        const target = (globalThis as Record<string, unknown>).__zksLoginFocused;
        if (target instanceof FakeInput) target.value = target.value + text;
      },
    },
    evaluate: async (fn: (arg: unknown) => unknown, arg: unknown) => {
      events.push("evaluate");
      evaluateArgs.push(arg);
      const g = globalThis as Record<string, unknown>;
      const saved = { document: g.document, HTMLInputElement: g.HTMLInputElement, HTMLTextAreaElement: g.HTMLTextAreaElement };
      let origin = "null";
      try {
        origin = new URL(state.url).origin;
      } catch {}
      g.document = {
        location: { origin, href: state.url },
        querySelectorAll: (sel: string) => {
          const wanted = sel.split(",").map((s) => s.trim());
          return state.nodes.filter((n) => n.sel.some((s) => wanted.includes(s)));
        },
        get activeElement() {
          return g.__zksLoginFocused;
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
  };
  return { page, state, user, password, events, evaluateArgs };
}

const AsyncFunction = Object.getPrototypeOf(async () => undefined).constructor as new (...args: string[]) => (...a: unknown[]) => Promise<void>;

const loginSpec = (over: Partial<NonNullable<CaptureScriptSpec["login"]>> = {}, spec: Partial<CaptureScriptSpec> = {}): CaptureScriptSpec => ({
  mode: "login",
  space: 4,
  page: "p1",
  selector: "#pw",
  click: null,
  origin: ORIGIN,
  service: "site",
  account: "password",
  waitMs: 60,
  login: { url: URL_, user: USER, userSelector: "#email", submitSelector: SUBMIT, successSelector: null, ...over },
  ...spec,
});

async function runLogin(spec: CaptureScriptSpec, page: Record<string, unknown>, security = fakeSecurity()) {
  const script = buildCaptureScript(spec, security.path);
  assert.ok(!script.includes('"/usr/bin/security"'), "the fake security must be in the script");
  const printed: string[] = [];
  const spaceEvents: unknown[] = [];
  const taskSpace = async (...args: unknown[]) => {
    spaceEvents.push(["taskSpace", ...args]);
    return { page: () => page, finish: async (arg: unknown) => void spaceEvents.push(["finish", arg]) };
  };
  const profiles = async () => [{ id: "Default", isDefault: true }, { id: PROFILE, isDefault: false }];
  await new AsyncFunction("taskSpace", "profiles", "console", script)(taskSpace, profiles, { log: (...a: unknown[]) => printed.push(a.join(" ")) });
  const securityCalls = existsSync(security.log) ? readFileSync(security.log, "utf8").trim().split("\n") : [];
  return { printed, spaceEvents, securityCalls };
}

const gone = (s: PageState) => {
  s.nodes = s.nodes.filter((n) => !n.sel.includes("#pw"));
};

test("S3: the script sets the user, types the stored password, submits and reports loggedIn", async () => {
  const p = loginPage({ afterSubmit: gone });
  const { printed, securityCalls } = await runLogin(loginSpec(), p.page);
  assert.deepEqual(printed, [`ZKS_RESULT {"ok":true,"loggedIn":true,"finalOrigin":"${ORIGIN}"}`]);
  assert.equal(p.user.value, USER);
  assert.deepEqual(p.user.events, ["input", "change"]);
  assert.equal(p.password.value, CANARY);
  assert.deepEqual(securityCalls, ["find-generic-password"]);
  assert.deepEqual(p.events.slice(0, 3), [`goto:${URL_}`, "wait:#email", "evaluate"]);
  assert.ok(p.events.indexOf("insertText") < p.events.indexOf(`click:${SUBMIT}`));
  assert.ok(!p.events.includes("goto:about:blank"), "a submitted login leaves the page alone");
  assert.ok(!JSON.stringify(p.evaluateArgs).includes(CANARY), "the password never enters page JavaScript");
});

test("S3: a success selector decides loggedIn when given", async () => {
  const found = loginPage({ afterSubmit: (s) => s.nodes.push(new FakeNode(["#dashboard"])) });
  const yes = await runLogin(loginSpec({ successSelector: "#dashboard" }), found.page);
  assert.deepEqual(yes.printed, [`ZKS_RESULT {"ok":true,"loggedIn":true,"finalOrigin":"${ORIGIN}"}`]);

  const missing = loginPage({ afterSubmit: gone });
  const no = await runLogin(loginSpec({ successSelector: "#dashboard" }), missing.page);
  assert.deepEqual(no.printed, [`ZKS_RESULT {"ok":true,"loggedIn":false,"finalOrigin":"${ORIGIN}","pending":"unknown"}`]);
});

test("S3: a one-time-code input is pending 2fa, a captcha iframe pending captcha, a remaining password field unknown", async () => {
  const otp = loginPage({ afterSubmit: (s) => { gone(s); s.nodes.push(new FakeInput([OTP.split(", ")[2]!], "text")); } });
  assert.deepEqual((await runLogin(loginSpec(), otp.page)).printed, [`ZKS_RESULT {"ok":true,"loggedIn":false,"finalOrigin":"${ORIGIN}","pending":"2fa"}`]);

  const tel = loginPage({ afterSubmit: (s) => { gone(s); s.nodes.push(new FakeInput(['input[type="tel"]'], "tel")); } });
  assert.deepEqual((await runLogin(loginSpec(), tel.page)).printed, [`ZKS_RESULT {"ok":true,"loggedIn":false,"finalOrigin":"${ORIGIN}","pending":"2fa"}`]);

  for (const src of ["https://newassets.hcaptcha.com/captcha/v1", "https://www.recaptcha.net/anchor", "https://www.google.com/recaptcha/api2/anchor"]) {
    const cap = loginPage({ afterSubmit: (s) => s.nodes.push(new FakeIframe(src)) });
    assert.deepEqual((await runLogin(loginSpec(), cap.page)).printed, [`ZKS_RESULT {"ok":true,"loggedIn":false,"finalOrigin":"${ORIGIN}","pending":"captcha"}`], src);
  }

  const stays = loginPage();
  assert.deepEqual((await runLogin(loginSpec(), stays.page)).printed, [`ZKS_RESULT {"ok":true,"loggedIn":false,"finalOrigin":"${ORIGIN}","pending":"unknown"}`]);
});

test("S3: landing on another origin is login_redirected; the Keychain is never read and nothing is typed", async () => {
  const p = loginPage({ landing: "https://sso.example/wall?next=x" });
  const { printed, securityCalls } = await runLogin(loginSpec(), p.page);
  assert.deepEqual(printed, ['ZKS_RESULT {"ok":false,"code":"login_redirected","finalOrigin":"https://sso.example"}']);
  assert.deepEqual(securityCalls, []);
  assert.ok(!p.events.includes("insertText"));
  assert.equal(p.user.value, "");
});

test("S3: leaving the origin after submit is login_redirected with the final origin", async () => {
  const p = loginPage({ afterSubmit: (s) => void (s.url = "https://sso.example/next") });
  const { printed } = await runLogin(loginSpec(), p.page);
  assert.deepEqual(printed, ['ZKS_RESULT {"ok":false,"code":"login_redirected","finalOrigin":"https://sso.example"}']);
});

test("S3: a failed submit blanks the password field and leaves the page", async () => {
  const p = loginPage({ clickThrows: true });
  const { printed } = await runLogin(loginSpec(), p.page);
  assert.deepEqual(printed, ['ZKS_RESULT {"ok":false,"code":"not_found"}']);
  assert.equal(p.password.value, "");
  assert.equal(p.events.at(-1), "goto:about:blank");
});

test("S3: a missing user field is not_found before the Keychain is read", async () => {
  const p = loginPage();
  p.state.nodes = p.state.nodes.filter((n) => !n.sel.includes("#email"));
  const { printed, securityCalls } = await runLogin(loginSpec(), p.page);
  assert.deepEqual(printed, ['ZKS_RESULT {"ok":false,"code":"not_found"}']);
  assert.deepEqual(securityCalls, []);
});

test("S3: an isolated login goes to the URL once, logs in and always finishes the space", async () => {
  const p = loginPage({ afterSubmit: gone });
  const iso = { profileId: PROFILE, url: URL_, name: "zks-capture-x" };
  const ok = await runLogin(loginSpec({}, { space: null, page: null, isolated: iso }), p.page);
  assert.deepEqual(ok.printed, [`ZKS_RESULT {"ok":true,"loggedIn":true,"finalOrigin":"${ORIGIN}"}`]);
  assert.equal(p.events.filter((e) => e === `goto:${URL_}`).length, 1);
  assert.deepEqual(ok.spaceEvents.at(-1), ["finish", { keep: [] }]);

  const away = loginPage({ landing: "https://sso.example/" });
  const red = await runLogin(loginSpec({}, { space: null, page: null, isolated: iso }), away.page);
  assert.deepEqual(red.printed, ['ZKS_RESULT {"ok":false,"code":"login_redirected","finalOrigin":"https://sso.example"}']);
  assert.deepEqual(red.securityCalls, []);
  assert.deepEqual(red.spaceEvents.at(-1), ["finish", { keep: [] }]);
});

test("R3-002: an isolated pending login keeps its page open; logged in or failed keeps nothing", async () => {
  const iso = { profileId: PROFILE, url: URL_, name: "zks-capture-x" };
  const spec = loginSpec({}, { space: null, page: null, isolated: iso });
  const cap = loginPage({ afterSubmit: (s) => { gone(s); s.nodes.push(new FakeIframe("https://newassets.hcaptcha.com/captcha/v1")); } });
  const pending = await runLogin(spec, cap.page);
  assert.deepEqual(pending.printed, [`ZKS_RESULT {"ok":true,"loggedIn":false,"finalOrigin":"${ORIGIN}","pending":"captcha"}`]);
  const finish = pending.spaceEvents.at(-1) as [string, { keep: unknown[] }];
  assert.equal(finish[0], "finish");
  assert.equal(finish[1].keep.length, 1);
  assert.equal(finish[1].keep[0], cap.page, "the page with the challenge stays open");

  const stays = loginPage();
  const unknown = await runLogin(spec, stays.page);
  assert.deepEqual(unknown.printed, [`ZKS_RESULT {"ok":true,"loggedIn":false,"finalOrigin":"${ORIGIN}","pending":"unknown"}`]);
  assert.equal((unknown.spaceEvents.at(-1) as [string, { keep: unknown[] }])[1].keep[0], stays.page);

  const failed = loginPage({ clickThrows: true });
  const notFound = await runLogin(spec, failed.page);
  assert.deepEqual(notFound.printed, ['ZKS_RESULT {"ok":false,"code":"not_found"}']);
  assert.deepEqual(notFound.spaceEvents.at(-1), ["finish", { keep: [] }]);
});

test("R3-001: a captcha iframe or code input already on the login page is not pending until the page changed", async () => {
  const preCaptcha = loginPage({ extra: [new FakeIframe("https://www.google.com/recaptcha/api2/anchor")] });
  assert.deepEqual((await runLogin(loginSpec(), preCaptcha.page)).printed, [`ZKS_RESULT {"ok":true,"loggedIn":false,"finalOrigin":"${ORIGIN}","pending":"unknown"}`]);

  const preTel = loginPage({ extra: [new FakeInput(['input[type="tel"]'], "tel")] });
  assert.deepEqual((await runLogin(loginSpec(), preTel.page)).printed, [`ZKS_RESULT {"ok":true,"loggedIn":false,"finalOrigin":"${ORIGIN}","pending":"unknown"}`]);

  // Once the page changed (the password field is gone), the code input counts.
  const changed = loginPage({ extra: [new FakeInput(['input[type="tel"]'], "tel")], afterSubmit: gone });
  assert.deepEqual((await runLogin(loginSpec(), changed.page)).printed, [`ZKS_RESULT {"ok":true,"loggedIn":false,"finalOrigin":"${ORIGIN}","pending":"2fa"}`]);

  // A URL change counts as a change too.
  const moved = loginPage({ extra: [new FakeInput(['input[type="tel"]'], "tel")], afterSubmit: (s) => void (s.url = `${ORIGIN}/verify`) });
  assert.deepEqual((await runLogin(loginSpec(), moved.page)).printed, [`ZKS_RESULT {"ok":true,"loggedIn":false,"finalOrigin":"${ORIGIN}","pending":"2fa"}`]);
});

test("R3-001: a found --success-selector wins over captcha and code-input detection", async () => {
  const p = loginPage({
    afterSubmit: (s) => s.nodes.push(new FakeNode(["#dashboard"]), new FakeIframe("https://www.recaptcha.net/anchor"), new FakeInput(['input[type="tel"]'], "tel")),
  });
  assert.deepEqual((await runLogin(loginSpec({ successSelector: "#dashboard" }), p.page)).printed, [`ZKS_RESULT {"ok":true,"loggedIn":true,"finalOrigin":"${ORIGIN}"}`]);
});

test("R1-001: a pending login with the password field still on the page blanks it, without leaving the page", async () => {
  const stays = loginPage();
  const { printed } = await runLogin(loginSpec(), stays.page);
  assert.deepEqual(printed, [`ZKS_RESULT {"ok":true,"loggedIn":false,"finalOrigin":"${ORIGIN}","pending":"unknown"}`]);
  assert.equal(stays.password.value, "", "the typed password does not stay in the field");
  assert.ok(!stays.events.includes("goto:about:blank"), "the page stays for the human");

  const cap = loginPage({ afterSubmit: (s) => s.nodes.push(new FakeIframe("https://newassets.hcaptcha.com/captcha/v1")) });
  const res = await runLogin(loginSpec(), cap.page);
  assert.deepEqual(res.printed, [`ZKS_RESULT {"ok":true,"loggedIn":false,"finalOrigin":"${ORIGIN}","pending":"captcha"}`]);
  assert.equal(cap.password.value, "");
});

test("S1: a hostile username or selector cannot break out of the script", async () => {
  const hostile = "a\"`${globalThis.zksLoginPwned=1}`\\\";globalThis.zksLoginPwned=2;//";
  const p = loginPage({ afterSubmit: gone });
  await runLogin(loginSpec({ user: hostile }), p.page);
  assert.equal((globalThis as { zksLoginPwned?: number }).zksLoginPwned, undefined);
  assert.equal(p.user.value, hostile);
});
