import assert from "node:assert/strict";
import { chmodSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { HELP_TEXT } from "../src/help.ts";
import { run } from "../src/run.ts";
import { CANARY, TEST_TOOLS, harness, parse, tempDir, type ExecCall } from "./helpers.ts";

// S3: capture in an isolated ego-browser profile, in a space zks creates and always finishes.

const ORIGIN = "http://127.0.0.1:8123";
const URL_ = `${ORIGIN}/account/tokens`;
const PROFILE = "zks-capture";
const SPACE_NAME = "zks-capture-0707070707070707"; // harness randomBytes: every byte is 7
const ISO_READ = ["capture", "read", "--isolated", "--url", URL_, "--selector", "#tok", "--store", "app/key", "--origin", ORIGIN];
const ISO_GENERATE = ["capture", "fill", "--isolated", "--url", URL_, "--selector", "#pw", "--store", "app/password", "--generate", "24", "--origin", ORIGIN];
const NO_MIRROR = (pending: number) => ({ configured: false, pushed: 0, pending });

const MESSAGES: Record<string, string> = {
  isolated_profile_unset:
    "no capture-profile is configured; run `zks config set capture-profile <profileId>` with a separate ego-browser profile",
  isolated_profile_missing: "the configured capture-profile is not an ego-browser profile; nothing was read or filled",
  isolated_profile_not_isolated: "the configured capture-profile is the default ego-browser profile; pick a separate profile",
  login_required: "the isolated page did not stay on --origin; log in to the site once in the capture profile; nothing was read or filled",
};

function ego(marker: string) {
  return (call: ExecCall) => (call.command === TEST_TOOLS.egoBrowser ? { stdout: Buffer.from(`${CANARY}\n${marker}\n`) } : {});
}

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

function configured(options: Parameters<typeof harness>[0] = {}) {
  const h = harness(options);
  h.config = { capture: { profileId: PROFILE } };
  return h;
}

/** Stand-in for /usr/bin/security that records what `-i` got on stdin. */
function fakeSecurity(): { path: string; log: string } {
  const dir = tempDir();
  const log = join(dir, "stdin.log");
  const path = join(dir, "security");
  writeFileSync(path, `#!/bin/sh\nif [ "$1" = "-i" ]; then cat >'${log}'; exit 0; fi\nexit 1\n`);
  chmodSync(path, 0o700);
  return { path, log };
}

const AsyncFunction = Object.getPrototypeOf(async () => undefined).constructor as new (...args: string[]) => (...a: unknown[]) => Promise<void>;

/** Runs the exact script zks piped to ego, against fake ego globals profiles() and taskSpace(). */
async function runEgo(
  script: string,
  options: { profiles?: unknown; landing?: string; gotoThrows?: boolean; value?: string; security?: string } = {},
) {
  const events: unknown[] = [];
  const printed: string[] = [];
  let url = "about:blank";
  let evaluations = 0;
  const page = {
    goto: async (to: string) => {
      events.push(["goto", to]);
      if (options.gotoThrows && to !== "about:blank") throw new Error(`net::ERR ${CANARY}`);
      url = to === "about:blank" ? to : (options.landing ?? to);
    },
    url: async () => url,
    click: async (selector: string) => void events.push(["click", selector]),
    waitForSelector: async () => void events.push(["wait"]),
    evaluate: async () => {
      events.push(["evaluate"]);
      return ++evaluations === 1 ? true : (options.value ?? CANARY);
    },
  };
  const taskSpace = async (...args: unknown[]) => {
    events.push(["taskSpace", ...args]);
    return {
      page: (label: unknown) => {
        events.push(["page", label]);
        return page;
      },
      finish: async (arg: unknown) => void events.push(["finish", arg]),
    };
  };
  const profiles = async () => {
    events.push(["profiles"]);
    return "profiles" in options ? options.profiles : [{ id: "Default", isDefault: true }, { id: PROFILE, isDefault: false }];
  };
  // Never the real /usr/bin/security: every run gets a stand-in, and the swap must have happened.
  const security = options.security ?? fakeSecurity().path;
  const text = script.replace('const SECURITY = "/usr/bin/security";', `const SECURITY = ${JSON.stringify(security)};`);
  assert.notEqual(text, script, "security path not replaced");
  assert.ok(!text.includes('"/usr/bin/security"'));
  await new AsyncFunction("taskSpace", "profiles", "console", text)(taskSpace, profiles, { log: (...a: unknown[]) => printed.push(a.join(" ")) });
  return { events, printed };
}

async function refused(argv: string[], message: string) {
  const h = configured({ exec: ego('ZKS_RESULT {"ok":true,"length":4}') });
  const out = await run(argv, h.deps);
  assert.equal(out.exitCode, 2, out.stdout);
  assert.deepEqual(parse(out.stdout), { ok: false, error: { code: "usage", message } });
  assert.equal(h.exec.calls.length + h.human.approvals.length, 0);
  assert.equal(h.keychain.store.size, 0);
  assert.equal(records(h).length, 0);
  assert.ok(!out.stdout.includes(CANARY));
}

// config capture-profile

test("S3: config set capture-profile asks first and stores the profile id", async () => {
  const h = harness();
  const out = await run(["config", "set", "capture-profile", PROFILE], h.deps);
  assert.equal(out.exitCode, 0, out.stdout);
  assert.deepEqual(parse(out.stdout), { ok: true, config: { capture: { profileId: PROFILE } } });
  assert.deepEqual(h.human.approvals, [[`Run isolated captures in the ego-browser profile ${PROFILE} (set capture-profile)?`]]);
  assert.deepEqual(h.config, { capture: { profileId: PROFILE } });
  assert.deepEqual(parse((await run(["config", "show"], h.deps)).stdout), { ok: true, config: { capture: { profileId: PROFILE } } });

  const denied = harness({ approve: false });
  const no = await run(["config", "set", "capture-profile", PROFILE], denied.deps);
  assert.equal(no.exitCode, 3, no.stdout);
  assert.deepEqual(parse(no.stdout), { ok: false, error: { code: "not_approved", message: "config change not approved" } });
  assert.deepEqual(denied.config, {});
});

test("S3: config set capture-profile refuses a bad id without echoing it, and keeps sheets-webhook", async () => {
  for (const bad of [CANARY.replace(/-/g, "/"), "", "a\"b", "x".repeat(65), " lead"]) {
    const h = harness();
    const out = await run(["config", "set", "capture-profile", bad], h.deps);
    assert.equal(out.exitCode, 2, out.stdout);
    assert.deepEqual(parse(out.stdout), {
      ok: false,
      error: { code: "usage", message: "capture-profile must be an ego-browser profile id (letters, digits, space, _ . -; at most 64)" },
    });
    assert.deepEqual(h.config, {});
    assert.equal(h.human.approvals.length, 0);
  }
  const url = "https://script.google.com/macros/s/abc/exec";
  const h = harness();
  h.config = { sheets: { webhookUrl: url } };
  await run(["config", "set", "capture-profile", "Profile 2"], h.deps);
  assert.deepEqual(h.config, { sheets: { webhookUrl: url }, capture: { profileId: "Profile 2" } });
});

test("S3: config unset capture-profile asks first and removes only the profile", async () => {
  const url = "https://script.google.com/macros/s/abc/exec";
  const h = harness();
  h.config = { sheets: { webhookUrl: url }, capture: { profileId: PROFILE } };
  const out = await run(["config", "unset", "capture-profile"], h.deps);
  assert.equal(out.exitCode, 0, out.stdout);
  assert.deepEqual(h.human.approvals, [["Stop isolated captures (unset capture-profile)?"]]);
  assert.deepEqual(h.config, { sheets: { webhookUrl: url }, capture: {} });

  const denied = harness({ approve: false });
  denied.config = { capture: { profileId: PROFILE } };
  assert.equal((await run(["config", "unset", "capture-profile"], denied.deps)).exitCode, 3);
  assert.deepEqual(denied.config, { capture: { profileId: PROFILE } });
});

test("S3 (preserve): config set sheets-webhook still works; the set usage lists both keys", async () => {
  const h = harness();
  const out = await run(["config", "set", "sheets-webhook", "https://script.google.com/macros/s/abc/exec"], h.deps);
  assert.equal(out.exitCode, 0, out.stdout);
  assert.deepEqual(h.config, { sheets: { webhookUrl: "https://script.google.com/macros/s/abc/exec" } });
  const bad = await run(["config", "set", "nope", "x"], harness().deps);
  assert.equal(bad.exitCode, 2);
  assert.equal(parse(bad.stdout).error.message, "usage: zks config set sheets-webhook <https://script.google.com/macros/s/.../exec> | zks config set capture-profile <profileId>");
});

// Refusals before ego

test("S3: --isolated without a configured profile is isolated_profile_unset; no ego, nothing stored, audited", async () => {
  for (const argv of [ISO_READ, ISO_GENERATE]) {
    for (const config of [{}, { capture: {} }, { capture: { profileId: "bad\"id" } }]) {
      const h = harness({ exec: ego('ZKS_RESULT {"ok":true,"length":4}') });
      h.config = config as typeof h.config;
      const out = await run(argv, h.deps);
      assert.equal(out.exitCode, 1, out.stdout);
      const body = parse(out.stdout);
      assert.deepEqual(body, {
        ok: false,
        command: "capture",
        mode: argv[1],
        store: argv === ISO_READ ? "app/key" : "app/password",
        origin: ORIGIN,
        isolated: true,
        error: { code: "isolated_profile_unset", message: MESSAGES.isolated_profile_unset },
        auditId: body.auditId,
        mirror: NO_MIRROR(1),
      });
      assert.equal(egoCalls(h).length, 0);
      assert.equal(h.human.approvals.length, 0);
      assert.deepEqual([...h.keychain.store.keys()], ["zks/audit-head"]);
      const [record] = records(h);
      assert.deepEqual([record!.result, record!.errorCode, record!.environment], ["failed", "isolated_profile_unset", ORIGIN]);
    }
  }
});

test("S3: --isolated excludes --space and --page and needs --url and --origin on the same origin", async () => {
  await refused([...ISO_READ, "--space", "4"], "--isolated cannot be combined with --space or --page");
  await refused([...ISO_READ, "--page", "p1"], "--isolated cannot be combined with --space or --page");
  const without = (argv: string[], flag: string) => {
    const i = argv.indexOf(flag);
    return [...argv.slice(0, i), ...argv.slice(i + 2)];
  };
  await refused(without(ISO_READ, "--url"), "--isolated needs --url and --origin");
  await refused(without(ISO_READ, "--origin"), "--isolated needs --url and --origin");
  await refused(without(ISO_GENERATE, "--origin"), "--isolated needs --url and --origin");
  const swap = (argv: string[], url: string) => argv.map((a) => (a === URL_ ? url : a));
  for (const other of ["https://evil.example/account", "http://127.0.0.1:8124/x", "http://localhost:8123/x"]) {
    await refused(swap(ISO_READ, other), "--url must be on --origin");
  }
  for (const bad of [`javascript:alert(1)`, "not a url", `${ORIGIN}/${CANARY} x`, `${ORIGIN}/${"a".repeat(2000)}`]) {
    await refused(swap(ISO_READ, bad), "--url must be an http(s) URL of at most 1000 printable ASCII characters");
  }
  await refused(["capture", "read", "--space", "4", "--page", "p1", "--url", URL_, "--selector", "#t", "--store", "a/b", "--origin", ORIGIN], "--url needs --isolated");
  await refused(["capture", "read", "--isolated=yes", "--url", URL_, "--selector", "#t", "--store", "a/b", "--origin", ORIGIN], "option --isolated takes no value");
  await refused(["plan", "--isolated"], "option --isolated is not valid for plan");
});

// Script outcomes

test("S3: the script refuses a profile missing from profiles() before it creates any space", async () => {
  const h = configured({ exec: ego('ZKS_RESULT {"ok":false,"code":"isolated_profile_missing"}') });
  const out = await run(ISO_READ, h.deps);
  assert.equal(out.exitCode, 1, out.stdout);
  const body = parse(out.stdout);
  assert.deepEqual(body.error, { code: "isolated_profile_missing", message: MESSAGES.isolated_profile_missing });
  assert.equal(body.isolated, true);
  assert.deepEqual([...h.keychain.store.keys()], ["zks/audit-head"]);
  assert.deepEqual([records(h)[0]!.result, records(h)[0]!.errorCode], ["failed", "isolated_profile_missing"]);
  assert.ok(!out.stdout.includes(CANARY));

  for (const list of [[{ id: "Default", isDefault: true }], [], null, "zks-capture", [{ id: "zks-capture-2", isDefault: false }]]) {
    const ran = await runEgo(egoCalls(h)[0]!.input, { profiles: list });
    assert.deepEqual(ran.printed, ['ZKS_RESULT {"ok":false,"code":"isolated_profile_missing"}']);
    assert.deepEqual(ran.events, [["profiles"]]);
  }
});

test("S3: the script refuses the default profile as isolated_profile_not_isolated", async () => {
  const h = configured({ exec: ego('ZKS_RESULT {"ok":false,"code":"isolated_profile_not_isolated"}') });
  const out = await run(ISO_READ, h.deps);
  assert.equal(out.exitCode, 1, out.stdout);
  assert.deepEqual(parse(out.stdout).error, { code: "isolated_profile_not_isolated", message: MESSAGES.isolated_profile_not_isolated });
  assert.deepEqual([records(h)[0]!.result, records(h)[0]!.errorCode], ["failed", "isolated_profile_not_isolated"]);
  assert.deepEqual([...h.keychain.store.keys()], ["zks/audit-head"]);

  for (const entry of [{ id: PROFILE, isDefault: true }, { id: PROFILE }, { id: PROFILE, isDefault: "false" }]) {
    const ran = await runEgo(egoCalls(h)[0]!.input, { profiles: [entry] });
    assert.deepEqual(ran.printed, ['ZKS_RESULT {"ok":false,"code":"isolated_profile_not_isolated"}']);
    assert.deepEqual(ran.events, [["profiles"]]);
  }
});

test("S3: landing on another origin is login_required; nothing is read and the space is finished", async () => {
  const h = configured({ exec: ego('ZKS_RESULT {"ok":false,"code":"login_required"}') });
  const out = await run([...ISO_READ, "--click", "#reveal"], h.deps);
  assert.equal(out.exitCode, 1, out.stdout);
  assert.deepEqual(parse(out.stdout).error, { code: "login_required", message: MESSAGES.login_required });
  assert.deepEqual([records(h)[0]!.result, records(h)[0]!.errorCode], ["failed", "login_required"]);
  assert.deepEqual([...h.keychain.store.keys()], ["zks/audit-head"]);

  const ran = await runEgo(egoCalls(h)[0]!.input, { landing: "https://login.example/sso" });
  assert.deepEqual(ran.printed, ['ZKS_RESULT {"ok":false,"code":"login_required"}']);
  assert.deepEqual(ran.events, [
    ["profiles"],
    ["taskSpace", SPACE_NAME, { profileId: PROFILE }],
    ["page", "p1"],
    ["goto", URL_],
    ["finish", { keep: [] }],
  ]);
});

test("S3: an isolated read creates its own space, goes to --url, stores the value and always finishes", async () => {
  const h = configured({ exec: ego('ZKS_RESULT {"ok":true,"length":21}') });
  const out = await run([...ISO_READ, "--click", "#reveal"], h.deps);
  assert.equal(out.exitCode, 0, out.stdout);
  const body = parse(out.stdout);
  assert.deepEqual(body, {
    ok: true,
    command: "capture",
    mode: "read",
    store: "app/key",
    origin: ORIGIN,
    isolated: true,
    length: 21,
    auditId: body.auditId,
    mirror: NO_MIRROR(1),
  });
  const [record] = records(h);
  assert.deepEqual([record!.result, record!.sourceKind, record!.environment, record!.target], ["applied", "capture-read", ORIGIN, "app/key"]);

  const [call] = egoCalls(h);
  assert.deepEqual(call!.args, ["nodejs"]);
  const script = call!.input;
  assert.ok(script.includes(`"isolated":{"profileId":"${PROFILE}","url":"${URL_}","name":"${SPACE_NAME}"}`), script.slice(0, 400));
  assert.ok(script.includes('"space":null,"page":null'));
  assert.match(script, /finally \{\s*try \{\s*await task\.finish\(\{ keep: \[\] \}\);/);

  const security = fakeSecurity();
  const ran = await runEgo(script, { security: security.path });
  assert.deepEqual(ran.printed, [`ZKS_RESULT {"ok":true,"length":${CANARY.length}}`]);
  assert.deepEqual(ran.events.slice(0, 5), [["profiles"], ["taskSpace", SPACE_NAME, { profileId: PROFILE }], ["page", "p1"], ["goto", URL_], ["click", "#reveal"]]);
  assert.deepEqual(ran.events.slice(-2), [["goto", "about:blank"], ["finish", { keep: [] }]]);
  assert.ok(readFileSync(security.log, "utf8").includes(Buffer.from(CANARY).toString("hex")));
  assert.ok(!script.includes(CANARY), "S1: the value is never in the script");
  assert.ok(!out.stdout.includes(CANARY));
});

test("S3: the space is finished with keep [] even when the browser step throws", async () => {
  const h = configured({ exec: ego('ZKS_RESULT {"ok":true,"length":4}') });
  await run(ISO_READ, h.deps);
  const ran = await runEgo(egoCalls(h)[0]!.input, { gotoThrows: true });
  assert.deepEqual(ran.printed, ['ZKS_RESULT {"ok":false,"code":"browser_failed"}']);
  assert.deepEqual(ran.events.at(-1), ["finish", { keep: [] }]);
});

test("S3: an isolated fill --generate keeps the value out of the script and removes a new item on an isolation refusal", async () => {
  const ok = configured({ exec: ego('ZKS_RESULT {"ok":true,"length":32}') });
  const out = await run(ISO_GENERATE, ok.deps);
  assert.equal(out.exitCode, 0, out.stdout);
  const generated = ok.keychain.store.get("app/password");
  assert.equal(generated, Buffer.alloc(24, 7).toString("base64url"));
  assert.ok(!egoCalls(ok)[0]!.input.includes(generated!), "S1: the generated value is never in the script");
  assert.ok(!out.stdout.includes(generated!));

  for (const code of ["isolated_profile_missing", "isolated_profile_not_isolated", "login_required"]) {
    const h = configured({ exec: ego(`ZKS_RESULT {"ok":false,"code":"${code}"}`) });
    const res = await run(ISO_GENERATE, h.deps);
    assert.equal(res.exitCode, 1, res.stdout);
    assert.deepEqual(parse(res.stdout).error, { code, message: MESSAGES[code] });
    assert.ok(!h.keychain.store.has("app/password"), `${code}: the generated item stayed in the Keychain`);
    assert.deepEqual([records(h)[0]!.result, records(h)[0]!.errorCode, records(h)[0]!.sourceKind], ["failed", code, "capture-generate"]);
  }
});

test("S3: replacing an item from an isolated capture names the profile in the dialog; deny runs nothing", async () => {
  const h = configured({ exec: ego('ZKS_RESULT {"ok":true,"length":4}'), keychain: { "app/key": "old" }, approve: false });
  const out = await run(ISO_READ, h.deps);
  assert.equal(out.exitCode, 3, out.stdout);
  assert.deepEqual(h.human.approvals, [["Replace the Keychain item app/key?", `New value: read from ${ORIGIN} (isolated ego-browser profile ${PROFILE})`]]);
  assert.equal(egoCalls(h).length, 0);
  assert.equal(h.keychain.store.get("app/key"), "old");
  assert.deepEqual([records(h)[0]!.result, records(h)[0]!.errorCode], ["denied", "not_approved"]);
});

test("S3 (preserve): a capture with --space/--page ignores the configured profile and resumes the agent's space", async () => {
  const h = configured({ exec: ego('ZKS_RESULT {"ok":true,"length":4}') });
  const out = await run(["capture", "read", "--space", "4", "--page", "p1", "--selector", "#tok", "--store", "app/key", "--origin", ORIGIN], h.deps);
  assert.equal(out.exitCode, 0, out.stdout);
  assert.equal(parse(out.stdout).isolated, undefined);
  const script = egoCalls(h)[0]!.input;
  assert.ok(script.includes('"space":4,"page":"p1"'));
  assert.ok(!script.includes('"isolated"'));
  assert.ok(!script.includes(PROFILE));
});

test("S3: help documents --isolated and capture-profile", () => {
  assert.ok(HELP_TEXT.includes("zks capture read --isolated --url URL --selector CSS --store SERVICE/ACCOUNT [--click SELECTOR] --origin ORIGIN"));
  assert.ok(HELP_TEXT.includes("zks capture fill --isolated --url URL --selector CSS"));
  assert.ok(HELP_TEXT.includes("zks config set capture-profile <profileId>"));
  assert.ok(HELP_TEXT.includes("zks config unset capture-profile"));
});
