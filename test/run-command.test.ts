import assert from "node:assert/strict";
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { setTimeout as sleep } from "node:timers/promises";
import { join } from "node:path";
import { test } from "node:test";
import { createMacDialogs, sanitizeLine } from "../src/gate/dialog.ts";
import { SAFE_PATH } from "../src/platform/exec.ts";
import { HELP_TEXT } from "../src/help.ts";
import { run } from "../src/run.ts";
import { CANARY, auditBytes, fakeExec, harness, parse } from "./helpers.ts";

// S1-S6 of `zks run -- <command>`: process-scoped secret injection.

const STRIPE = "sk_test_51Hzks0canary0stripe0value";
/** The variables zks run may inject: SIGNING_KEY is generated and SIGNING_URL is derived from it. */
const VALUES: Record<string, string> = { DATABASE_URL: CANARY, STRIPE_SECRET_KEY: STRIPE, LOG_LEVEL: "info" };

const policy = {
  version: 1,
  project: "acme",
  targets: { v1: { provider: "vercel", projectId: "prj_1", environments: ["production"] } },
  variables: {
    DATABASE_URL: { sensitive: true, source: { kind: "keychain", service: "app", account: "db" }, targets: ["v1"] },
    STRIPE_SECRET_KEY: { sensitive: true, source: { kind: "keychain", service: "app", account: "stripe" }, targets: ["v1"] },
    LOG_LEVEL: { sensitive: false, value: "info", targets: ["v1"] },
    SIGNING_KEY: { sensitive: true, source: { kind: "generate", bytes: 32 }, targets: ["v1"] },
    SIGNING_URL: { sensitive: true, source: { kind: "template", template: "k-${SIGNING_KEY}" }, targets: ["v1"] },
  },
};

/** Names a shell may add to its own environment; they are not injected by zks. */
const SHELL_NAMES = new Set(["PWD", "OLDPWD", "SHLVL", "_"]);
const BASE_NAMES = ["HOME", "LANG", "LOGNAME", "PATH", "USER"];

/**
 * A fake child: writes NAME=<length of value> of its whole environment to the file named by $1
 * (never a value), then exits with $2, or kills itself with SIGTERM when $2 is TERM. With $2 TRAP it
 * writes the signal it gets (INT, TERM or HUP) to $1.sig after creating $1.ready, and exits 42.
 */
const CHILD_SCRIPT = `#!/bin/sh
out="$1"
/usr/bin/awk 'BEGIN { for (k in ENVIRON) print k "=" length(ENVIRON[k]) }' > "$out"
if [ "$2" = "TERM" ]; then kill -TERM $$; sleep 5; fi
if [ "$2" = "TRAP" ]; then
  for s in INT TERM HUP; do trap "echo $s > '$out.sig'; exit 42" $s; done
  : > "$out.ready"
  i=0; while [ $i -lt 100 ]; do sleep 0.1; i=$((i+1)); done
  exit 1
fi
exit "\${2:-0}"
`;

function writeChild(path: string): string {
  mkdirSync(join(path, ".."), { recursive: true });
  writeFileSync(path, CHILD_SCRIPT);
  chmodSync(path, 0o755);
  return path;
}

function setup(options: { approve?: boolean; decision?: "deny" | "once" | "always"; keychain?: Record<string, string> } = {}) {
  const h = harness({
    policy,
    keychain: options.keychain ?? { "app/db": CANARY, "app/stripe": STRIPE },
    approve: options.approve,
    decision: options.decision,
  });
  const child = writeChild(join(h.dir, "bin", "child.sh"));
  const out = join(h.dir, "child-env.txt");
  // The fake sources record whether they were called.
  const sourceCalls: string[] = [];
  const get = h.deps.keychain.get.bind(h.deps.keychain);
  h.deps.keychain = {
    ...h.deps.keychain,
    get: async (service, account) => {
      if (service === "app") sourceCalls.push(`keychain:${account}`);
      return get(service, account);
    },
  };
  const random = h.deps.randomBytes as (n: number) => Buffer;
  h.deps.randomBytes = (n) => {
    sourceCalls.push("generate");
    return random(n);
  };
  return { h, child, out, sourceCalls };
}

/** NAME -> length of the child's environment, without the shell's own names. */
function childEnv(out: string): Map<string, number> {
  const env = new Map<string, number>();
  for (const line of readFileSync(out, "utf8").split("\n").filter(Boolean)) {
    const at = line.lastIndexOf("=");
    const name = line.slice(0, at);
    if (!SHELL_NAMES.has(name)) env.set(name, Number(line.slice(at + 1)));
  }
  return env;
}

async function runCaptured(argv: string[], deps: ReturnType<typeof harness>["deps"]) {
  const written: string[] = [];
  const stderr: string[] = [];
  const stdoutWrite = process.stdout.write;
  const stderrWrite = process.stderr.write;
  // Recorded and passed through: the test reporter writes to stdout meanwhile.
  const tee = (write: typeof process.stdout.write, stream: NodeJS.WriteStream) =>
    ((chunk: unknown, ...rest: unknown[]) => {
      written.push(String(chunk));
      return (write as (...a: unknown[]) => boolean).call(stream, chunk, ...rest);
    }) as typeof process.stdout.write;
  process.stdout.write = tee(stdoutWrite, process.stdout);
  const teeErr = tee(stderrWrite, process.stderr);
  process.stderr.write = ((chunk: unknown, ...rest: unknown[]) => {
    stderr.push(String(chunk));
    return (teeErr as (...a: unknown[]) => boolean)(chunk, ...rest);
  }) as typeof process.stderr.write;
  try {
    return { out: await run(argv, deps), written: written.join(""), stderr: stderr.join("") };
  } finally {
    process.stdout.write = stdoutWrite;
    process.stderr.write = stderrWrite;
  }
}

async function auditRecords(h: ReturnType<typeof harness>): Promise<Record<string, any>[]> {
  return parse((await run(["audit", "list"], h.deps)).stdout).records as Record<string, any>[];
}

test("S2: the dialog shows the executable, arguments, directory and names, and asks every time", async () => {
  const { h, child, out } = setup({ decision: "always" });
  for (let i = 0; i < 2; i++) {
    const res = await run(["run", "--only", "DATABASE_URL,LOG_LEVEL", "--", child, out, "0", "with space"], h.deps);
    assert.equal(res.exitCode, 0, res.stdout);
  }
  assert.equal(h.human.approvals.length, 2, "every run asks");
  assert.equal(h.trust, null, "run never trusts anything");
  const lines = h.human.approvals[0] as string[];
  assert.ok(lines.includes(`Command: ${child}`), lines.join("\n"));
  assert.ok(lines.includes(`${out} 0 "with space"`), lines.join("\n"));
  assert.ok(lines.includes(`Directory: ${h.dir}`), lines.join("\n"));
  assert.ok(lines.some((l) => l.startsWith("- DATABASE_URL [secret; Keychain app/db]")), lines.join("\n"));
  assert.ok(lines.some((l) => l.startsWith("- LOG_LEVEL [plain; literal]")), lines.join("\n"));
  assert.ok(!lines.some((l) => l.includes("STRIPE_SECRET_KEY")));
  assert.ok(!lines.join("\n").includes(CANARY));
});

test("S2: arguments are shown in full; more than 300 characters is arguments_too_long before any dialog", async () => {
  const { h, child, out, sourceCalls } = setup();
  const never = join(h.dir, "never.txt");
  const fill = (file: string, length: number) => "a".repeat(length - `${file} 0 `.length);
  const ok = await run(["run", "--only", "LOG_LEVEL", "--", child, out, "0", fill(out, 300)], h.deps);
  assert.equal(ok.exitCode, 0, ok.stdout);
  assert.ok((h.human.approvals[0] as string[]).includes(`${out} 0 ${fill(out, 300)}`), "the 300-character line is shown whole");

  const res = await run(["run", "--only", "DATABASE_URL", "--", child, never, "0", fill(never, 301)], h.deps);
  assert.equal(res.exitCode, 2, res.stdout);
  assert.deepEqual(parse(res.stdout).error, {
    code: "arguments_too_long",
    message: "the arguments are longer than 300 characters; the dialog shows them in full, so shorten them",
  });
  assert.equal(h.human.approvals.length, 1, "no dialog for the refused run");
  assert.deepEqual(sourceCalls, []);
  assert.ok(!existsSync(never));
  assert.equal((await auditRecords(h)).length, 1, "only the first run is audited");
});

test("S2: a denied run resolves nothing, runs nothing, exits 3 and is audited denied", async () => {
  const { h, child, out, sourceCalls } = setup({ approve: false });
  const res = await run(["run", "--", child, out], h.deps);
  assert.equal(res.exitCode, 3, res.stdout);
  const body = parse(res.stdout);
  assert.equal(body.ok, false);
  assert.equal(body.error.code, "not_approved");
  assert.deepEqual(sourceCalls, [], "no source may be read before approval");
  assert.ok(!existsSync(out), "the command must not run");
  const records = await auditRecords(h);
  assert.equal(records.length, 3);
  for (const r of records) {
    assert.equal(r.action, "run");
    assert.equal(r.provider, "run");
    assert.equal(r.target, child);
    assert.equal(r.result, "denied");
    assert.equal(r.errorCode, "not_approved");
    assert.equal(r.approval, "dialog");
  }
  assert.deepEqual(records.map((r) => r.variableName).sort(), Object.keys(VALUES).sort());
});

test("S1/S3/S4/S5: success injects exactly the selected variables, prints nothing and leaks no value", async () => {
  const { h, child, out } = setup();
  const marker = "argv-marker-not-for-audit";
  const { out: res, written } = await runCaptured(["run", "--only", "DATABASE_URL,STRIPE_SECRET_KEY", "--", child, out, "0", marker], h.deps);
  assert.equal(res.exitCode, 0, res.stdout);
  assert.equal(res.stdout, "", "the child owns stdout");
  const env = childEnv(out);
  assert.deepEqual([...env.keys()].sort(), [...BASE_NAMES, "DATABASE_URL", "STRIPE_SECRET_KEY"].sort());
  assert.equal(env.get("DATABASE_URL"), CANARY.length);
  assert.equal(env.get("STRIPE_SECRET_KEY"), STRIPE.length);
  assert.equal(env.get("PATH"), `${join(h.dir, "node_modules", ".bin")}:${SAFE_PATH}`.length);
  assert.equal(env.get("HOME"), h.dir.length);

  const records = await auditRecords(h);
  assert.equal(records.length, 2);
  for (const r of records) {
    assert.equal(r.action, "run");
    assert.equal(r.provider, "run");
    assert.equal(r.target, child);
    assert.equal(r.result, "applied");
    assert.equal(r.project, "acme");
  }
  const audit = await auditBytes(h.auditDb);
  assert.ok(!audit.includes(marker), "the audit never holds the argv");
  for (const value of [CANARY, STRIPE]) {
    assert.ok(!res.stdout.includes(value));
    assert.ok(!written.includes(value), "zks wrote a value to its own stdout/stderr");
    assert.ok(!audit.includes(value), "audit db or -wal holds a value");
  }
  for (const name of ["DATABASE_URL", "STRIPE_SECRET_KEY"]) assert.equal(process.env[name], undefined, "zks's own env was changed");
});

test("S1: without --only every variable is injected except generated ones and those derived from them", async () => {
  const { h, child, out, sourceCalls } = setup();
  const res = await run(["run", "--", child, out], h.deps);
  assert.equal(res.exitCode, 0, res.stdout);
  const env = childEnv(out);
  for (const [name, value] of Object.entries(VALUES)) assert.equal(env.get(name), value.length, name);
  assert.equal(env.get("SIGNING_KEY"), undefined);
  assert.equal(env.get("SIGNING_URL"), undefined);
  assert.ok(!sourceCalls.includes("generate"), "a generated value is never created for run");
  const lines = h.human.approvals[0] as string[];
  assert.ok(!lines.some((l) => l.includes("SIGNING")), lines.join("\n"));
  assert.deepEqual((await auditRecords(h)).map((r) => r.variableName).sort(), Object.keys(VALUES).sort());
});

test("S1: naming a generated variable, or one derived from it, in --only is a usage error before the dialog", async () => {
  const { h, child, out, sourceCalls } = setup();
  for (const only of ["DATABASE_URL,SIGNING_URL,SIGNING_KEY", "SIGNING_KEY,SIGNING_URL"]) {
    const res = await run(["run", "--only", only, "--", child, out], h.deps);
    assert.equal(res.exitCode, 2, res.stdout);
    assert.deepEqual(parse(res.stdout).error, {
      code: "usage",
      message: "run cannot inject generated values; they exist only at their destinations (SIGNING_KEY, SIGNING_URL)",
    });
  }
  const derived = await run(["run", "--only", "SIGNING_URL", "--", child, out], h.deps);
  assert.equal(parse(derived.stdout).error.message, "run cannot inject generated values; they exist only at their destinations (SIGNING_URL)");
  assert.equal(h.human.approvals.length, 0);
  assert.deepEqual(sourceCalls, []);
  assert.ok(!existsSync(out));
  assert.deepEqual(await auditRecords(h), []);
});

test("S3: SIGINT, SIGTERM and SIGHUP are forwarded to the child; the handlers are removed after it exits", async () => {
  const { h, child } = setup();
  const signals = ["SIGINT", "SIGTERM", "SIGHUP"] as const;
  for (const signal of signals) {
    const out = join(h.dir, `trap-${signal}.txt`);
    const before = signals.map((s) => process.listenerCount(s));
    let installed: Record<string, Function[]> = {};
    const spawnInherited = h.deps.spawnInherited;
    h.deps.spawnInherited = (path, args, options) => {
      const known = Object.fromEntries(signals.map((s) => [s, process.listeners(s)]));
      const spawned = spawnInherited(path, args, options);
      installed = Object.fromEntries(signals.map((s) => [s, process.listeners(s).filter((l) => !known[s]?.includes(l))]));
      return spawned;
    };
    const running = run(["run", "--only", "LOG_LEVEL", "--", child, out, "TRAP"], h.deps);
    for (let i = 0; i < 100 && !existsSync(`${out}.ready`); i++) await sleep(50);
    assert.ok(existsSync(`${out}.ready`), "the child did not start");
    assert.deepEqual(signals.map((s) => installed[s]?.length), [1, 1, 1], "one handler per signal while the child runs");
    // Only zks's own handler is called: no real signal reaches the test process.
    for (const listener of installed[signal] as Function[]) listener(signal);
    const res = await running;
    assert.equal(res.exitCode, 42, `${signal}: ${res.stdout}`);
    assert.equal(readFileSync(`${out}.sig`, "utf8").trim(), signal.slice(3));
    assert.deepEqual(signals.map((s) => process.listenerCount(s)), before, "every handler is removed after the exit");
    h.deps.spawnInherited = spawnInherited;
  }
});

test("S3/S4: anchor and mirror run after the child exits; their failure keeps the exit code and only writes stderr", async () => {
  const { h, child, out } = setup();
  let exitedFirst: boolean | null = null;
  let childExited = false;
  const spawnInherited = h.deps.spawnInherited;
  h.deps.spawnInherited = (path, args, options) => {
    const spawned = spawnInherited(path, args, options);
    void spawned.exited.then(() => (childExited = true));
    return spawned;
  };
  h.deps.mirror = {
    async sync() {
      exitedFirst = childExited;
      throw new Error(`mirror down ${CANARY}`);
    },
  };
  const { out: res, written, stderr } = await runCaptured(["run", "--only", "DATABASE_URL", "--", child, out, "7"], h.deps);
  assert.equal(res.exitCode, 7, res.stdout);
  assert.equal(res.stdout, "");
  assert.equal(exitedFirst, true, "the mirror ran before the child exited");
  assert.equal(stderr, "zks: audit anchor/mirror: mirror down [REDACTED]\n");
  assert.ok(!written.includes(CANARY));
  assert.equal((await auditRecords(h))[0]?.result, "applied");
});

test("S2: a spawn that throws synchronously is run_failed and audited failed", async () => {
  const { h, child, out } = setup();
  h.deps.spawnInherited = () => {
    throw new Error(`spawn EINVAL ${CANARY}`);
  };
  const res = await run(["run", "--only", "DATABASE_URL,LOG_LEVEL", "--", child, out], h.deps);
  assert.equal(res.exitCode, 1, res.stdout);
  const body = parse(res.stdout);
  assert.equal(body.error.code, "run_failed");
  assert.ok(!res.stdout.includes(CANARY), res.stdout);
  assert.deepEqual((await auditRecords(h)).map((r) => `${r.variableName}:${r.result}:${r.errorCode}`).sort(), [
    "DATABASE_URL:failed:run_failed",
    "LOG_LEVEL:failed:run_failed",
  ]);
});

test("S3: zks exits with the child's exit code, and 128+signal when it is killed", async () => {
  const { h, child, out } = setup();
  assert.equal((await run(["run", "--only", "LOG_LEVEL", "--", child, out, "7"], h.deps)).exitCode, 7);
  const killed = await run(["run", "--only", "LOG_LEVEL", "--", child, out, "TERM"], h.deps);
  assert.equal(killed.exitCode, 128 + 15, killed.stdout);
  assert.equal(killed.stdout, "");
});

test("S3: a bare name is found in <cwd>/node_modules/.bin and a relative path against cwd", async () => {
  const { h, out } = setup();
  const bin = writeChild(join(h.dir, "node_modules", ".bin", "fake-tool"));
  assert.equal((await run(["run", "--only", "LOG_LEVEL", "--", "fake-tool", out], h.deps)).exitCode, 0);
  assert.ok((h.human.approvals[0] as string[]).includes(`Command: ${bin}`));
  assert.equal((await run(["run", "--only", "LOG_LEVEL", "--", "./bin/child.sh", out], h.deps)).exitCode, 0);
  assert.ok((h.human.approvals[1] as string[]).includes(`Command: ${join(h.dir, "bin", "child.sh")}`));
});

test("S3: command_not_found before any dialog, source or audit", async () => {
  const { h, out, sourceCalls } = setup();
  writeFileSync(join(h.dir, "not-exec.sh"), "#!/bin/sh\n");
  for (const command of ["zks-no-such-command-xyz", "./missing.sh", "./bin", "./not-exec.sh"]) {
    const res = await run(["run", "--", command, out], h.deps);
    assert.equal(res.exitCode, 1, `${command}: ${res.stdout}`);
    assert.equal(parse(res.stdout).error.code, "command_not_found");
  }
  assert.equal(h.human.approvals.length, 0);
  assert.deepEqual(sourceCalls, []);
  assert.deepEqual(await auditRecords(h), []);
});

test("S1/S5: usage errors: missing --, empty command, extra argument, --target", async () => {
  const { h, child, out } = setup();
  const usage = "usage: zks run [--policy FILE] [--only A,B] [--agent LABEL] -- <command> [args...]";
  for (const argv of [["run"], ["run", child], ["run", "--"], ["run", "--only", "LOG_LEVEL"]]) {
    const res = await run(argv, h.deps);
    assert.equal(res.exitCode, 2, argv.join(" "));
    assert.deepEqual(parse(res.stdout).error, { code: "usage", message: usage });
  }
  const extra = await run(["run", "extra", "--", child, out], h.deps);
  assert.equal(extra.exitCode, 2);
  assert.equal(parse(extra.stdout).error.message, "unexpected argument");
  const target = await run(["run", "--target", "v1", "--", child, out], h.deps);
  assert.equal(target.exitCode, 2);
  assert.equal(parse(target.stdout).error.message, "option --target is not valid for run");
  // Options after -- belong to the command.
  assert.equal((await run(["run", "--only", "LOG_LEVEL", "--", child, out, "0", "--target", "--value"], h.deps)).exitCode, 0);
  assert.equal(h.human.approvals.length, 1);
});

test("S1: an unknown --only name is a usage error naming it; nothing is resolved or asked", async () => {
  const { h, child, out, sourceCalls } = setup();
  const res = await run(["run", "--only", "DATABASE_URL,NOPE", "--", child, out], h.deps);
  assert.equal(res.exitCode, 2, res.stdout);
  assert.deepEqual(parse(res.stdout).error, { code: "usage", message: '--only: a name is not a variable of the policy; see `zks plan`' });
  assert.equal(h.human.approvals.length, 0);
  assert.deepEqual(sourceCalls, []);
  assert.ok(!existsSync(out));
});

test("S2: a source that fails after approval runs nothing and is audited failed", async () => {
  const { h, child, out } = setup({ keychain: { "app/db": CANARY } });
  const res = await run(["run", "--only", "DATABASE_URL,STRIPE_SECRET_KEY", "--", child, out], h.deps);
  assert.equal(res.exitCode, 1, res.stdout);
  assert.equal(parse(res.stdout).error.code, "source_missing");
  assert.ok(!existsSync(out));
  assert.ok(!res.stdout.includes(CANARY));
  const records = await auditRecords(h);
  assert.deepEqual(records.map((r) => `${r.variableName}:${r.result}:${r.errorCode}`).sort(), [
    "DATABASE_URL:failed:not_run",
    "STRIPE_SECRET_KEY:failed:source_missing",
  ]);
});

test("S4: inventory skips run records", async () => {
  const { h, child, out } = setup();
  assert.equal((await run(["run", "--only", "LOG_LEVEL", "--", child, out], h.deps)).exitCode, 0);
  const entries = parse((await run(["inventory"], h.deps)).stdout).entries as Record<string, any>[];
  assert.ok(entries.every((e) => e.provider !== "run" && e.status === "never_written"));
});

test("S6: help lists zks run, the generated-variable rule and the argument limit", () => {
  assert.match(HELP_TEXT, /zks run \[--policy FILE\] \[--only A,B\] \[--agent LABEL\] -- <command> \[args\.\.\.\]/);
  assert.match(HELP_TEXT, /generated variables are skipped unless named/);
  assert.match(HELP_TEXT, /arguments_too_long/);
});

test("PRESERVE: -- is still an unknown option for other commands", async () => {
  const h = harness({ policy });
  const res = await run(["apply", "--", "x"], h.deps);
  assert.equal(res.exitCode, 2);
  assert.equal(parse(res.stdout).error.message, "unknown option --");
});

test("PRESERVE: the dialog replaces every character outside printable ASCII, so the script stays ASCII", async () => {
  assert.equal(sanitizeLine("a\nb‮c…"), "a?b?c?");
  const exec = fakeExec(() => ({ stdout: Buffer.from("Approve\n") }));
  assert.equal(await createMacDialogs(exec.exec, "darwin").approve("t", ["args …"]), true);
  const script = exec.calls[0]?.input as string;
  assert.ok(script.includes("args ?"), script);
  assert.ok(/^[\x00-\x7F]*$/.test(script), script);
});
