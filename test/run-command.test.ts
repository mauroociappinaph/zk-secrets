import assert from "node:assert/strict";
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { createMacDialogs, sanitizeLine } from "../src/gate/dialog.ts";
import { SAFE_PATH } from "../src/platform/exec.ts";
import { HELP_TEXT } from "../src/help.ts";
import { run } from "../src/run.ts";
import { CANARY, auditBytes, fakeExec, harness, parse } from "./helpers.ts";

// S1-S6 of `zks run -- <command>`: process-scoped secret injection.

const STRIPE = "sk_test_51Hzks0canary0stripe0value";
/** base64url of Buffer.alloc(32, 7), the harness randomBytes. */
const GENERATED = Buffer.alloc(32, 7).toString("base64url");
const VALUES: Record<string, string> = { DATABASE_URL: CANARY, STRIPE_SECRET_KEY: STRIPE, LOG_LEVEL: "info", SIGNING_KEY: GENERATED };

const policy = {
  version: 1,
  project: "acme",
  targets: { v1: { provider: "vercel", projectId: "prj_1", environments: ["production"] } },
  variables: {
    DATABASE_URL: { sensitive: true, source: { kind: "keychain", service: "app", account: "db" }, targets: ["v1"] },
    STRIPE_SECRET_KEY: { sensitive: true, source: { kind: "keychain", service: "app", account: "stripe" }, targets: ["v1"] },
    LOG_LEVEL: { sensitive: false, value: "info", targets: ["v1"] },
    SIGNING_KEY: { sensitive: true, source: { kind: "generate", bytes: 32 }, targets: ["v1"] },
  },
};

/** Names a shell may add to its own environment; they are not injected by zks. */
const SHELL_NAMES = new Set(["PWD", "OLDPWD", "SHLVL", "_"]);
const BASE_NAMES = ["HOME", "LANG", "LOGNAME", "PATH", "USER"];

/**
 * A fake child: writes NAME=<length of value> of its whole environment to the file named by $1
 * (never a value), then exits with $2, or kills itself with SIGTERM when $2 is TERM.
 */
const CHILD_SCRIPT = `#!/bin/sh
out="$1"
/usr/bin/awk 'BEGIN { for (k in ENVIRON) print k "=" length(ENVIRON[k]) }' > "$out"
if [ "$2" = "TERM" ]; then kill -TERM $$; sleep 5; fi
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
  const stdoutWrite = process.stdout.write;
  const stderrWrite = process.stderr.write;
  // Recorded and passed through: the test reporter writes to stdout meanwhile.
  const tee = (write: typeof process.stdout.write, stream: NodeJS.WriteStream) =>
    ((chunk: unknown, ...rest: unknown[]) => {
      written.push(String(chunk));
      return (write as (...a: unknown[]) => boolean).call(stream, chunk, ...rest);
    }) as typeof process.stdout.write;
  process.stdout.write = tee(stdoutWrite, process.stdout);
  process.stderr.write = tee(stderrWrite, process.stderr);
  try {
    return { out: await run(argv, deps), written: written.join("") };
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

test("S2: arguments longer than 300 characters are truncated with …", async () => {
  const { h, child, out } = setup();
  const long = "a".repeat(400);
  const res = await run(["run", "--only", "LOG_LEVEL", "--", child, out, "0", long], h.deps);
  assert.equal(res.exitCode, 0, res.stdout);
  const args = (h.human.approvals[0] as string[]).find((l) => l.startsWith(`${out} 0 aaa`)) as string;
  assert.equal(args.length, 300);
  assert.ok(args.endsWith("…"));
  assert.ok((h.human.approvals[0] as string[]).every((l) => l.length <= 300));
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
  assert.equal(records.length, 4);
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
  const { out: res, written } = await runCaptured(["run", "--only", "DATABASE_URL,SIGNING_KEY", "--", child, out, "0", marker], h.deps);
  assert.equal(res.exitCode, 0, res.stdout);
  assert.equal(res.stdout, "", "the child owns stdout");
  const env = childEnv(out);
  assert.deepEqual([...env.keys()].sort(), [...BASE_NAMES, "DATABASE_URL", "SIGNING_KEY"].sort());
  assert.equal(env.get("DATABASE_URL"), CANARY.length);
  assert.equal(env.get("SIGNING_KEY"), GENERATED.length);
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
  for (const value of [CANARY, GENERATED]) {
    assert.ok(!res.stdout.includes(value));
    assert.ok(!written.includes(value), "zks wrote a value to its own stdout/stderr");
    assert.ok(!audit.includes(value), "audit db or -wal holds a value");
  }
  for (const name of ["DATABASE_URL", "SIGNING_KEY"]) assert.equal(process.env[name], undefined, "zks's own env was changed");
});

test("S1: without --only every variable of the policy is injected", async () => {
  const { h, child, out } = setup();
  const res = await run(["run", "--", child, out], h.deps);
  assert.equal(res.exitCode, 0, res.stdout);
  const env = childEnv(out);
  for (const [name, value] of Object.entries(VALUES)) assert.equal(env.get(name), value.length, name);
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

test("S6: help lists zks run", () => {
  assert.match(HELP_TEXT, /zks run \[--policy FILE\] \[--only A,B\] \[--agent LABEL\] -- <command> \[args\.\.\.\]/);
});

test("PRESERVE: -- is still an unknown option for other commands", async () => {
  const h = harness({ policy });
  const res = await run(["apply", "--", "x"], h.deps);
  assert.equal(res.exitCode, 2);
  assert.equal(parse(res.stdout).error.message, "unknown option --");
});

test("PRESERVE: the dialog still replaces control and bidi characters; … reaches osascript as character id 8230", async () => {
  assert.equal(sanitizeLine("a\nb‮c…"), "a?b?c…");
  const exec = fakeExec(() => ({ stdout: Buffer.from("Approve\n") }));
  assert.equal(await createMacDialogs(exec.exec, "darwin").approve("t", ["args …"]), true);
  const script = exec.calls[0]?.input as string;
  assert.ok(script.includes("character id 8230"), script);
  assert.ok(!script.includes("…"));
});
