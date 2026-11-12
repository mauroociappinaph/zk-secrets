import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, existsSync, lstatSync, mkdirSync, readFileSync, readdirSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { createServer, type Server } from "node:net";
import { join } from "node:path";
import { after, test } from "node:test";
import { createExec } from "../src/platform/exec.ts";
import { parseToolPins, parseToolsFile, pinnedExec, resolveTools } from "../src/platform/tools.ts";
import { describeDestination, describeEffect } from "../src/policy/describe.ts";
import { describeTrustKey, trustKeyOf } from "../src/policy/trust.ts";
import type { Operation, TargetConfig } from "../src/policy/types.ts";
import { PolicyError, validatePolicy } from "../src/policy/validate.ts";
import { HELP_TEXT } from "../src/help.ts";
import { run } from "../src/run.ts";
import { SecretBuffer } from "../src/secret/secret-buffer.ts";
import { composeSink } from "../src/sinks/compose.ts";
import { dockerSwarmSink } from "../src/sinks/docker.ts";
import { SinkError, type SinkContext } from "../src/sinks/types.ts";
import { CANARY, TEST_TOOLS, auditBytes, fakeAws, fakeExec, fakeFetch, fakeKeychain, harness, parse, tempDir, type ExecCall } from "./helpers.ts";

const REPO = join(import.meta.dirname, "..");
const DOCKER = TEST_TOOLS.docker as string;

/** A real unix socket in a fresh temp dir (the sink lstats unix:// hosts); closed after the tests. */
async function realSocket(): Promise<{ path: string; host: string; server: Server }> {
  const path = join(tempDir(), "docker.sock");
  const server = createServer();
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(path, () => resolve());
  });
  return { path, host: `unix://${path}`, server };
}

const socket = await realSocket();
after(() => socket.server.close());
const SOCK = socket.host;
const TCP = "tcp://127.0.0.1:2375";

function op(target: TargetConfig, name = "API_KEY"): Operation {
  return { name, targetKey: "t", target, variable: { sensitive: true, targets: ["t"], source: { kind: "prompt" } }, sourceKind: "prompt" };
}

function ctx(exec = fakeExec(), tools = TEST_TOOLS) {
  const context: SinkContext = { fetch: fakeFetch().fetch, exec: exec.exec, aws: fakeAws().aws, keychain: fakeKeychain().keychain, tools };
  return { context, exec };
}

async function rejects(promise: Promise<unknown>, code: string, message: string): Promise<void> {
  await assert.rejects(promise, (error: unknown) => {
    assert.ok(error instanceof SinkError, String(error));
    assert.equal(error.code, code);
    assert.equal(error.message, message);
    return true;
  });
}

/** A docker that knows the secrets in `existing`; create answers with an id. */
function docker(existing: string[] = [], fail: Partial<Record<string, number>> = {}) {
  return fakeExec((call: ExecCall) => {
    const sub = call.args[call.args.indexOf("secret") + 1] as string;
    if (fail[sub] !== undefined) return { code: fail[sub], stderr: Buffer.from(`error ${CANARY}`) };
    if (sub === "inspect") return existing.includes(call.args[call.args.length - 1] as string) ? { stdout: Buffer.from("abc\n") } : { code: 1 };
    if (sub === "create") return { stdout: Buffer.from("k3y1d0000000000000000000a\n") };
    return {};
  });
}

const argvHasNoValue = (calls: ExecCall[]) => calls.every((c) => !c.args.join(" ").includes(CANARY));

// docker-swarm

test("S12: docker-swarm creates the secret with the value on stdin only", async () => {
  const c = ctx(docker());
  assert.deepEqual(await dockerSwarmSink.apply(op({ provider: "docker-swarm", host: SOCK }), SecretBuffer.fromString(CANARY), c.context), {
    version: "k3y1d0000000000000000000a",
  });
  assert.deepEqual(
    c.exec.calls.map((call) => [call.command, call.args, call.input]),
    [
      [DOCKER, ["--host", SOCK, "secret", "inspect", "--format", "{{.ID}}", "API_KEY"], ""],
      [DOCKER, ["--host", SOCK, "secret", "create", "API_KEY", "-"], CANARY],
    ],
  );

  // R1: the policy host is always passed as --host and the user's docker config/contexts are ignored.
  assert.ok(c.exec.calls.every((call) => call.args[0] === "--host" && call.args[1] === SOCK && !call.args.includes("--context")));
  assert.deepEqual(c.exec.calls.map((call) => call.env), [{ DOCKER_CONFIG: "/var/empty" }, { DOCKER_CONFIG: "/var/empty" }]);

  // tcp:// hosts have no local check.
  const tcp = ctx(docker());
  await dockerSwarmSink.apply(op({ provider: "docker-swarm", host: TCP }), SecretBuffer.fromString(CANARY), tcp.context);
  assert.deepEqual(tcp.exec.calls[1]!.args, ["--host", TCP, "secret", "create", "API_KEY", "-"]);
});

test("S12 R1: a unix:// host must be a real socket, not a symlink, a missing path or a file; nothing runs when refused", async () => {
  assert.ok(lstatSync(socket.path).isSocket());
  const dir = tempDir();
  const link = join(dir, "link.sock");
  symlinkSync(socket.path, link);
  const file = join(dir, "file.sock");
  writeFileSync(file, "");
  const missing = join(dir, "missing.sock");
  for (const path of [link, missing, file]) {
    const c = ctx(docker());
    await rejects(
      dockerSwarmSink.apply(op({ provider: "docker-swarm", host: `unix://${path}` }), SecretBuffer.fromString(CANARY), c.context),
      "docker_host_invalid",
      `${path} is not a socket; zks talks only to a real docker socket, not a symlink`,
    );
    assert.equal(c.exec.calls.length, 0, path);
  }

  const real = ctx(docker());
  await dockerSwarmSink.apply(op({ provider: "docker-swarm", host: SOCK }), SecretBuffer.fromString(CANARY), real.context);
  assert.equal(real.exec.calls.length, 2);
});

test("S12: an existing docker secret is secret_exists unless replace: true, which removes then creates it", async () => {
  const kept = ctx(docker(["API_KEY"]));
  await rejects(
    dockerSwarmSink.apply(op({ provider: "docker-swarm", host: SOCK }), SecretBuffer.fromString(CANARY), kept.context),
    "secret_exists",
    "docker secret API_KEY already exists; set replace: true on the target to remove and recreate it",
  );
  assert.equal(kept.exec.calls.length, 1);

  const replaced = ctx(docker(["API_KEY"]));
  await dockerSwarmSink.apply(op({ provider: "docker-swarm", host: SOCK, replace: true }), SecretBuffer.fromString(CANARY), replaced.context);
  assert.deepEqual(
    replaced.exec.calls.map((call) => call.args.slice(2, 4)),
    [["secret", "inspect"], ["secret", "rm"], ["secret", "create"]],
  );
  assert.deepEqual(replaced.exec.calls[1]!.args, ["--host", SOCK, "secret", "rm", "API_KEY"]);
  assert.ok(argvHasNoValue(replaced.exec.calls));
});

test("S12: docker failures report the step and exit code, never docker's output", async () => {
  const inUse = ctx(docker(["API_KEY"], { rm: 1 }));
  await rejects(
    dockerSwarmSink.apply(op({ provider: "docker-swarm", host: SOCK, replace: true }), SecretBuffer.fromString(CANARY), inUse.context),
    "docker_failed",
    "docker secret rm API_KEY failed (exit 1); a service may still use it",
  );
  assert.equal(inUse.exec.calls.length, 2);

  const create = ctx(docker([], { create: 1 }));
  await rejects(dockerSwarmSink.apply(op({ provider: "docker-swarm", host: SOCK }), SecretBuffer.fromString(CANARY), create.context), "docker_failed", "docker secret create API_KEY failed (exit 1)");

  const none = ctx(fakeExec(), { ...TEST_TOOLS, docker: null });
  await rejects(
    dockerSwarmSink.apply(op({ provider: "docker-swarm", host: SOCK }), SecretBuffer.fromString(CANARY), none.context),
    "docker_unavailable",
    "docker is not available; install Docker and rerun ./install.sh",
  );
  assert.equal(none.exec.calls.length, 0);

  const changed = ctx({ calls: [], exec: async () => Promise.reject(Object.assign(new Error("docker changed since install"), { code: "tool_changed" })) });
  await rejects(dockerSwarmSink.apply(op({ provider: "docker-swarm", host: SOCK }), SecretBuffer.fromString(CANARY), changed.context), "docker_unavailable", "docker is not available; install Docker and rerun ./install.sh");
});

test("S12 S1: a real docker binary gets the value on stdin, never in argv or its environment", async () => {
  const dir = tempDir();
  const fake = join(dir, "docker");
  writeFileSync(
    fake,
    `#!/bin/sh\nprintf '%s\\n' "$@" >>"${dir}/argv"\n/usr/bin/env >>"${dir}/env"\ncase "$4" in inspect) exit 1;; create) /bin/cat >"${dir}/stdin"; echo abcdef123;; esac\n`,
    { mode: 0o755 },
  );
  const exec = createExec({ home: dir, user: "tester" });
  const c = ctx({ calls: [], exec }, { ...TEST_TOOLS, docker: fake });
  assert.deepEqual(await dockerSwarmSink.apply(op({ provider: "docker-swarm", host: SOCK }), SecretBuffer.fromString(CANARY), c.context), { version: "abcdef123" });
  assert.equal(readFileSync(join(dir, "stdin"), "utf8"), CANARY);
  assert.ok(!readFileSync(join(dir, "argv"), "utf8").includes(CANARY));
  const env = readFileSync(join(dir, "env"), "utf8");
  assert.ok(!env.includes(CANARY));
  assert.ok(env.includes("DOCKER_CONFIG=/var/empty\n"));
  assert.ok(readFileSync(join(dir, "argv"), "utf8").startsWith(`--host\n${SOCK}\n`));
});

test("S12: docker is a pinned tool in tools.json, looked up on SAFE_PATH in a development run", async () => {
  const text = JSON.stringify({ "ego-browser": null, gh: null, op: null, docker: { path: "/usr/local/bin/docker", sha256: "e".repeat(64) } });
  assert.equal(parseToolsFile(text).docker, "/usr/local/bin/docker");
  assert.equal(parseToolPins(text).docker, "e".repeat(64));
  assert.equal(parseToolsFile(JSON.stringify({ gh: null })).docker, null);
  assert.equal(resolveTools(null, (path) => path === "/usr/local/bin/docker").docker, "/usr/local/bin/docker");

  const warnings: string[] = [];
  const base = fakeExec();
  const tools = { egoBrowser: null, gh: null, op: null, docker: "/usr/local/bin/docker" };
  const exec = pinnedExec(base.exec, tools, { egoBrowser: null, gh: null, op: null, docker: "e".repeat(64) }, {
    hashFile: async () => "f".repeat(64),
    warn: (line) => warnings.push(line),
  });
  await assert.rejects(exec("/usr/local/bin/docker", ["secret", "ls"]), { code: "tool_changed" });
  assert.equal(base.calls.length, 0);
  assert.deepEqual(warnings, ["zks: docker changed since install (sha256 mismatch); rerun ./install.sh to pin the new binary\n"]);
});

test("S12: install.sh pins docker found on SAFE_PATH and records null when it is absent", () => {
  const source = readFileSync(join(REPO, "install.sh"), "utf8");
  const start = source.indexOf("tool_path() {");
  const end = source.indexOf('chmod 444 "$DEST/tools.json"');
  assert.ok(start > 0 && end > start);
  const dir = tempDir();
  const safe = join(dir, "safe");
  mkdirSync(safe);
  mkdirSync(join(dir, "dest"));
  const step = (safePath: string) => {
    const script = `set -eu\nDEST="${dir}/dest"; SAFE_PATH="${safePath}"\n${source.slice(start, end)}\n`;
    const r = spawnSync("/bin/sh", ["-c", script], { env: { PATH: `${process.execPath.replace(/\/node$/, "")}:/usr/bin:/bin` }, encoding: "utf8" });
    assert.equal(r.status, 0, r.stderr);
    return JSON.parse(readFileSync(join(dir, "dest", "tools.json"), "utf8")) as Record<string, unknown>;
  };
  assert.equal(step(`${safe}:/usr/bin:/bin`).docker, null);
  writeFileSync(join(safe, "docker"), "#!/bin/sh\n", { mode: 0o755 });
  const sha = spawnSync("/usr/bin/shasum", ["-a", "256", join(safe, "docker")], { encoding: "utf8" }).stdout.split(" ")[0];
  assert.deepEqual(step(`${safe}:/usr/bin:/bin`).docker, { path: join(safe, "docker"), sha256: sha });
});

// compose

test("S12: compose writes <dir>/<NAME> with mode 600, creating dir with 700, and leaves no temp file", async () => {
  const root = tempDir();
  const dir = join(root, "secrets");
  const c = ctx();
  assert.deepEqual(await composeSink.apply(op({ provider: "compose", dir }), SecretBuffer.fromString(CANARY), c.context), {});
  assert.equal(readFileSync(join(dir, "API_KEY"), "utf8"), CANARY);
  assert.equal(statSync(join(dir, "API_KEY")).mode & 0o777, 0o600);
  assert.equal(statSync(dir).mode & 0o777, 0o700);
  assert.deepEqual(readdirSync(dir), ["API_KEY"]);

  writeFileSync(join(dir, "API_KEY"), "old", { mode: 0o644 });
  await composeSink.apply(op({ provider: "compose", dir }), SecretBuffer.fromString("new"), c.context);
  assert.equal(readFileSync(join(dir, "API_KEY"), "utf8"), "new");
  assert.equal(statSync(join(dir, "API_KEY")).mode & 0o777, 0o600);
  assert.deepEqual(readdirSync(dir), ["API_KEY"]);
  assert.equal(c.exec.calls.length, 0);
});

test("S12: compose refuses symlinks and directories others can read, writing nothing", async () => {
  const root = tempDir();
  const real = join(root, "real");
  mkdirSync(real, { mode: 0o700 });
  symlinkSync(real, join(root, "link"));
  await rejects(composeSink.apply(op({ provider: "compose", dir: join(root, "link") }), SecretBuffer.fromString(CANARY), ctx().context), "symlink_refused", `${join(root, "link")} is a symlink; zks writes only to real files and directories`);
  assert.deepEqual(readdirSync(real), []);

  symlinkSync(join(root, "elsewhere"), join(real, "API_KEY"));
  await rejects(composeSink.apply(op({ provider: "compose", dir: real }), SecretBuffer.fromString(CANARY), ctx().context), "symlink_refused", `${join(real, "API_KEY")} is a symlink; zks writes only to real files and directories`);
  assert.equal(existsSync(join(root, "elsewhere")), false);
  assert.deepEqual(readdirSync(real), ["API_KEY"]);
  assert.ok(lstatSync(join(real, "API_KEY")).isSymbolicLink());

  const open = join(root, "open");
  mkdirSync(open);
  chmodSync(open, 0o755);
  await rejects(composeSink.apply(op({ provider: "compose", dir: open }), SecretBuffer.fromString(CANARY), ctx().context), "insecure_dir", `${open} is accessible by other users; run chmod 700 ${open}`);
  assert.deepEqual(readdirSync(open), []);

  writeFileSync(join(root, "file"), "");
  await rejects(composeSink.apply(op({ provider: "compose", dir: join(root, "file") }), SecretBuffer.fromString(CANARY), ctx().context), "not_a_directory", `${join(root, "file")} is not a directory`);
});

// policy, trust, describe

test("S12: docker-swarm and compose targets are validated; docker secret names follow docker's rules", () => {
  const policy = (target: unknown, name = "API_KEY") => ({
    version: 1,
    project: "p",
    targets: { t: target },
    variables: { [name]: { sensitive: true, source: { kind: "prompt" }, targets: ["t"] } },
  });
  const issues = (input: unknown) => {
    try {
      validatePolicy(input);
      return [];
    } catch (error) {
      return (error as PolicyError).issues;
    }
  };
  assert.deepEqual(issues(policy({ provider: "docker-swarm", host: "tcp://10.0.0.5:2376", replace: true })), []);
  assert.deepEqual(issues(policy({ provider: "compose", dir: "./secrets" })), []);
  assert.deepEqual(issues(policy({ provider: "docker-swarm", host: "unix:///run/docker.sock" })), []);
  assert.deepEqual(issues(policy({ provider: "docker-swarm", host: "prod", replace: "yes" })), [
    "targets.t.host: must be unix:///path or tcp://host:port",
    "targets.t.replace: must be a boolean",
  ]);
  // R1: ssh:// resolves through the user's ssh client config, so it is refused; tcp:// needs a port.
  for (const host of ["ssh://deploy@h", "ssh://deploy@swarm.example.com:22", "tcp://10.0.0.5", "unix://run/docker.sock"]) {
    assert.deepEqual(issues(policy({ provider: "docker-swarm", host })), ["targets.t.host: must be unix:///path or tcp://host:port"], host);
  }
  assert.deepEqual(issues(policy({ provider: "docker-swarm", host: SOCK }, "_KEY_")), ["variables._KEY_: docker secret names must start and end with a letter or digit (target \"t\")"]);
  assert.deepEqual(issues(policy({ provider: "compose", dir: "" })), ["targets.t.dir: must be a path of 1 to 200 printable characters"]);
  assert.deepEqual(issues(policy({ provider: "compose", dir: "a\nb" })), ["targets.t.dir: must be a path of 1 to 200 printable characters"]);
});

test("S12: trust keys, destinations and effects of docker-swarm and compose", () => {
  assert.equal(trustKeyOf(op({ provider: "docker-swarm", host: SOCK })), "docker-swarm:" + SOCK);
  assert.equal(trustKeyOf(op({ provider: "docker-swarm", host: "tcp://h:2376" })), "docker-swarm:tcp://h:2376");
  assert.equal(trustKeyOf(op({ provider: "compose", dir: "/w/secrets" })), "compose:/w/secrets");
  assert.equal(describeTrustKey("docker-swarm:tcp://h:2376"), "Docker swarm at tcp://h:2376");
  assert.equal(describeTrustKey("docker-swarm:" + SOCK), "Docker swarm at " + SOCK);
  assert.equal(describeTrustKey("compose:/w/a:b"), "Compose secrets directory /w/a:b");
  assert.equal(describeDestination(op({ provider: "docker-swarm", host: SOCK, replace: true })), "docker-swarm secret API_KEY at " + SOCK + " (replace)");
  assert.equal(describeDestination(op({ provider: "docker-swarm", host: SOCK })), "docker-swarm secret API_KEY at " + SOCK);
  assert.equal(describeDestination(op({ provider: "compose", dir: "/w/secrets" })), "compose file /w/secrets/API_KEY");
  assert.equal(describeEffect(op({ provider: "docker-swarm", host: SOCK })), "update services to use the new secret");
  assert.equal(describeEffect(op({ provider: "compose", dir: "/w" })), "restart the Compose stack to use it");
  assert.ok(HELP_TEXT.includes("docker-swarm") && HELP_TEXT.includes("compose {dir}"));
});

test("S12 S1 S5: apply to compose resolves dir against cwd, asks for the new destination and audits no value", async () => {
  const policy = {
    version: 1,
    project: "web",
    targets: { files: { provider: "compose", dir: "run/secrets" } },
    variables: { API_KEY: { sensitive: true, source: { kind: "keychain", service: "app", account: "key" }, targets: ["files"] } },
  };
  const h = harness({ policy, keychain: { "app/key": CANARY } });
  const dir = join(h.dir, "run", "secrets");

  const plan = await run(["plan"], h.deps);
  assert.equal(parse(plan.stdout).operations[0].destination, `compose file ${dir}/API_KEY`);
  assert.equal(existsSync(dir), false);

  const denied = harness({ policy, keychain: { "app/key": CANARY }, approve: false });
  assert.equal((await run(["apply"], denied.deps)).exitCode, 3);
  assert.equal(existsSync(join(denied.dir, "run")), false);

  const out = await run(["apply"], h.deps);
  assert.equal(out.exitCode, 0, out.stdout);
  assert.ok(h.human.approvals[0]!.some((line) => line.includes(`compose file ${dir}/API_KEY`) && line.includes("[NEW destination]")));
  assert.equal(readFileSync(join(dir, "API_KEY"), "utf8"), CANARY);
  assert.ok(!out.stdout.includes(CANARY));
  assert.ok(!(await auditBytes(h.auditDb)).includes(CANARY));
});
