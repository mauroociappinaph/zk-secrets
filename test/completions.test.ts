import assert from "node:assert/strict";
import { test } from "node:test";
import { run } from "../src/run.ts";
import { harness, parse } from "./helpers.ts";

test("completions bash outputs a function definition", async () => {
  const h = harness({});
  const out = await run(["completions", "bash"], h.deps);
  assert.equal(out.exitCode, 0, out.stdout);
  assert.ok(out.stdout.includes("_zks()"));
  assert.ok(out.stdout.includes("complete -F _zks zks"));
  assert.ok(out.stdout.includes("--detect"));
});

test("completions zsh outputs a compdef", async () => {
  const h = harness({});
  const out = await run(["completions", "zsh"], h.deps);
  assert.equal(out.exitCode, 0, out.stdout);
  assert.ok(out.stdout.includes("#compdef zks"));
  assert.ok(out.stdout.includes("init:Create a zks.policy.json template"));
});

test("completions fish outputs complete rules", async () => {
  const h = harness({});
  const out = await run(["completions", "fish"], h.deps);
  assert.equal(out.exitCode, 0, out.stdout);
  assert.ok(out.stdout.includes("complete -c zks"));
  assert.ok(out.stdout.includes("-l detect"));
});

test("completions without shell defaults to bash", async () => {
  const h = harness({});
  const out = await run(["completions"], h.deps);
  assert.equal(out.exitCode, 0, out.stdout);
  assert.ok(out.stdout.includes("_zks()"));
});

test("completions with unknown shell fails", async () => {
  const h = harness({});
  const out = await run(["completions", "powershell"], h.deps);
  assert.notEqual(out.exitCode, 0, "unknown shell should fail");
  assert.ok(out.stdout.includes("usage: zks completions <bash|zsh|fish>"));
});
