import assert from "node:assert/strict";
import { test } from "node:test";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { run } from "../src/run.ts";
import { harness, parse } from "./helpers.ts";

async function initDetect(h: ReturnType<typeof harness>, files: Record<string, string>, project?: string) {
  for (const [name, content] of Object.entries(files)) {
    await writeFile(`${h.dir}/${name}`, content);
  }
  const args = ["init", "--detect"];
  if (project) args.push("--project", project);
  const out = await run(args, h.deps);
  return { out, h };
}

function readPolicy(h: ReturnType<typeof harness>): Record<string, unknown> {
  const raw = h.files.get(join(h.dir, "zks.policy.json"));
  assert.ok(raw, "zks.policy.json was not created");
  return JSON.parse(raw as string) as Record<string, unknown>;
}

test("init --detect creates a policy from vercel.json", async () => {
  const h = harness({});
  const { out } = await initDetect(h, {
    "vercel.json": JSON.stringify({ projectId: "prj_abc123", orgId: "team_xyz789" }),
    ".env.example": "API_KEY=REPLACE_ME\nNEXT_PUBLIC_URL=https://example.com",
  });
  assert.equal(out.exitCode, 0, out.stdout);
  const body = parse(out.stdout);
  assert.ok(Array.isArray(body.detected));
  assert.ok(body.detected.some((d: string) => d.includes("vercel.json")));
  assert.ok(body.detected.some((d: string) => d.includes(".env.example")));

  const policy = readPolicy(h) as Record<string, unknown>;
  assert.equal(String(policy["project"]), "my-project");
  const targets = policy.targets as Record<string, unknown>;
  assert.ok(targets["vercel-prod"]);
  assert.equal((targets["vercel-prod"] as Record<string, unknown>).provider, "vercel");
  assert.equal((targets["vercel-prod"] as Record<string, unknown>).projectId, "prj_abc123");
  assert.equal((targets["vercel-prod"] as Record<string, unknown>).teamId, "team_xyz789");
  const variables = policy.variables as Record<string, unknown>;
  assert.ok(variables["API_KEY"]);
  assert.equal((variables["API_KEY"] as Record<string, unknown>).sensitive, true);
  assert.equal(((variables["API_KEY"] as Record<string, unknown>).source as Record<string, unknown>).kind, "generate");
  assert.ok(variables["NEXT_PUBLIC_URL"]);
  assert.equal((variables["NEXT_PUBLIC_URL"] as Record<string, unknown>).sensitive, false);
});

test("init --detect creates a policy from docker-compose.yml", async () => {
  const h = harness({});
  const { out } = await initDetect(h, {
    "docker-compose.yml": "services:\n  db:\n    image: postgres:15",
    ".env.example": "DB_PASSWORD=secret",
  });
  assert.equal(out.exitCode, 0, out.stdout);
  const body = parse(out.stdout);
  assert.ok(body.detected.some((d: string) => d.includes("docker-compose.yml")));
});

test("init --detect with no config files uses placeholders", async () => {
  const h = harness({});
  const { out } = await initDetect(h, {});
  assert.equal(out.exitCode, 0, out.stdout);
  const body = parse(out.stdout);
  assert.ok(body.detected.some((d: string) => d.includes("placeholder")));
  assert.ok(body.detected.some((d: string) => d.includes("vercel placeholder")));
});

test("init --detect does not overwrite existing policy", async () => {
  const h = harness({ files: { "zks.policy.json": "{}" } });
  const out = await run(["init", "--detect"], h.deps);
  assert.notEqual(out.exitCode, 0, "existing policy should fail");
});

test("init --detect accepts --project flag", async () => {
  const h = harness({ files: { ".env.example": "FOO=bar" } });
  const out = await run(["init", "--detect", "--project", "mi-proyecto"], h.deps);
  assert.equal(out.exitCode, 0, out.stdout);
  const policy = readPolicy(h) as Record<string, unknown>;
  assert.equal(policy.project, "mi-proyecto");
});

test("init without --detect creates the default template", async () => {
  const h = harness({});
  const out = await run(["init"], h.deps);
  assert.equal(out.exitCode, 0, out.stdout);
  const body = parse(out.stdout);
  assert.equal(body.created, `${h.dir}/zks.policy.json`);
  assert.equal(body.detected, undefined);
  const policy = readPolicy(h) as Record<string, unknown>;
  assert.equal(((policy["targets"] as Record<string, unknown>)["vercel-prod"] as Record<string, unknown>).provider, "vercel");
  assert.equal((((policy["variables"] as Record<string, unknown>)["API_SIGNING_KEY"] as Record<string, unknown>).source as Record<string, unknown>).kind, "generate");
});
