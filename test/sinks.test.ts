import assert from "node:assert/strict";
import { test } from "node:test";
import type { Operation, TargetConfig } from "../src/policy/types.ts";
import { SecretBuffer } from "../src/secret/secret-buffer.ts";
import { awsSmSink, awsSsmSink } from "../src/sinks/aws.ts";
import { sessionPolicyFor } from "../src/sinks/aws-clients.ts";
import { githubSink } from "../src/sinks/github.ts";
import { railwaySink } from "../src/sinks/railway.ts";
import { supabaseSink } from "../src/sinks/supabase.ts";
import { SinkError, type SinkContext } from "../src/sinks/types.ts";
import { vercelSink } from "../src/sinks/vercel.ts";
import { CANARY, fakeAws, fakeExec, fakeFetch, fakeKeychain } from "./helpers.ts";

function op(target: TargetConfig, sensitive = true, name = "API_KEY"): Operation {
  return { name, targetKey: "t", target, variable: { sensitive, targets: ["t"], source: { kind: "prompt" } }, sourceKind: "prompt" };
}

function ctx(parts: Partial<{ fetch: ReturnType<typeof fakeFetch>; exec: ReturnType<typeof fakeExec>; aws: ReturnType<typeof fakeAws>; tokens: Record<string, string> }> = {}) {
  const fetch = parts.fetch ?? fakeFetch();
  const exec = parts.exec ?? fakeExec();
  const aws = parts.aws ?? fakeAws();
  const { keychain } = fakeKeychain(parts.tokens ?? { "zks/vercel": "tv", "zks/railway": "tr", "zks/supabase": "ts" });
  const context: SinkContext = { fetch: fetch.fetch, exec: exec.exec, aws: aws.aws, keychain };
  return { context, fetch, exec, aws };
}

const secret = () => SecretBuffer.fromString(CANARY);

async function rejects(promise: Promise<unknown>, code: string): Promise<SinkError> {
  try {
    await promise;
  } catch (error) {
    assert.ok(error instanceof SinkError, String(error));
    assert.equal(error.code, code);
    assert.ok(!error.message.includes(CANARY));
    return error;
  }
  assert.fail("expected rejection");
}

test("vercel upserts a sensitive env var with the team and returns the created id", async () => {
  const c = ctx({ fetch: fakeFetch(() => ({ body: { created: { id: "env_123" } } })) });
  const target = { provider: "vercel", projectId: "prj 1", teamId: "team_9", environments: ["production"], gitBranch: "main" } as const;

  const res = await vercelSink.apply(op({ ...target, environments: ["production"] }), secret(), c.context);

  assert.deepEqual(res, { version: "env_123" });
  const call = c.fetch.calls[0]!;
  assert.equal(call.url, "https://api.vercel.com/v10/projects/prj%201/env?upsert=true&teamId=team_9");
  assert.equal(call.init.method, "POST");
  assert.equal((call.init.headers as Record<string, string>).authorization, "Bearer tv");
  assert.deepEqual(JSON.parse(call.body), { key: "API_KEY", value: CANARY, type: "sensitive", target: ["production"], gitBranch: "main" });
});

test("vercel without a token fails with missing_token before any request", async () => {
  const c = ctx({ tokens: {} });
  const err = await rejects(vercelSink.apply(op({ provider: "vercel", projectId: "p", environments: ["preview"] }), secret(), c.context), "missing_token");
  assert.equal(err.message, "no vercel token in the Keychain; run `zks auth set vercel`");
  assert.equal(c.fetch.calls.length, 0);
});

test("vercel errors expose only the provider error code", async () => {
  const c = ctx({ fetch: fakeFetch(() => ({ status: 403, body: { error: { code: "forbidden", message: `nope ${CANARY}` } } })) });
  const err = await rejects(vercelSink.apply(op({ provider: "vercel", projectId: "p", environments: ["preview"] }), secret(), c.context), "vercel_failed");
  assert.equal(err.message, "Vercel forbidden");
  assert.equal(err.status, 403);
});

test("aws-ssm writes a SecureString with the KMS key under the prefix", async () => {
  const c = ctx({ aws: fakeAws(() => ({ Version: 4 })) });
  const res = await awsSsmSink.apply(
    op({ provider: "aws-ssm", region: "sa-east-1", prefix: "/app/prod/", kmsKeyId: "alias/app" }),
    secret(),
    c.context,
  );
  assert.deepEqual(res, { version: "4" });
  assert.deepEqual(c.aws.calls[0], {
    client: "ssm",
    command: "PutParameterCommand",
    input: { Name: "/app/prod/API_KEY", Value: CANARY, Type: "SecureString", KeyId: "alias/app", Overwrite: true },
  });
});

test("aws-ssm maps SDK errors to their name only", async () => {
  const c = ctx({
    aws: fakeAws(() => {
      throw Object.assign(new Error(`AccessDenied for ${CANARY}`), { name: "AccessDeniedException", $metadata: { httpStatusCode: 400 } });
    }),
  });
  const err = await rejects(awsSsmSink.apply(op({ provider: "aws-ssm", region: "us-east-1", prefix: "/" }), secret(), c.context), "AccessDeniedException");
  assert.equal(err.message, "AWS AccessDeniedException");
});

test("aws-sm puts a new version, and creates the secret when it does not exist", async () => {
  const existing = ctx({ aws: fakeAws(() => ({ VersionId: "v-1" })) });
  assert.deepEqual(await awsSmSink.apply(op({ provider: "aws-sm", region: "us-east-1", prefix: "app/" }), secret(), existing.context), { version: "v-1" });
  assert.deepEqual(existing.aws.calls.map((c) => c.command), ["PutSecretValueCommand"]);

  const missing = ctx({
    aws: fakeAws((call) => {
      if (call.command === "PutSecretValueCommand") throw Object.assign(new Error("x"), { name: "ResourceNotFoundException" });
      return { VersionId: "v-new" };
    }),
  });
  const res = await awsSmSink.apply(op({ provider: "aws-sm", region: "us-east-1", prefix: "app/", kmsKeyId: "k1" }), secret(), missing.context);
  assert.deepEqual(res, { version: "v-new" });
  assert.deepEqual(missing.aws.calls[1], {
    client: "sm",
    command: "CreateSecretCommand",
    input: { Name: "app/API_KEY", SecretString: CANARY, KmsKeyId: "k1" },
  });
});

test("aws session policy only allows writes under the prefix", () => {
  const ssm = JSON.parse(sessionPolicyFor({ provider: "aws-ssm", region: "sa-east-1", prefix: "/app/prod/" }));
  assert.deepEqual(ssm.Statement[0], {
    Effect: "Allow",
    Action: ["ssm:PutParameter", "ssm:AddTagsToResource"],
    Resource: "arn:aws:ssm:sa-east-1:*:parameter/app/prod/*",
  });
  const sm = JSON.parse(sessionPolicyFor({ provider: "aws-sm", region: "us-east-1", prefix: "app/" }));
  assert.equal(sm.Statement[0].Resource, "arn:aws:secretsmanager:us-east-1:*:secret:app/*");
  assert.ok(!JSON.stringify([ssm, sm]).includes("Get"), "no read actions");
});

test("github secrets go on stdin; failures do not echo stderr", async () => {
  const ok = ctx();
  await githubSink.apply(op({ provider: "github", repo: "acme/web", environment: "prod" }), secret(), ok.context);
  assert.deepEqual(ok.exec.calls, [{ command: "gh", args: ["secret", "set", "API_KEY", "--repo", "acme/web", "--env", "prod"], input: CANARY }]);

  const failing = ctx({ exec: fakeExec(() => ({ code: 1, stderr: Buffer.from(`bad ${CANARY}`) })) });
  const err = await rejects(githubSink.apply(op({ provider: "github", repo: "acme/web" }), secret(), failing.context), "github_failed");
  assert.equal(err.message, "gh secret set exited 1");
});

test("railway upserts through GraphQL with an account or project token", async () => {
  const account = ctx({ fetch: fakeFetch(() => ({ body: { data: { variableUpsert: true } } })) });
  await railwaySink.apply(op({ provider: "railway", projectId: "p", environmentId: "e", serviceId: "s", skipDeploys: true }), secret(), account.context);
  const call = account.fetch.calls[0]!;
  assert.equal(call.url, "https://backboard.railway.com/graphql/v2");
  assert.equal((call.init.headers as Record<string, string>).authorization, "Bearer tr");
  assert.deepEqual(JSON.parse(call.body).variables, {
    input: { projectId: "p", environmentId: "e", name: "API_KEY", value: CANARY, serviceId: "s", skipDeploys: true },
  });

  const project = ctx();
  await railwaySink.apply(op({ provider: "railway", projectId: "p", environmentId: "e", tokenType: "project" }), secret(), project.context);
  const headers = project.fetch.calls[0]!.init.headers as Record<string, string>;
  assert.equal(headers["project-access-token"], "tr");
  assert.equal(headers.authorization, undefined);
});

test("railway GraphQL errors fail without echoing them", async () => {
  const c = ctx({ fetch: fakeFetch(() => ({ body: { errors: [{ message: `bad ${CANARY}` }] } })) });
  const err = await rejects(railwaySink.apply(op({ provider: "railway", projectId: "p", environmentId: "e" }), secret(), c.context), "railway_failed");
  assert.equal(err.message, "Railway rejected the upsert (HTTP 200)");
});

test("supabase sets an edge function secret and reports HTTP failures", async () => {
  const c = ctx({ fetch: fakeFetch(() => ({ status: 201 })) });
  await supabaseSink.apply(op({ provider: "supabase", projectRef: "abcdefghijklmnopqrst" }), secret(), c.context);
  assert.equal(c.fetch.calls[0]!.url, "https://api.supabase.com/v1/projects/abcdefghijklmnopqrst/secrets");
  assert.deepEqual(JSON.parse(c.fetch.calls[0]!.body), [{ name: "API_KEY", value: CANARY }]);

  const failing = ctx({ fetch: fakeFetch(() => ({ status: 401, body: CANARY })) });
  const err = await rejects(supabaseSink.apply(op({ provider: "supabase", projectRef: "abcdefghijklmnopqrst" }), secret(), failing.context), "supabase_failed");
  assert.equal(err.message, "Supabase HTTP 401");
});

test("network failures become <provider>_unreachable", async () => {
  const c = ctx();
  c.context.fetch = (async () => {
    throw new Error(`socket ${CANARY}`);
  }) as typeof fetch;
  const err = await rejects(supabaseSink.apply(op({ provider: "supabase", projectRef: "abcdefghijklmnopqrst" }), secret(), c.context), "supabase_unreachable");
  assert.equal(err.message, "supabase API request failed");
});
