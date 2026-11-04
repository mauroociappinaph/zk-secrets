import assert from "node:assert/strict";
import { test } from "node:test";
import type { Operation, TargetConfig } from "../src/policy/types.ts";
import { SecretBuffer } from "../src/secret/secret-buffer.ts";
import { awsSmSink, awsSsmSink } from "../src/sinks/aws.ts";
import { createAwsClientFactory, sessionPolicyFor } from "../src/sinks/aws-clients.ts";
import { githubSink } from "../src/sinks/github.ts";
import { railwaySink } from "../src/sinks/railway.ts";
import { supabaseSink } from "../src/sinks/supabase.ts";
import { SinkError, type SinkContext } from "../src/sinks/types.ts";
import { vercelSink } from "../src/sinks/vercel.ts";
import {
  CANARY,
  GH_TOKEN,
  GITHUB_KEY_ID,
  fakeAws,
  fakeExec,
  fakeFetch,
  fakeKeychain,
  ghTokenExec,
  openSealed,
  providerResponse,
  type FetchCall,
} from "./helpers.ts";

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

test("aws clients ignore endpoint URLs configured in ~/.aws/config", async () => {
  const factory = createAwsClientFactory();
  const ssm = factory.ssm({ provider: "aws-ssm", region: "us-east-1", prefix: "/a/" }) as unknown as { config: Record<string, unknown> };
  const sm = factory.secretsManager({ provider: "aws-sm", region: "us-east-1", prefix: "a/" }) as unknown as { config: Record<string, unknown> };
  for (const client of [ssm, sm]) {
    const setting = client.config.ignoreConfiguredEndpointUrls;
    assert.equal(typeof setting === "function" ? await (setting as () => Promise<boolean>)() : setting, true);
  }
});

const GH_HEADERS = {
  authorization: `Bearer ${GH_TOKEN}`,
  accept: "application/vnd.github+json",
  "x-github-api-version": "2022-11-28",
  "user-agent": "zks",
};

function headersOf(call: FetchCall): Record<string, string> {
  const headers = call.init.headers as Record<string, string>;
  const { "content-type": _contentType, ...rest } = headers;
  return rest;
}

function assertNoCanary(c: { fetch: ReturnType<typeof fakeFetch>; exec: ReturnType<typeof fakeExec> }) {
  for (const call of c.fetch.calls) {
    assert.ok(!call.url.includes(CANARY), call.url);
    assert.ok(!call.body.includes(CANARY), "GitHub body carries the plaintext");
    assert.ok(!JSON.stringify(call.init.headers).includes(CANARY));
  }
  for (const call of c.exec.calls) assert.ok(!`${call.args.join(" ")} ${call.input}`.includes(CANARY));
}

test("github secret: gets the repo public key, seals the value and PUTs it with the key id", async () => {
  const c = ctx({ exec: fakeExec(ghTokenExec), fetch: fakeFetch(providerResponse) });

  const res = await githubSink.apply(op({ provider: "github", repo: "acme/web" }), secret(), c.context);

  assert.deepEqual(res, { version: GITHUB_KEY_ID });
  assert.deepEqual(c.exec.calls, [{ command: "gh", args: ["auth", "token", "--hostname", "github.com"], input: "" }]);
  assert.deepEqual(
    c.fetch.calls.map((call) => [call.init.method, call.url]),
    [
      ["GET", "https://api.github.com/repos/acme/web/actions/secrets/public-key"],
      ["PUT", "https://api.github.com/repos/acme/web/actions/secrets/API_KEY"],
    ],
  );
  for (const call of c.fetch.calls) assert.deepEqual(headersOf(call), GH_HEADERS);
  const body = JSON.parse(c.fetch.calls[1]!.body) as { encrypted_value: string; key_id: string };
  assert.deepEqual(Object.keys(body).sort(), ["encrypted_value", "key_id"]);
  assert.equal(body.key_id, GITHUB_KEY_ID);
  assert.equal(openSealed(body.encrypted_value), CANARY);
  assertNoCanary(c);
});

test("github environment secret uses the environment public key and path", async () => {
  const c = ctx({ exec: fakeExec(ghTokenExec), fetch: fakeFetch(providerResponse) });
  await githubSink.apply(op({ provider: "github", repo: "acme/web", environment: "prod" }), secret(), c.context);
  assert.deepEqual(
    c.fetch.calls.map((call) => [call.init.method, call.url]),
    [
      ["GET", "https://api.github.com/repos/acme/web/environments/prod/secrets/public-key"],
      ["PUT", "https://api.github.com/repos/acme/web/environments/prod/secrets/API_KEY"],
    ],
  );
  assert.equal(openSealed(JSON.parse(c.fetch.calls[1]!.body).encrypted_value), CANARY);
});

test("github variable: PATCH updates an existing one; 404 falls back to POST", async () => {
  const existing = ctx({ exec: fakeExec(ghTokenExec), fetch: fakeFetch(providerResponse) });
  assert.deepEqual(await githubSink.apply(op({ provider: "github", repo: "acme/web" }, false, "LOG_LEVEL"), SecretBuffer.fromString("info"), existing.context), {});
  assert.deepEqual(
    existing.fetch.calls.map((call) => [call.init.method, call.url, JSON.parse(call.body)]),
    [["PATCH", "https://api.github.com/repos/acme/web/actions/variables/LOG_LEVEL", { name: "LOG_LEVEL", value: "info" }]],
  );
  assert.deepEqual(headersOf(existing.fetch.calls[0]!), GH_HEADERS);

  const missing = ctx({
    exec: fakeExec(ghTokenExec),
    fetch: fakeFetch((call) => (call.init.method === "PATCH" ? { status: 404, body: { message: "Not Found" } } : { status: 201 })),
  });
  await githubSink.apply(op({ provider: "github", repo: "acme/web", environment: "prod" }, false, "LOG_LEVEL"), SecretBuffer.fromString("info"), missing.context);
  assert.deepEqual(
    missing.fetch.calls.map((call) => [call.init.method, call.url, JSON.parse(call.body)]),
    [
      ["PATCH", "https://api.github.com/repos/acme/web/environments/prod/variables/LOG_LEVEL", { name: "LOG_LEVEL", value: "info" }],
      ["POST", "https://api.github.com/repos/acme/web/environments/prod/variables", { name: "LOG_LEVEL", value: "info" }],
    ],
  );
});

test("github without a gh login fails with missing_token before any request", async () => {
  for (const answer of [{ code: 1 }, { stdout: Buffer.from("\n") }, {}]) {
    const c = ctx({ exec: fakeExec(() => answer), fetch: fakeFetch(providerResponse) });
    const err = await rejects(githubSink.apply(op({ provider: "github", repo: "acme/web" }), secret(), c.context), "missing_token");
    assert.equal(err.message, "no GitHub login; run `gh auth login`");
    assert.equal(c.fetch.calls.length, 0);
  }
});

test("github HTTP errors report only the status, never the body", async () => {
  const keyFails = ctx({ exec: fakeExec(ghTokenExec), fetch: fakeFetch(() => ({ status: 403, body: { message: `nope ${CANARY} ${GH_TOKEN}` } })) });
  const err = await rejects(githubSink.apply(op({ provider: "github", repo: "acme/web" }), secret(), keyFails.context), "github_failed");
  assert.equal(err.message, "GitHub HTTP 403");
  assert.equal(err.status, 403);
  assert.equal(keyFails.fetch.calls.length, 1);

  const putFails = ctx({
    exec: fakeExec(ghTokenExec),
    fetch: fakeFetch((call) => (call.init.method === "GET" ? providerResponse(call) : { status: 422, body: `bad ${CANARY}` })),
  });
  const putErr = await rejects(githubSink.apply(op({ provider: "github", repo: "acme/web" }), secret(), putFails.context), "github_failed");
  assert.equal(putErr.message, "GitHub HTTP 422");
  assert.ok(!putErr.message.includes(GH_TOKEN));

  const patchFails = ctx({ exec: fakeExec(ghTokenExec), fetch: fakeFetch(() => ({ status: 500 })) });
  const patchErr = await rejects(githubSink.apply(op({ provider: "github", repo: "acme/web" }, false), secret(), patchFails.context), "github_failed");
  assert.equal(patchErr.message, "GitHub HTTP 500");
  assertNoCanary(keyFails);
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
