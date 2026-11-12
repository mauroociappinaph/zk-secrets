import assert from "node:assert/strict";
import { createPrivateKey, createPublicKey, randomBytes as cryptoRandomBytes } from "node:crypto";
import { test } from "node:test";
import { run } from "../src/run.ts";
import { createResolver, resolveValue } from "../src/sources/resolve.ts";
import { CANARY, auditBytes, fakeHuman, fakeKeychain, fakeExec, harness, parse, TEST_TOOLS } from "./helpers.ts";

const tokens = { "zks/vercel": "tok-vercel-1" };
const targets = {
  v1: { provider: "vercel", projectId: "prj_1", environments: ["production"] },
  v2: { provider: "vercel", projectId: "prj_2", environments: ["production"] },
};
const policyWith = (variables: Record<string, unknown>) => ({ version: 1, project: "acme", targets, variables });

/** The value each Vercel write carried, keyed by "<projectId>/<NAME>". */
function written(h: ReturnType<typeof harness>): Map<string, { value: string; type: string }> {
  const out = new Map<string, { value: string; type: string }>();
  for (const call of h.fetch.calls) {
    const project = /\/projects\/([^/]+)\/env/.exec(call.url)?.[1];
    const body = JSON.parse(call.body) as { key: string; value: string; type: string };
    out.set(`${project}/${body.key}`, { value: body.value, type: body.type });
  }
  return out;
}

async function issuesOf(policy: unknown): Promise<string[]> {
  const h = harness({ policy });
  const out = await run(["validate"], h.deps);
  assert.equal(out.exitCode, 2, out.stdout);
  return parse(out.stdout).error.issues as string[];
}

async function applyOk(h: ReturnType<typeof harness>, argv: string[] = ["apply"]) {
  const out = await run(argv, h.deps);
  assert.equal(out.exitCode, 0, out.stdout);
  return out;
}

async function assertNotLeaked(h: ReturnType<typeof harness>, stdout: string, values: string[]) {
  const audit = await auditBytes(h.auditDb);
  for (const v of values) {
    for (const form of [v, encodeURIComponent(v), JSON.stringify(v).slice(1, -1)]) {
      assert.ok(!stdout.includes(form), "stdout leaked a value");
      assert.ok(!audit.includes(form), "audit leaked a value");
    }
  }
}

const sourceDeps = () => ({
  exec: fakeExec().exec,
  tools: TEST_TOOLS,
  keychain: fakeKeychain().keychain,
  human: fakeHuman().human,
  cwd: "/w",
  randomBytes: cryptoRandomBytes,
});

// S5 — formatted generators

test("S5: generate without format keeps the random bytes/encoding behaviour", async () => {
  const h = harness({ policy: policyWith({ K: { sensitive: true, source: { kind: "generate", bytes: 16, encoding: "hex" }, targets: ["v1"] } }), keychain: tokens });
  await applyOk(h);
  assert.equal(written(h).get("prj_1/K")?.value, "07".repeat(16));
  const plan = parse((await run(["plan"], h.deps)).stdout);
  assert.equal(plan.operations[0].source, "NEW random value (16 bytes) - rotates on every apply");
});

test("S5: format random is the default bytes/encoding generator", async () => {
  const h = harness({ policy: policyWith({ K: { sensitive: true, source: { kind: "generate", format: "random", bytes: 16 }, targets: ["v1"] } }), keychain: tokens });
  await applyOk(h);
  assert.equal(written(h).get("prj_1/K")?.value, Buffer.alloc(16, 7).toString("base64url"));
});

test("S5: uuid is a v4 UUID built from deps.randomBytes", async () => {
  const h = harness({ policy: policyWith({ ID: { sensitive: true, source: { kind: "generate", format: "uuid" }, targets: ["v1"] } }), keychain: tokens });
  const out = await applyOk(h);
  const value = written(h).get("prj_1/ID")!.value;
  assert.equal(value, "07070707-0707-4707-8707-070707070707");
  await assertNotLeaked(h, out.stdout, [value]);
  assert.equal(parse((await run(["plan"], h.deps)).stdout).operations[0].source, "generate uuid - NEW value on every apply");
});

test("S5: jwt-secret is 64 random bytes in base64url", async () => {
  const h = harness({ policy: policyWith({ JWT: { sensitive: true, source: { kind: "generate", format: "jwt-secret" }, targets: ["v1"] } }), keychain: tokens });
  const out = await applyOk(h);
  const value = written(h).get("prj_1/JWT")!.value;
  assert.equal(value, Buffer.alloc(64, 7).toString("base64url"));
  await assertNotLeaked(h, out.stdout, [value]);
});

test("S5: password defaults to 32 characters with every class present", async () => {
  for (let i = 0; i < 200; i++) {
    const v = await resolveValue("P", { sensitive: true, targets: [], source: { kind: "generate", format: "password" } }, sourceDeps());
    const pw = v.reveal();
    v.dispose();
    assert.equal(pw.length, 32);
    assert.match(pw, /[a-z]/);
    assert.match(pw, /[A-Z]/);
    assert.match(pw, /[0-9]/);
    assert.match(pw, /[^A-Za-z0-9]/);
    assert.match(pw, /^[\x21-\x7e]+$/);
    assert.ok(!/["'`\\]/.test(pw), "symbols exclude quotes and backslash");
  }
});

test("S5: password honours length and disabled classes", async () => {
  for (let i = 0; i < 100; i++) {
    const v = await resolveValue(
      "P",
      { sensitive: true, targets: [], source: { kind: "generate", format: "password", length: 12, symbols: false, upper: false } },
      sourceDeps(),
    );
    const pw = v.reveal();
    assert.equal(pw.length, 12);
    assert.match(pw, /^[a-z0-9]+$/);
    assert.match(pw, /[a-z]/);
    assert.match(pw, /[0-9]/);
  }
});

test("S5: password selection rejects biased bytes instead of reducing them modulo", async () => {
  // 250..255 would map to digits 0..5 under a modulo; rejection sampling must skip them all.
  let served = 0;
  const randomBytes = (n: number) => {
    const out = Buffer.alloc(n);
    for (let i = 0; i < n; i++, served++) out[i] = served < 60 ? 250 + (served % 6) : 0;
    return out;
  };
  const v = await resolveValue(
    "P",
    { sensitive: true, targets: [], source: { kind: "generate", format: "password", length: 12, lower: false, upper: false, symbols: false } },
    { ...sourceDeps(), randomBytes },
  );
  assert.equal(v.reveal(), "000000000000");
  assert.ok(served > 60);
});

test("S5: password plan text shows the length", async () => {
  const h = harness({ policy: policyWith({ P: { sensitive: true, source: { kind: "generate", format: "password" }, targets: ["v1"] } }) });
  assert.equal(parse((await run(["plan"], h.deps)).stdout).operations[0].source, "generate password(32) - NEW value on every apply");
});

test("S5: rsa-private-key is a PKCS8 PEM with the requested bits; ed25519 likewise", async () => {
  const h = harness({
    policy: policyWith({
      RSA: { sensitive: true, source: { kind: "generate", format: "rsa-private-key", bits: 2048 }, targets: ["v1"] },
      ED: { sensitive: true, source: { kind: "generate", format: "ed25519-private-key" }, targets: ["v1"] },
    }),
    keychain: tokens,
  });
  const out = await applyOk(h);
  const rsa = written(h).get("prj_1/RSA")!.value;
  const ed = written(h).get("prj_1/ED")!.value;
  assert.match(rsa, /^-----BEGIN PRIVATE KEY-----\n/);
  assert.match(ed, /^-----BEGIN PRIVATE KEY-----\n/);
  const rsaKey = createPrivateKey(rsa);
  assert.equal(rsaKey.asymmetricKeyType, "rsa");
  assert.equal(rsaKey.asymmetricKeyDetails?.modulusLength, 2048);
  assert.equal(createPrivateKey(ed).asymmetricKeyType, "ed25519");
  await assertNotLeaked(h, out.stdout, [rsa, ed]);
  const plan = parse((await run(["plan"], h.deps)).stdout);
  assert.deepEqual(plan.operations.map((o: { source: string }) => o.source), [
    "generate rsa-private-key(2048) - NEW value on every apply",
    "generate ed25519-private-key - NEW value on every apply",
  ]);
});

test("S5: rsa-private-key defaults to 3072 bits", async () => {
  const v = await resolveValue("R", { sensitive: true, targets: [], source: { kind: "generate", format: "rsa-private-key" } }, sourceDeps());
  assert.equal(createPrivateKey(v.reveal()).asymmetricKeyDetails?.modulusLength, 3072);
});

test("S5: invalid formats and options are invalid_policy issues", async () => {
  const gen = (source: Record<string, unknown>) => ({ sensitive: true, source: { kind: "generate", ...source }, targets: ["v1"] });
  assert.deepEqual(
    await issuesOf(
      policyWith({
        A: gen({ format: "nope" }),
        B: gen({ format: "uuid", length: 20 }),
        C: gen({ format: "password", length: 11 }),
        D: gen({ format: "password", length: 129, bits: 2048 }),
        E: gen({ format: "password", lower: false, upper: false, digits: false, symbols: false }),
        F: gen({ format: "password", digits: "yes" }),
        G: gen({ format: "rsa-private-key", bits: 1024 }),
        H: gen({ format: "ed25519-private-key", bytes: 32 }),
        I: gen({ length: 20 }),
        J: gen({ format: "jwt-secret", encoding: "hex" }),
      }),
    ),
    [
      "variables.A.source.format: must be one of random, uuid, jwt-secret, password, rsa-private-key, ed25519-private-key",
      'variables.B.source.length: is not valid for format "uuid"',
      "variables.C.source.length: must be an integer between 12 and 128",
      'variables.D.source.bits: is not valid for format "password"',
      "variables.D.source.length: must be an integer between 12 and 128",
      "variables.E.source: password needs at least one of lower, upper, digits, symbols",
      "variables.F.source.digits: must be true or false",
      "variables.G.source.bits: must be 2048, 3072 or 4096",
      'variables.H.source.bytes: is not valid for format "ed25519-private-key"',
      'variables.I.source.length: is not valid for format "random"',
      'variables.J.source.encoding: is not valid for format "jwt-secret"',
    ],
  );
});

// S5 — public keys

test("S5: public-key writes the SPKI PEM of the private key generated in the same apply, as plain", async () => {
  const h = harness({
    policy: policyWith({
      SIGNING_KEY_PUB: { sensitive: false, source: { kind: "public-key", of: "SIGNING_KEY" }, targets: ["v2"] },
      SIGNING_KEY: { sensitive: true, source: { kind: "generate", format: "ed25519-private-key" }, targets: ["v1"] },
    }),
    keychain: tokens,
  });
  const out = await applyOk(h);
  const priv = written(h).get("prj_1/SIGNING_KEY")!;
  const pub = written(h).get("prj_2/SIGNING_KEY_PUB")!;
  assert.equal(priv.type, "sensitive");
  assert.equal(pub.type, "plain");
  assert.match(pub.value, /^-----BEGIN PUBLIC KEY-----\n/);
  assert.equal(pub.value, createPublicKey(priv.value).export({ type: "spki", format: "pem" }));
  await assertNotLeaked(h, out.stdout, [priv.value]);
  const plan = parse((await run(["plan"], h.deps)).stdout);
  assert.equal(plan.operations[0].source, "public-key of SIGNING_KEY");
  assert.equal(plan.operations[0].sensitive, false);
});

test("S5: public-key of an RSA key matches it", async () => {
  const h = harness({
    policy: policyWith({
      K: { sensitive: true, source: { kind: "generate", format: "rsa-private-key", bits: 2048 }, targets: ["v1"] },
      K_PUB: { sensitive: false, source: { kind: "public-key", of: "K" }, targets: ["v1"] },
    }),
    keychain: tokens,
  });
  await applyOk(h);
  const pub = createPublicKey(written(h).get("prj_1/K_PUB")!.value);
  assert.equal(pub.asymmetricKeyType, "rsa");
  assert.equal(pub.export({ type: "spki", format: "pem" }), createPublicKey(written(h).get("prj_1/K")!.value).export({ type: "spki", format: "pem" }));
});

test("S5: public-key must reference a generated private key; other sources stay sensitive", async () => {
  assert.deepEqual(
    await issuesOf(
      policyWith({
        A: { sensitive: false, source: { kind: "public-key", of: "NOPE" }, targets: ["v1"] },
        B: { sensitive: false, source: { kind: "public-key", of: "C" }, targets: ["v1"] },
        C: { sensitive: true, source: { kind: "generate", format: "uuid" }, targets: ["v1"] },
        D: { sensitive: false, source: { kind: "public-key" }, targets: ["v1"] },
        E: { sensitive: false, source: { kind: "generate", format: "uuid" }, targets: ["v1"] },
      }),
    ),
    [
      'variables.A.source.of: unknown variable "NOPE"',
      'variables.B.source.of: "C" must use a generate rsa-private-key or ed25519-private-key source',
      "variables.D.source.of: must name another variable",
      "variables.E.sensitive: must be true when a source is used; only literal values can be non-sensitive",
    ],
  );
});

// S6 — templates

const dbVariables = {
  // Declared first on purpose: dependencies resolve before it, not in policy order.
  DATABASE_URL: { sensitive: true, source: { kind: "template", template: "postgres://${DB_USER}:${DB_PASSWORD:url}@${DB_HOST}/app" }, targets: ["v2"] },
  DB_USER: { sensitive: false, value: "app_user", targets: ["v1"] },
  DB_PASSWORD: { sensitive: true, source: { kind: "generate", format: "password" }, targets: ["v1"] },
  DB_HOST: { sensitive: false, value: "db.internal", targets: ["v1"] },
};

test("S6: a template shares the generated password with its dependents, percent-encoded with :url", async () => {
  const h = harness({ policy: policyWith(dbVariables), keychain: tokens });
  h.deps.randomBytes = cryptoRandomBytes;
  const out = await applyOk(h);
  const password = written(h).get("prj_1/DB_PASSWORD")!.value;
  const url = written(h).get("prj_2/DATABASE_URL")!.value;
  assert.equal(url, `postgres://app_user:${encodeURIComponent(password)}@db.internal/app`);
  assert.equal(h.fetch.calls.length, 4);
  await assertNotLeaked(h, out.stdout, [password, url]);
  assert.equal(
    parse((await run(["plan", "--only", "DATABASE_URL,DB_PASSWORD"], h.deps)).stdout).operations[0].source,
    "template(DB_USER, DB_PASSWORD, DB_HOST)",
  );
});

test("S6: a prompt referenced by a template and written itself asks only once", async () => {
  const h = harness({
    policy: policyWith({
      A: { sensitive: true, source: { kind: "template", template: "${B}-${B:url}" }, targets: ["v1"] },
      B: { sensitive: true, source: { kind: "prompt" }, targets: ["v1"] },
    }),
    keychain: tokens,
    prompt: `${CANARY} &x`,
  });
  const out = await applyOk(h);
  assert.deepEqual(h.human.prompts, ["Value for B"]);
  assert.equal(written(h).get("prj_1/A")!.value, `${CANARY} &x-${encodeURIComponent(`${CANARY} &x`)}`);
  await assertNotLeaked(h, out.stdout, [CANARY]);
});

test("S6: a dependency resolves even when only the template is selected", async () => {
  const h = harness({
    policy: policyWith({
      URL: { sensitive: true, source: { kind: "template", template: "x$${NOT}y${SECRET}" }, targets: ["v1"] },
      SECRET: { sensitive: true, source: { kind: "keychain", service: "app", account: "s" }, targets: ["v2"] },
    }),
    keychain: { ...tokens, "app/s": CANARY },
  });
  const out = await applyOk(h, ["apply", "--only", "URL"]);
  assert.equal(h.fetch.calls.length, 1);
  assert.equal(written(h).get("prj_1/URL")!.value, `x\${NOT}y${CANARY}`);
  await assertNotLeaked(h, out.stdout, [CANARY]);
});

test("S6: a selection that would generate a dependency without writing it is refused", async () => {
  const h = harness({ policy: policyWith(dbVariables), keychain: tokens });
  const out = await run(["apply", "--only", "DATABASE_URL"], h.deps);
  assert.equal(out.exitCode, 2);
  assert.deepEqual(parse(out.stdout).error.issues, [
    "selection: DATABASE_URL uses DB_PASSWORD, a generated value this selection does not write; select it too",
  ]);
  assert.equal(h.human.approvals.length + h.fetch.calls.length, 0);
});

test("S6: a failed dependency fails the template without writing it", async () => {
  const h = harness({
    policy: policyWith({
      URL: { sensitive: true, source: { kind: "template", template: "x${SECRET}" }, targets: ["v1"] },
      SECRET: { sensitive: true, source: { kind: "keychain", service: "app", account: "missing" }, targets: ["v2"] },
    }),
    keychain: tokens,
  });
  const out = await run(["apply"], h.deps);
  assert.equal(out.exitCode, 1);
  const results = parse(out.stdout).results as { name: string; error: { code: string } }[];
  assert.deepEqual(results.map((r) => [r.name, r.error.code]), [["URL", "source_missing"], ["SECRET", "source_missing"]]);
  assert.equal(h.fetch.calls.length, 0);
});

test("S6: unknown, self and cyclic references and non-sensitive templates are invalid_policy", async () => {
  const tpl = (template: unknown, sensitive = true) => ({ sensitive, source: { kind: "template", template }, targets: ["v1"] });
  assert.deepEqual(
    await issuesOf(
      policyWith({
        A: tpl("${NOPE}"),
        B: tpl("x${B}"),
        C: tpl("${D}"),
        D: tpl("${E:url}"),
        E: tpl("${C}"),
        F: tpl("${A:base64}"),
        G: tpl("${A"),
        H: tpl("no refs"),
        I: tpl(42),
        J: tpl("${A}", false),
      }),
    ),
    [
      'variables.A.source.template: unknown variable "NOPE"',
      "variables.B.source.template: references itself",
      'variables.F.source.template: unknown modifier "base64" (only :url)',
      "variables.G.source.template: unclosed ${ at position 0; write $${ for a literal ${",
      "variables.H.source.template: must reference at least one variable",
      "variables.I.source.template: must be a string of 1 to 2000 characters",
      "variables.J.sensitive: must be true when a source is used; only literal values can be non-sensitive",
      "variables.C.source.template: reference cycle C -> D -> E -> C",
    ],
  );
});

test("S6: describe and the approval dialog show the template source without values", async () => {
  const h = harness({ policy: policyWith(dbVariables), keychain: tokens });
  await applyOk(h);
  const line = h.human.approvals[0]!.find((l) => l.startsWith("- DATABASE_URL"));
  assert.equal(line, "- DATABASE_URL -> vercel project prj_2 env production [secret; template(DB_USER, DB_PASSWORD, DB_HOST)] (target v2) [NEW destination]");
});

test("S5/S6: the resolver zeroes every value it resolved, dependencies included", async () => {
  const variables = {
    K: { sensitive: true, source: { kind: "generate" as const, format: "ed25519-private-key" as const }, targets: ["v1"] },
    K_PUB: { sensitive: false, source: { kind: "public-key" as const, of: "K" }, targets: ["v1"] },
    T: { sensitive: true, source: { kind: "template" as const, template: "${K_PUB}" }, targets: ["v1"] },
  };
  const seen: string[] = [];
  const resolver = createResolver(variables, sourceDeps(), (name) => seen.push(name));
  const t = await resolver.resolve("T");
  const k = await resolver.resolve("K");
  assert.equal(await resolver.resolve("T"), t);
  assert.deepEqual(seen, ["K", "K_PUB", "T"]);
  resolver.dispose();
  assert.equal(t.disposed, true);
  assert.equal(k.disposed, true);
});
