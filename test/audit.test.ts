import assert from "node:assert/strict";
import { statSync } from "node:fs";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { test } from "node:test";
import { MIRROR_BATCH, createSheetsMirror, signPayload } from "../src/audit/mirror.ts";
import { GENESIS_HASH, openAuditStore } from "../src/audit/store.ts";
import type { AuditEntryInput } from "../src/audit/types.ts";
import { fakeFetch, fakeKeychain, tempDir } from "./helpers.ts";

const entry = (variableName = "API_KEY"): AuditEntryInput => ({
  ts: "2026-11-04T12:00:00.000Z",
  actorHuman: "tester",
  actorAgent: "pi:s1",
  project: "web",
  provider: "vercel",
  target: "vercel-prod",
  environment: "production",
  variableName,
  action: "set",
  sensitive: true,
  sourceKind: "op",
  result: "applied",
  providerVersion: "env_1",
  errorCode: "",
});

function freshStore() {
  const path = join(tempDir(), "state", "audit.db");
  return { path, store: openAuditStore(path) };
}

test("records are hash-chained from the genesis hash and verify", () => {
  const { store } = freshStore();
  const a = store.append(entry("A"));
  const b = store.append(entry("B"));
  assert.equal(a.prevHash, GENESIS_HASH);
  assert.equal(b.prevHash, a.hash);
  assert.notEqual(a.hash, b.hash);
  assert.deepEqual(store.verify(), { ok: true, count: 2 });
  assert.deepEqual(store.list().map((r) => r.variableName), ["B", "A"]);
  store.close();
});

test("the database is private and has no column that could hold a value", () => {
  const { path, store } = freshStore();
  store.append(entry());
  store.close();
  assert.equal(statSync(path).mode & 0o777, 0o600);
  assert.equal(statSync(join(path, "..")).mode & 0o777, 0o700);
  const db = new DatabaseSync(path);
  const columns = (db.prepare("PRAGMA table_info(audit)").all() as Array<{ name: string }>).map((c) => c.name);
  db.close();
  assert.ok(columns.every((c) => !/value|secret|plain|token/.test(c.replace("provider_version", ""))), columns.join(","));
});

test("deletes and updates are refused; only mirrored_at can change", () => {
  const { path, store } = freshStore();
  const record = store.append(entry());
  const db = new DatabaseSync(path);
  assert.throws(() => db.exec("DELETE FROM audit"), /audit log is append-only/);
  assert.throws(() => db.exec("UPDATE audit SET variable_name = 'X'"), /audit log is append-only/);
  db.close();
  store.markMirrored([record.auditId], "2026-11-04T12:01:00.000Z");
  assert.equal(store.list()[0]!.mirroredAt, "2026-11-04T12:01:00.000Z");
  assert.equal(store.pendingMirror(10).length, 0);
  assert.equal(store.verify().ok, true);
  store.close();
});

test("tampering that bypasses the triggers is detected by verify", () => {
  const { path, store } = freshStore();
  store.append(entry("A"));
  const b = store.append(entry("B"));
  store.append(entry("C"));
  const db = new DatabaseSync(path);
  db.exec("DROP TRIGGER audit_no_update");
  db.prepare("UPDATE audit SET variable_name = 'EVIL' WHERE audit_id = ?").run(b.auditId);
  db.close();
  assert.deepEqual(store.verify(), { ok: false, count: 1, brokenAt: b.auditId });
  store.close();
});

function mirrorWith(fetch: typeof globalThis.fetch, opts: { url?: string; key?: string } = {}) {
  const { keychain } = fakeKeychain(opts.key ? { "zks/sheets-hmac": opts.key } : {});
  return createSheetsMirror({
    fetch,
    keychain,
    readConfig: async () => (opts.url ? { sheets: { webhookUrl: opts.url } } : {}),
    now: () => new Date("2026-11-04T12:00:00.000Z"),
  });
}

const URL = "https://script.google.com/macros/s/abc/exec";

test("mirror: not configured leaves records pending", async () => {
  const { store } = freshStore();
  store.append(entry());
  const f = fakeFetch();
  assert.deepEqual(await mirrorWith(f.fetch).sync(store), { configured: false, pushed: 0, pending: 1 });
  assert.equal(f.calls.length, 0);
  store.close();
});

test("mirror: a missing HMAC key reports the fix", async () => {
  const { store } = freshStore();
  store.append(entry());
  assert.deepEqual(await mirrorWith(fakeFetch().fetch, { url: URL }).sync(store), {
    configured: true,
    pushed: 0,
    pending: 1,
    error: "missing sheets-hmac token; run zks auth set sheets-hmac",
  });
  store.close();
});

test("mirror: signed batches mark accepted records as mirrored", async () => {
  const { store } = freshStore();
  for (let i = 0; i < MIRROR_BATCH + 5; i++) store.append(entry(`V${i}`));
  const f = fakeFetch((call) => {
    const { payload } = JSON.parse(call.body) as { payload: string };
    return { body: { ok: true, accepted: (JSON.parse(payload).records as Array<{ auditId: string }>).map((r) => r.auditId) } };
  });

  const result = await mirrorWith(f.fetch, { url: URL, key: "hmac-key-1" }).sync(store);

  assert.deepEqual(result, { configured: true, pushed: MIRROR_BATCH + 5, pending: 0 });
  assert.equal(f.calls.length, 2);
  const first = JSON.parse(f.calls[0]!.body) as { payload: string; signature: string };
  assert.equal(first.signature, signPayload("hmac-key-1", first.payload));
  assert.equal(JSON.parse(first.payload).records.length, MIRROR_BATCH);
  assert.ok(!f.calls[0]!.body.includes("hmac-key-1"));
  store.close();
});

test("mirror: an unreachable webhook keeps records pending and never throws", async () => {
  const { store } = freshStore();
  store.append(entry());
  const failing = (async () => {
    throw new Error("offline");
  }) as typeof fetch;
  assert.deepEqual(await mirrorWith(failing, { url: URL, key: "k" }).sync(store), {
    configured: true,
    pushed: 0,
    pending: 1,
    error: "mirror unreachable",
  });
  store.close();
});
