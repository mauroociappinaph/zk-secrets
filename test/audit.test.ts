import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdirSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
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

test("S4: an audit DB created before the approval column still verifies and keeps chaining", () => {
  const path = join(tempDir(), "state", "audit.db");
  mkdirSync(dirname(path), { recursive: true });
  const columns = [
    "audit_id", "ts", "actor_human", "actor_agent", "project", "provider", "target", "environment", "variable_name",
    "action", "sensitive", "source_kind", "result", "provider_version", "error_code", "prev_hash", "hash", "mirrored_at",
  ];
  const old = new DatabaseSync(path);
  old.exec(`CREATE TABLE audit (seq INTEGER PRIMARY KEY AUTOINCREMENT, ${columns.map((c) => `${c} ${c === "sensitive" ? "INTEGER" : "TEXT"} NOT NULL`).join(", ")});
CREATE UNIQUE INDEX audit_id_idx ON audit(audit_id);
CREATE TRIGGER audit_no_delete BEFORE DELETE ON audit BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
CREATE TRIGGER audit_no_update BEFORE UPDATE ON audit WHEN ${columns.filter((c) => c !== "mirrored_at").map((c) => `NEW.${c} IS NOT OLD.${c}`).concat("NEW.seq IS NOT OLD.seq").join(" OR ")}
BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;`);
  // Records hashed exactly as the previous release did: sha256(prev + "\n" + sorted-key JSON).
  let prev = GENESIS_HASH;
  for (const [i, name] of ["OLD_A", "OLD_B"].entries()) {
    const { ...fields } = entry(name);
    const record: Record<string, unknown> = { ...fields, auditId: `01OLDRECORD00000000000000${i}`, prevHash: prev };
    const sorted = Object.fromEntries(Object.keys(record).sort().map((k) => [k, record[k]]));
    const hash = createHash("sha256").update(`${prev}\n${JSON.stringify(sorted)}`).digest("hex");
    const row = { ...record, hash, mirroredAt: "" } as Record<string, unknown>;
    const values = [row.auditId, row.ts, row.actorHuman, row.actorAgent, row.project, row.provider, row.target, row.environment,
      row.variableName, row.action, row.sensitive ? 1 : 0, row.sourceKind, row.result, row.providerVersion, row.errorCode,
      row.prevHash, row.hash, row.mirroredAt] as Array<string | number>;
    old.prepare(`INSERT INTO audit (${columns.join(", ")}) VALUES (${columns.map(() => "?").join(", ")})`).run(...values);
    prev = hash;
  }
  old.close();

  const store = openAuditStore(path);
  assert.deepEqual(store.verify(), { ok: true, count: 2 });
  const added = store.append({ ...entry("NEW_C"), approval: "trusted" });
  assert.equal(added.prevHash, prev);
  assert.deepEqual(store.verify(), { ok: true, count: 3 });
  assert.deepEqual(store.list().map((r) => [r.variableName, r.approval]), [["NEW_C", "trusted"], ["OLD_B", ""], ["OLD_A", ""]]);
  store.close();

  const db = new DatabaseSync(path);
  assert.throws(() => db.exec("UPDATE audit SET approval = 'dialog'"), /audit log is append-only/);
  db.close();
  const reopened = openAuditStore(path);
  assert.deepEqual(reopened.verify(), { ok: true, count: 3 });
  reopened.close();
});

test("S4: the approval mode is part of the hash", () => {
  const { path, store } = freshStore();
  const record = store.append({ ...entry(), approval: "dialog" });
  assert.equal(store.list()[0]!.approval, "dialog");
  store.close();
  const db = new DatabaseSync(path);
  db.exec("DROP TRIGGER audit_no_update");
  db.exec("DROP TRIGGER IF EXISTS audit_no_update_approval");
  db.prepare("UPDATE audit SET approval = 'trusted' WHERE audit_id = ?").run(record.auditId);
  db.close();
  const reopened = openAuditStore(path);
  assert.deepEqual(reopened.verify(), { ok: false, count: 0, brokenAt: record.auditId });
  reopened.close();
});

const captureEntry = (over: Partial<AuditEntryInput> = {}): AuditEntryInput => ({
  ...entry("pw"),
  project: "app",
  provider: "keychain",
  target: "app/pw",
  environment: "https://a.example",
  action: "capture",
  sourceKind: "capture-generate",
  providerVersion: "",
  ...over,
});

test("S11: lastCaptureOrigin is the origin of the latest applied capture-read or capture-generate of that item", () => {
  const { store } = freshStore();
  assert.equal(store.lastCaptureOrigin("app/pw"), null);
  store.append(captureEntry({ environment: "https://a.example" }));
  assert.equal(store.lastCaptureOrigin("app/pw"), "https://a.example");
  store.append(captureEntry({ environment: "https://b.example", sourceKind: "capture-read" }));
  assert.equal(store.lastCaptureOrigin("app/pw"), "https://b.example");
  // Neither a fill of the stored item, nor a failed or denied capture, nor a set, nor another item moves it.
  store.append(captureEntry({ environment: "https://evil.example", sourceKind: "capture-from" }));
  store.append(captureEntry({ environment: "https://evil.example", result: "failed" }));
  store.append(captureEntry({ environment: "https://evil.example", result: "denied" }));
  store.append(captureEntry({ environment: "https://evil.example", action: "set" }));
  store.append(captureEntry({ environment: "https://evil.example", target: "app/other" }));
  assert.equal(store.lastCaptureOrigin("app/pw"), "https://b.example");
  assert.equal(store.lastCaptureOrigin("app/other"), "https://evil.example");
  assert.equal(store.lastCaptureOrigin("APP/pw"), null);
  // A read without --origin recorded "": known capture, unknown origin.
  store.append(captureEntry({ environment: "", sourceKind: "capture-read" }));
  assert.equal(store.lastCaptureOrigin("app/pw"), "");
  store.close();
});

test("S11: lastCaptureOrigin works on a database created before the approval column", () => {
  const path = join(tempDir(), "state", "audit.db");
  mkdirSync(dirname(path), { recursive: true });
  const columns = [
    "audit_id", "ts", "actor_human", "actor_agent", "project", "provider", "target", "environment", "variable_name",
    "action", "sensitive", "source_kind", "result", "provider_version", "error_code", "prev_hash", "hash", "mirrored_at",
  ];
  const old = new DatabaseSync(path);
  old.exec(`CREATE TABLE audit (seq INTEGER PRIMARY KEY AUTOINCREMENT, ${columns.map((c) => `${c} ${c === "sensitive" ? "INTEGER" : "TEXT"} NOT NULL`).join(", ")});`);
  const e = captureEntry({ environment: "https://old.example" });
  old.prepare(`INSERT INTO audit (${columns.join(", ")}) VALUES (${columns.map(() => "?").join(", ")})`).run(
    "01OLDCAPTURE0000000000000", e.ts, e.actorHuman, e.actorAgent, e.project, e.provider, e.target, e.environment, e.variableName,
    e.action, 1, e.sourceKind, e.result, e.providerVersion, e.errorCode, GENESIS_HASH, "f".repeat(64), "",
  );
  old.close();
  const store = openAuditStore(path);
  assert.equal(store.lastCaptureOrigin("app/pw"), "https://old.example");
  store.append(captureEntry({ environment: "https://new.example", approval: "dialog" }));
  assert.equal(store.lastCaptureOrigin("app/pw"), "https://new.example");
  store.close();
});
