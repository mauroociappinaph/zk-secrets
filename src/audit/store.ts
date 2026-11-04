import { createHash, randomBytes } from "node:crypto";
import { chmodSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { DatabaseSync } from "node:sqlite";
import type { AuditEntryInput, AuditRecord, AuditStore, AuditVerification } from "./types.ts";

export const GENESIS_HASH = "0".repeat(64);
const CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

const COLUMNS: Array<[keyof AuditRecord, string]> = [
  ["auditId", "audit_id"],
  ["ts", "ts"],
  ["actorHuman", "actor_human"],
  ["actorAgent", "actor_agent"],
  ["project", "project"],
  ["provider", "provider"],
  ["target", "target"],
  ["environment", "environment"],
  ["variableName", "variable_name"],
  ["action", "action"],
  ["sensitive", "sensitive"],
  ["sourceKind", "source_kind"],
  ["result", "result"],
  ["providerVersion", "provider_version"],
  ["errorCode", "error_code"],
  ["prevHash", "prev_hash"],
  ["hash", "hash"],
  ["mirroredAt", "mirrored_at"],
];

const SCHEMA = `
CREATE TABLE IF NOT EXISTS audit (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  ${COLUMNS.map(([, col]) => `${col} ${col === "sensitive" ? "INTEGER" : "TEXT"} NOT NULL`).join(",\n  ")}
);
CREATE UNIQUE INDEX IF NOT EXISTS audit_id_idx ON audit(audit_id);
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit
BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit
WHEN ${COLUMNS.filter(([, col]) => col !== "mirrored_at")
  .map(([, col]) => `NEW.${col} IS NOT OLD.${col}`)
  .concat("NEW.seq IS NOT OLD.seq")
  .join(" OR ")}
BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
`;

/** JSON with sorted keys, so the hash does not depend on property order. */
export function canonicalJson(value: Record<string, unknown>): string {
  const sorted: Record<string, unknown> = {};
  for (const key of Object.keys(value).sort()) sorted[key] = value[key];
  return JSON.stringify(sorted);
}

export function computeHash(prevHash: string, record: Omit<AuditRecord, "hash" | "mirroredAt">): string {
  return createHash("sha256").update(`${prevHash}\n${canonicalJson({ ...record })}`).digest("hex");
}

export function newAuditId(now = Date.now()): string {
  let time = "";
  let t = now;
  for (let i = 0; i < 10; i++) {
    time = CROCKFORD[t % 32] + time;
    t = Math.floor(t / 32);
  }
  const random = [...randomBytes(16)].map((b) => CROCKFORD[b % 32]).join("");
  return time + random;
}

type Row = Record<string, string | number | bigint | null>;

function fromRow(row: Row): AuditRecord {
  const record: Record<string, unknown> = {};
  for (const [field, col] of COLUMNS) {
    record[field] = col === "sensitive" ? Number(row[col]) === 1 : String(row[col] ?? "");
  }
  return record as unknown as AuditRecord;
}

function withoutChainFields(record: AuditRecord): Omit<AuditRecord, "hash" | "mirroredAt"> {
  const { hash: _hash, mirroredAt: _mirroredAt, ...rest } = record;
  return rest;
}

export function openAuditStore(dbPath: string): AuditStore {
  mkdirSync(dirname(dbPath), { recursive: true, mode: 0o700 });
  const db = new DatabaseSync(dbPath);
  chmodSync(dbPath, 0o600);
  db.exec("PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;");
  db.exec(SCHEMA);

  const insert = db.prepare(
    `INSERT INTO audit (${COLUMNS.map(([, c]) => c).join(", ")}) VALUES (${COLUMNS.map(() => "?").join(", ")})`,
  );
  const lastHash = db.prepare("SELECT hash FROM audit ORDER BY seq DESC LIMIT 1");

  return {
    append(entry: AuditEntryInput): AuditRecord {
      db.exec("BEGIN IMMEDIATE");
      try {
        const prevHash = String((lastHash.get() as Row | undefined)?.hash ?? GENESIS_HASH);
        const base = { ...entry, auditId: newAuditId(), prevHash };
        const record: AuditRecord = { ...base, hash: computeHash(prevHash, base), mirroredAt: "" };
        insert.run(
          ...COLUMNS.map(([field]) => {
            const value = record[field];
            return typeof value === "boolean" ? (value ? 1 : 0) : value;
          }),
        );
        db.exec("COMMIT");
        return record;
      } catch (error) {
        db.exec("ROLLBACK");
        throw error;
      }
    },
    list(options = {}) {
      const limit = options.limit ?? 50;
      const rows = options.project
        ? db.prepare("SELECT * FROM audit WHERE project = ? ORDER BY seq DESC LIMIT ?").all(options.project, limit)
        : db.prepare("SELECT * FROM audit ORDER BY seq DESC LIMIT ?").all(limit);
      return (rows as Row[]).map(fromRow);
    },
    verify(): AuditVerification {
      let prev = GENESIS_HASH;
      let count = 0;
      for (const row of db.prepare("SELECT * FROM audit ORDER BY seq ASC").iterate() as Iterable<Row>) {
        const record = fromRow(row);
        if (record.prevHash !== prev || computeHash(prev, withoutChainFields(record)) !== record.hash) {
          return { ok: false, count, brokenAt: record.auditId };
        }
        prev = record.hash;
        count++;
      }
      return { ok: true, count };
    },
    pendingMirror(limit) {
      const rows = db.prepare("SELECT * FROM audit WHERE mirrored_at = '' ORDER BY seq ASC LIMIT ?").all(limit);
      return (rows as Row[]).map(fromRow);
    },
    markMirrored(auditIds, ts) {
      const update = db.prepare("UPDATE audit SET mirrored_at = ? WHERE audit_id = ? AND mirrored_at = ''");
      db.exec("BEGIN IMMEDIATE");
      try {
        for (const id of auditIds) update.run(ts, id);
        db.exec("COMMIT");
      } catch (error) {
        db.exec("ROLLBACK");
        throw error;
      }
    },
    close() {
      db.close();
    },
  };
}
