// Dependency hygiene check, run by install.sh and CI:
//   1. every package.json dependency is an exact version (no ranges, tags or URLs);
//   2. the v3 lockfile root agrees with package.json;
//   3. `npm audit --omit=dev` reports no high or critical vulnerability.
// Prints one JSON summary on stdout. Exit 0 when ok, 1 otherwise. An unreachable registry only
// warns on stderr unless --strict is given. Never reads anything but the two manifest files.
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";

type Manifest = { dependencies?: Record<string, string>; devDependencies?: Record<string, string> };
type Lock = { lockfileVersion?: number; packages?: Record<string, Manifest> };
export type PinIssue =
  | { code: "not_pinned"; name: string; spec: string }
  | { code: "lockfile_mismatch"; name: string; spec: string; locked: string | null }
  | { code: "lockfile_version"; found: number | null; expected: 3 };
export type AuditResult = { status: "ok" | "vulnerable" | "unavailable"; high: number | null; critical: number | null };

const EXACT = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;

export function checkPinned(pkg: Manifest, lock: Lock): PinIssue[] {
  const issues: PinIssue[] = [];
  const version = typeof lock.lockfileVersion === "number" ? lock.lockfileVersion : null;
  if (version !== 3) issues.push({ code: "lockfile_version", found: version, expected: 3 });
  const root = lock.packages?.[""] ?? {};
  for (const field of ["dependencies", "devDependencies"] as const) {
    for (const [name, spec] of Object.entries(pkg[field] ?? {})) {
      if (!EXACT.test(spec)) {
        issues.push({ code: "not_pinned", name, spec });
        continue;
      }
      const locked = root[field]?.[name] ?? null;
      if (version === 3 && locked !== spec) issues.push({ code: "lockfile_mismatch", name, spec, locked });
    }
  }
  return issues;
}

export function evaluateAudit(raw: string): AuditResult & { reason?: string } {
  let report: { error?: { code?: string }; metadata?: { vulnerabilities?: Record<string, number> } };
  try {
    report = JSON.parse(raw);
  } catch {
    return { status: "unavailable", high: null, critical: null, reason: "unparsable output" };
  }
  const counts = report?.metadata?.vulnerabilities;
  if (report?.error || !counts || typeof counts.high !== "number" || typeof counts.critical !== "number") {
    return { status: "unavailable", high: null, critical: null, reason: String(report?.error?.code ?? "no report") };
  }
  const status = counts.high + counts.critical > 0 ? "vulnerable" : "ok";
  return { status, high: counts.high, critical: counts.critical };
}

function main(argv: string[]): number {
  const strict = argv.includes("--strict");
  const pkg = JSON.parse(readFileSync("package.json", "utf8")) as Manifest;
  const lock = JSON.parse(readFileSync("package-lock.json", "utf8")) as Lock;
  const issues = checkPinned(pkg, lock);
  const npm = process.env.ZKS_NPM || "npm";
  const run = spawnSync(npm, ["audit", "--omit=dev", "--json"], { encoding: "utf8", maxBuffer: 32 * 1024 * 1024 });
  const { reason, ...audit } = evaluateAudit(run.stdout ?? "");
  if (audit.status === "unavailable") {
    process.stderr.write(`deps-check: npm audit unavailable (${reason}); rerun online or with --strict to fail\n`);
  }
  const auditOk = audit.status === "ok" || (audit.status === "unavailable" && !strict);
  const ok = issues.length === 0 && auditOk;
  process.stdout.write(`${JSON.stringify({ ok, pinned: { ok: issues.length === 0, issues }, audit })}\n`);
  return ok ? 0 : 1;
}

if (import.meta.main) process.exitCode = main(process.argv.slice(2));
