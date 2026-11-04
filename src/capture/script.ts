/** How long the script waits for the element (and, for read, for it to hold a value). */
export const CAPTURE_WAIT_MS = 15_000;
/** The only line of ego-browser output zks reads. */
export const CAPTURE_MARKER = "ZKS_RESULT ";

export const CAPTURE_ERROR_CODES = ["origin_mismatch", "not_found", "keychain_failed", "browser_failed"] as const;
export type CaptureErrorCode = (typeof CAPTURE_ERROR_CODES)[number];
export type CaptureOutcome = { ok: true; length: number } | { ok: false; code: CaptureErrorCode };

const MAX_LENGTH = 100_000;

export interface CaptureScriptSpec {
  /** read: take the element's value into the Keychain item; fill: put the Keychain item into the element. */
  mode: "read" | "fill";
  space: number;
  page: string;
  selector: string;
  /** read only: clicked first, inside the script, so the agent never sees the revealed value. */
  click: string | null;
  origin: string | null;
  service: string;
  account: string;
  waitMs: number;
}

/**
 * The body runs inside `ego-browser nodejs`. It never prints anything but the one marker line,
 * never prints an error message (it could quote a value) and moves the value only through
 * /usr/bin/security: on stdin as hex for a write, on spawnSync stdout (kept in memory) for a read.
 */
const BODY = `
const { spawnSync } = await import("node:child_process");
const { Buffer } = await import("node:buffer");
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function originMatches(page) {
  if (spec.origin === null) return true;
  try {
    return new URL(await page.url()).origin === spec.origin;
  } catch {
    return false;
  }
}

async function waitForElement(page) {
  try {
    await page.waitForSelector(spec.selector, { state: "attached", timeout: spec.waitMs });
    return true;
  } catch {
    return false;
  }
}

async function hasValue(page) {
  return page.evaluate((selector) => {
    const nodes = document.querySelectorAll(selector);
    if (nodes.length !== 1) return false;
    const node = nodes[0];
    const text = node instanceof HTMLInputElement || node instanceof HTMLTextAreaElement ? node.value : (node.textContent || "").trim();
    return text.length > 0;
  }, spec.selector);
}

async function read(page) {
  if (!(await originMatches(page))) return { ok: false, code: "origin_mismatch" };
  if (spec.click !== null) await page.click(spec.click, { timeout: spec.waitMs });
  if (!(await waitForElement(page))) return { ok: false, code: "not_found" };
  const deadline = Date.now() + spec.waitMs;
  while (!(await hasValue(page))) {
    if (Date.now() >= deadline) return { ok: false, code: "not_found" };
    await sleep(200);
  }
  if (!(await originMatches(page))) return { ok: false, code: "origin_mismatch" };
  let value = await page.evaluate((selector) => {
    const nodes = document.querySelectorAll(selector);
    if (nodes.length !== 1) return null;
    const node = nodes[0];
    if (node instanceof HTMLInputElement || node instanceof HTMLTextAreaElement) {
      const taken = node.value;
      node.value = "";
      return taken;
    }
    const taken = (node.textContent || "").trim();
    node.textContent = "[captured by zks]";
    return taken;
  }, spec.selector);
  if (typeof value !== "string" || value.length === 0) return { ok: false, code: "not_found" };
  const length = value.length;
  const command = Buffer.from(
    "add-generic-password -U -s " + spec.service + " -a " + spec.account + " -X " + Buffer.from(value, "utf8").toString("hex") + "\\n",
    "utf8",
  );
  value = null;
  const stored = spawnSync("/usr/bin/security", ["-i"], { input: command, timeout: 15000 });
  command.fill(0);
  if (stored.stdout) stored.stdout.fill(0);
  if (stored.status !== 0 || (stored.stderr && stored.stderr.length > 0)) return { ok: false, code: "keychain_failed" };
  try {
    await page.goto("about:blank");
  } catch {}
  return { ok: true, length };
}

async function fill(page) {
  if (!(await originMatches(page))) return { ok: false, code: "origin_mismatch" };
  if (!(await waitForElement(page))) return { ok: false, code: "not_found" };
  const found = spawnSync("/usr/bin/security", ["find-generic-password", "-s", spec.service, "-a", spec.account, "-w"], { timeout: 15000 });
  if (found.status === 44) return { ok: false, code: "not_found" };
  if (found.status !== 0 || !found.stdout) return { ok: false, code: "keychain_failed" };
  const bytes = found.stdout;
  const end = bytes.length > 0 && bytes[bytes.length - 1] === 10 ? bytes.length - 1 : bytes.length;
  let value = bytes.subarray(0, end).toString("utf8");
  bytes.fill(0);
  if (value.length === 0) return { ok: false, code: "not_found" };
  const length = value.length;
  try {
    await page.fill(spec.selector, value);
  } finally {
    value = null;
  }
  return { ok: true, length };
}

let result;
try {
  const task = await taskSpace(spec.space);
  const page = task.page(spec.page);
  result = spec.mode === "read" ? await read(page) : await fill(page);
} catch {
  result = { ok: false, code: "browser_failed" };
}
console.log("ZKS_RESULT " + JSON.stringify(result));
`;

/** The script zks pipes to `ego-browser nodejs`. Every input enters it only through JSON.stringify. */
export function buildCaptureScript(spec: CaptureScriptSpec): string {
  const embedded = {
    mode: spec.mode,
    space: spec.space,
    page: spec.page,
    selector: spec.selector,
    click: spec.click,
    origin: spec.origin,
    service: spec.service,
    account: spec.account,
    waitMs: spec.waitMs,
  };
  return `// zks capture script (generated). Prints exactly one line: ZKS_RESULT <metadata json>.\nconst spec = ${JSON.stringify(embedded)};\n${BODY}`;
}

const FAILED: CaptureOutcome = { ok: false, code: "browser_failed" };

/** Reads the one marker line of ego-browser output; anything else, or more than one marker, is browser_failed. */
export function parseCaptureOutput(text: string): CaptureOutcome {
  const markers = text.split(/\r?\n/).filter((line) => line.startsWith(CAPTURE_MARKER));
  if (markers.length !== 1) return FAILED;
  let parsed: unknown;
  try {
    parsed = JSON.parse((markers[0] as string).slice(CAPTURE_MARKER.length));
  } catch {
    return FAILED;
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) return FAILED;
  const result = parsed as Record<string, unknown>;
  const keys = Object.keys(result).sort().join(",");
  if (result.ok === true && keys === "length,ok") {
    const length = result.length;
    return typeof length === "number" && Number.isInteger(length) && length > 0 && length <= MAX_LENGTH ? { ok: true, length } : FAILED;
  }
  if (result.ok === false && keys === "code,ok" && (CAPTURE_ERROR_CODES as readonly unknown[]).includes(result.code)) {
    return { ok: false, code: result.code as CaptureErrorCode };
  }
  return FAILED;
}
