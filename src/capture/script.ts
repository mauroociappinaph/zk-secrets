/** How long the script waits for the element (and, for read, for it to hold a value). */
export const CAPTURE_WAIT_MS = 15_000;
/** The only line of ego-browser output zks reads. */
export const CAPTURE_MARKER = "ZKS_RESULT ";

/** The only binary the script moves a value through. */
export const SECURITY_PATH = "/usr/bin/security";

/** Page label of the page zks opens in its own isolated space. */
export const ISOLATED_PAGE = "p1"; // ego-browser: a new space starts with managed Page p1

export const CAPTURE_ERROR_CODES = [
  "origin_mismatch",
  "not_found",
  "not_password_field",
  "keychain_failed",
  "browser_failed",
  "isolated_profile_missing",
  "isolated_profile_not_isolated",
  "login_required",
] as const;
export type CaptureErrorCode = (typeof CAPTURE_ERROR_CODES)[number];
export type CaptureOutcome = { ok: true; length: number } | { ok: false; code: CaptureErrorCode };

const MAX_LENGTH = 100_000;

export interface CaptureScriptSpec {
  /** read: take the element's value into the Keychain item; fill: put the Keychain item into the element. */
  mode: "read" | "fill";
  /** The agent's TaskSpace and page; null for an isolated capture. */
  space: number | null;
  page: string | null;
  selector: string;
  /** read only: clicked first, inside the script, so the agent never sees the revealed value. */
  click: string | null;
  /** Required for fill: the script fills nothing when it is null. */
  origin: string | null;
  service: string;
  account: string;
  waitMs: number;
  /**
   * Isolated capture: zks checks the profile with profiles(), creates its own space `name` with
   * it, goes to `url` and always finishes the space with keep: []. Absent for --space/--page.
   */
  isolated?: { profileId: string; url: string; name: string };
}

/**
 * The body runs inside `ego-browser nodejs`. It never prints anything but the one marker line,
 * never prints an error message (it could quote a value) and moves the value only through
 * /usr/bin/security: on stdin as hex for a write, on spawnSync stdout (kept in memory) for a read.
 * After a reveal click the page always navigates to about:blank, so a failure never leaves the
 * token on screen. A fill only sets one password input of the main frame, in one evaluate that
 * re-checks the document origin first.
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

async function blank(page) {
  try {
    await page.goto("about:blank");
  } catch {}
}

async function read(page) {
  if (!(await originMatches(page))) return { ok: false, code: "origin_mismatch" };
  const clicking = spec.click !== null;
  let result = null;
  try {
    if (clicking) await page.click(spec.click, { timeout: spec.waitMs });
    result = await readValue(page);
    return result;
  } finally {
    // Once a reveal click was attempted the token may be on screen, whatever happened next.
    if (clicking || (result !== null && result.ok)) await blank(page);
  }
}

async function readValue(page) {
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
  const stored = spawnSync(SECURITY, ["-i"], { input: command, timeout: 15000 });
  command.fill(0);
  if (stored.stdout) stored.stdout.fill(0);
  if (stored.status !== 0 || (stored.stderr && stored.stderr.length > 0)) return { ok: false, code: "keychain_failed" };
  return { ok: true, length };
}

/** Runs in the page's main frame without the secret: one password input, same origin, cleared and focused. */
function preparePassword({ selector, expected }) {
  if (expected === null || document.location.origin !== expected) return { ok: false, code: "origin_mismatch" };
  const nodes = document.querySelectorAll(selector);
  if (nodes.length !== 1) return { ok: false, code: "not_password_field" };
  const node = nodes[0];
  if (!(node instanceof HTMLInputElement) || node.type !== "password") return { ok: false, code: "not_password_field" };
  Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value").set.call(node, "");
  node.focus();
  return document.activeElement === node ? { ok: true } : { ok: false, code: "not_password_field" };
}

/**
 * Runs right before typing, without the secret: same origin, focus still on that input.
 * document.hasFocus() is not required: an automated tab whose window lacks OS focus reports
 * false, while the browser still types into the page's active element.
 */
function focusStillOnPassword({ selector, expected }) {
  if (document.location.origin !== expected) return { ok: false, code: "not_password_field" };
  const nodes = document.querySelectorAll(selector);
  const node = nodes.length === 1 ? nodes[0] : null;
  if (!(node instanceof HTMLInputElement) || node.type !== "password" || document.activeElement !== node) {
    return { ok: false, code: "not_password_field" };
  }
  return { ok: true };
}

/** After a failed confirmation: clear whatever received the text and the target input. */
function clearAfterFailure(selector) {
  const clear = (el) => {
    if (el instanceof HTMLInputElement) Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value").set.call(el, "");
    else if (el instanceof HTMLTextAreaElement) Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, "value").set.call(el, "");
    else if (el && el.isContentEditable) el.textContent = "";
  };
  clear(document.activeElement);
  document.querySelectorAll(selector).forEach(clear);
  return true;
}

/** Runs after typing, again without the secret: same origin, same focused password input, expected length. */
function confirmPassword({ selector, expected, length }) {
  if (document.location.origin !== expected) return { ok: false, code: "origin_mismatch" };
  const nodes = document.querySelectorAll(selector);
  const node = nodes.length === 1 ? nodes[0] : null;
  if (!(node instanceof HTMLInputElement) || node.type !== "password" || document.activeElement !== node) {
    return { ok: false, code: "browser_failed" };
  }
  if (node.value.length !== length) return { ok: false, code: "browser_failed" };
  node.dispatchEvent(new Event("change", { bubbles: true }));
  return { ok: true };
}

const FILL_CODES = ["origin_mismatch", "not_password_field"];

/** Only the shape zks expects leaves the page; anything else is browser_failed. */
function pageResult(r) {
  if (r !== null && typeof r === "object" && r.ok === true) return { ok: true };
  if (r !== null && typeof r === "object" && r.ok === false && FILL_CODES.includes(r.code)) return { ok: false, code: r.code };
  return { ok: false, code: "browser_failed" };
}

// The secret never enters page JavaScript as an evaluate argument: it is typed through the
// browser's input pipeline into the input that a secret-free evaluate focused, and the origin
// is checked again right before the Keychain read and right before typing.
async function fill(page) {
  if (!(await originMatches(page))) return { ok: false, code: "origin_mismatch" };
  if (!(await waitForElement(page))) return { ok: false, code: "not_found" };
  const prepared = pageResult(await page.evaluate(preparePassword, { selector: spec.selector, expected: spec.origin }));
  if (!prepared.ok) return prepared;
  if (!(await originMatches(page))) return { ok: false, code: "origin_mismatch" };
  // -g, not -w: -w prints non-printable values as hex, indistinguishable from a hex-looking value.
  const found = spawnSync(SECURITY, ["find-generic-password", "-s", spec.service, "-a", spec.account, "-g"], { timeout: 15000 });
  if (found.status === 44) return { ok: false, code: "not_found" };
  if (found.status !== 0 || !found.stderr) return { ok: false, code: "keychain_failed" };
  const bytes = found.stderr;
  const line = /^password: (.*)$/m.exec(bytes.toString("latin1"));
  const rest = line ? line[1] : null;
  const hex = rest === null ? null : /^0x([0-9A-Fa-f]*)(?:\\s|$)/.exec(rest);
  let value = null;
  if (rest === "") value = "";
  else if (hex && hex[1].length % 2 === 0) {
    // fatal: bytes that are not UTF-8 fail closed instead of being typed as U+FFFD.
    try {
      value = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(Buffer.from(hex[1], "hex"));
    } catch {
      value = null;
    }
  }
  else if (rest !== null && rest.length >= 2 && rest.startsWith('"') && rest.endsWith('"')) value = rest.slice(1, -1);
  bytes.fill(0);
  if (found.stdout) found.stdout.fill(0);
  if (value === null) return { ok: false, code: "keychain_failed" };
  if (value.length === 0) return { ok: false, code: "not_found" };
  const length = value.length;
  let typed = false;
  let confirmed = { ok: false, code: "browser_failed" };
  try {
    if (!(await originMatches(page))) return { ok: false, code: "origin_mismatch" };
    const focused = pageResult(await page.evaluate(focusStillOnPassword, { selector: spec.selector, expected: spec.origin }));
    if (!focused.ok) return focused;
    typed = true;
    await page.keyboard.insertText(value);
    value = null;
    confirmed = pageResult(await page.evaluate(confirmPassword, { selector: spec.selector, expected: spec.origin, length }));
  } catch {
    confirmed = { ok: false, code: "browser_failed" };
  } finally {
    value = null;
    if (typed && !confirmed.ok) {
      // The text may have landed somewhere else: wipe it and leave the page.
      try { await page.evaluate(clearAfterFailure, spec.selector); } catch {}
      try { await page.goto("about:blank"); } catch {}
    }
  }
  return confirmed.ok ? { ok: true, length } : confirmed;
}

// Isolated: the profile must exist and must not be the default one (the agent's own session).
// zks creates the space itself, lands on --url and, whatever happens, finishes it keeping nothing.
async function isolated(iso) {
  const list = await profiles();
  const profile = Array.isArray(list)
    ? list.find((p) => p !== null && typeof p === "object" && p.id === iso.profileId)
    : undefined;
  if (profile === undefined) return { ok: false, code: "isolated_profile_missing" };
  if (profile.isDefault !== false) return { ok: false, code: "isolated_profile_not_isolated" };
  const task = await taskSpace(iso.name, { profileId: iso.profileId });
  try {
    const page = task.page(ISOLATED_PAGE);
    await page.goto(iso.url);
    if (!(await originMatches(page))) return { ok: false, code: "login_required" };
    return spec.mode === "read" ? await read(page) : await fill(page);
  } finally {
    try {
      await task.finish({ keep: [] });
    } catch {}
  }
}

let result;
try {
  if (spec.isolated) {
    result = await isolated(spec.isolated);
  } else {
    const task = await taskSpace(spec.space);
    const page = task.page(spec.page);
    result = spec.mode === "read" ? await read(page) : await fill(page);
  }
} catch {
  result = { ok: false, code: "browser_failed" };
}
console.log("ZKS_RESULT " + JSON.stringify(result));
`;

/**
 * The script zks pipes to `ego-browser nodejs`. Every input enters it only through JSON.stringify.
 * zks always uses SECURITY_PATH; tests pass a stand-in so they never touch the real Keychain.
 */
export function buildCaptureScript(spec: CaptureScriptSpec, security: string = SECURITY_PATH): string {
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
    ...(spec.isolated
      ? { isolated: { profileId: spec.isolated.profileId, url: spec.isolated.url, name: spec.isolated.name } }
      : {}),
  };
  return (
    "// zks capture script (generated). Prints exactly one line: ZKS_RESULT <metadata json>.\n" +
    `const spec = ${JSON.stringify(embedded)};\nconst SECURITY = ${JSON.stringify(security)};\n` +
    `const ISOLATED_PAGE = ${JSON.stringify(ISOLATED_PAGE)};\n${BODY}`
  );
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
