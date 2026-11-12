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
  "login_redirected",
] as const;
export type CaptureErrorCode = (typeof CAPTURE_ERROR_CODES)[number];
export type CaptureOutcome = { ok: true; length: number } | { ok: false; code: CaptureErrorCode };

export const LOGIN_PENDING = ["2fa", "captcha", "unknown"] as const;
export type LoginPending = (typeof LOGIN_PENDING)[number];
/** A login reports whether it worked, never a value; login_redirected carries only the final origin. */
export type LoginOutcome =
  | { ok: true; loggedIn: boolean; finalOrigin: string; pending?: LoginPending }
  | { ok: false; code: "login_redirected"; finalOrigin: string }
  | { ok: false; code: Exclude<CaptureErrorCode, "login_redirected"> };

/** The non-secret part of a login: the page, the username and the form's selectors. */
export interface LoginScriptSpec {
  url: string;
  user: string;
  userSelector: string;
  submitSelector: string;
  successSelector: string | null;
}

const MAX_LENGTH = 100_000;

export interface CaptureScriptSpec {
  /**
   * read: take the element's value into the Keychain item; fill: put the Keychain item into the element;
   * login: set the user field, fill the Keychain item into `selector` (the password field) and submit.
   */
  mode: "read" | "fill" | "login";
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
   * it, goes to `url` and finishes the space with keep: [] (a pending login keeps its page open
   * for the human). Absent for --space/--page.
   */
  isolated?: { profileId: string; url: string; name: string };
  /** Required for login; `waitMs` also bounds how long the script waits for the page to settle after submit. */
  login?: LoginScriptSpec;
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

/** The page's origin only ("null" when it has none); never its path or query. */
async function currentOrigin(page) {
  try {
    return new URL(await page.url()).origin;
  } catch {
    return "null";
  }
}

async function redirected(page) {
  return { ok: false, code: "login_redirected", finalOrigin: await currentOrigin(page) };
}

async function waitFor(page, selector) {
  try {
    await page.waitForSelector(selector, { state: "attached", timeout: spec.waitMs });
    return true;
  } catch {
    return false;
  }
}

/** Runs in the page without the secret: same origin, exactly one non-password input, set like a user would. */
function setUser({ selector, expected, user }) {
  if (document.location.origin !== expected) return { ok: false, code: "origin_mismatch" };
  const nodes = document.querySelectorAll(selector);
  const node = nodes.length === 1 ? nodes[0] : null;
  if (!(node instanceof HTMLInputElement) || node.type === "password") return { ok: false, code: "not_found" };
  Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value").set.call(node, user);
  node.dispatchEvent(new Event("input", { bubbles: true }));
  node.dispatchEvent(new Event("change", { bubbles: true }));
  return { ok: true };
}

/** Runs in the page after submit, without the secret: what the page shows now, as booleans only. */
function inspectLogin({ expected, passwordSelector, successSelector }) {
  if (document.location.origin !== expected) return { away: true };
  const any = (selector) => {
    try {
      return document.querySelectorAll(selector).length > 0;
    } catch {
      return false;
    }
  };
  let captcha = false;
  for (const frame of document.querySelectorAll("iframe")) {
    try {
      const src = new URL(frame.getAttribute("src") || "", document.location.href);
      if (/captcha/i.test(src.hostname) || /^\\/recaptcha\\//i.test(src.pathname)) captcha = true;
    } catch {}
  }
  return {
    success: successSelector === null ? false : any(successSelector),
    password: any(passwordSelector),
    otp: any('input[type="tel"], input[type="number"], input[autocomplete="one-time-code"]'),
    captcha,
  };
}

async function loginState(page) {
  const origin = await currentOrigin(page);
  let url = "";
  try {
    url = await page.url();
  } catch {}
  if (origin !== spec.origin) return { origin, url, away: true };
  let seen = null;
  try {
    seen = await page.evaluate(inspectLogin, { expected: spec.origin, passwordSelector: spec.selector, successSelector: spec.login.successSelector });
  } catch {}
  const s = seen !== null && typeof seen === "object" ? seen : {};
  if (s.away === true) return { origin, url, away: true };
  // An unreadable page counts as still showing the password field: fail towards loggedIn false.
  return { origin, url, away: false, success: s.success === true, password: s.password !== false, otp: s.otp === true, captcha: s.captcha === true };
}

/**
 * A captcha frame or code input counts only when it is new since the submit, or once the page
 * changed (another URL, or the password field is gone): one that was already on the login page
 * (an invisible reCAPTCHA, a phone field) is not a challenge. A found success selector wins.
 */
function judge(before, state) {
  const changed = state.url !== before.url || (before.password && !state.password);
  const captcha = state.captcha && (changed || !before.captcha);
  const otp = state.otp && (changed || !before.otp);
  const success = spec.login.successSelector !== null && state.success;
  const done = success || captcha || otp || (spec.login.successSelector === null && !state.password);
  return { ...state, success, captcha: !success && captcha, otp: !success && otp, done };
}

/** Waits, bounded by waitMs, for the page to show a result; leaving the origin twice in a row ends it. */
async function settle(page, before) {
  const deadline = Date.now() + spec.waitMs;
  let away = 0;
  for (;;) {
    await sleep(Math.min(250, spec.waitMs));
    const state = await loginState(page);
    if (state.away) {
      if (++away >= 2) return state;
    } else {
      away = 0;
      const judged = judge(before, state);
      if (judged.done || Date.now() >= deadline) return judged;
    }
    if (Date.now() >= deadline) return state;
  }
}

// Login: the user field gets the (non-secret) username, the password goes through fill's typing
// path, then zks clicks submit and reports only booleans about the page that follows.
async function login(page, navigated) {
  const L = spec.login;
  if (!navigated) await page.goto(L.url);
  if (!(await originMatches(page))) return await redirected(page);
  if (!(await waitFor(page, L.userSelector))) return { ok: false, code: "not_found" };
  const set = await page.evaluate(setUser, { selector: L.userSelector, expected: spec.origin, user: L.user });
  if (set === null || typeof set !== "object" || set.ok !== true) {
    if (set !== null && typeof set === "object" && set.code === "origin_mismatch") return await redirected(page);
    return { ok: false, code: set !== null && typeof set === "object" && set.code === "not_found" ? "not_found" : "browser_failed" };
  }
  const filled = await fill(page);
  if (!filled.ok) return filled.code === "origin_mismatch" ? await redirected(page) : filled;
  // The password is in the field now: any failure before the submit wipes it and leaves the page.
  let submitted = false;
  let before = null;
  try {
    if (!(await originMatches(page))) return await redirected(page);
    before = await loginState(page);
    if (before.away) return await redirected(page);
    try {
      await page.click(L.submitSelector, { timeout: spec.waitMs });
    } catch {
      return { ok: false, code: "not_found" };
    }
    submitted = true;
  } finally {
    if (!submitted) {
      try { await page.evaluate(clearAfterFailure, spec.selector); } catch {}
      try { await page.goto("about:blank"); } catch {}
    }
  }
  const state = await settle(page, before);
  if (state.away) return { ok: false, code: "login_redirected", finalOrigin: state.origin };
  const loggedIn = L.successSelector !== null ? state.success : !state.password && !state.otp && !state.captcha;
  // The click may not have submitted (or a success selector matched the login page itself): never
  // leave the typed password in a field the agent can read, whatever the verdict.
  if (state.password) {
    try { await page.evaluate(clearAfterFailure, spec.selector); } catch {}
  }
  if (loggedIn) return { ok: true, loggedIn: true, finalOrigin: state.origin };
  // The page itself stays, so the human can finish a captcha or 2FA step there.
  return { ok: true, loggedIn: false, finalOrigin: state.origin, pending: state.captcha ? "captcha" : state.otp ? "2fa" : "unknown" };
}

function step(page, navigated) {
  return spec.mode === "read" ? read(page) : spec.mode === "login" ? login(page, navigated) : fill(page);
}

// Isolated: the profile must exist and must not be the default one (the agent's own session).
// zks creates the space itself, lands on --url and finishes it keeping nothing, except the page of
// a pending login (2FA, captcha or unknown), which stays open for the human to finish there.
async function isolated(iso) {
  const list = await profiles();
  const profile = Array.isArray(list)
    ? list.find((p) => p !== null && typeof p === "object" && p.id === iso.profileId)
    : undefined;
  if (profile === undefined) return { ok: false, code: "isolated_profile_missing" };
  if (profile.isDefault !== false) return { ok: false, code: "isolated_profile_not_isolated" };
  const task = await taskSpace(iso.name, { profileId: iso.profileId });
  let page = null;
  let result = null;
  try {
    page = task.page(ISOLATED_PAGE);
    await page.goto(iso.url);
    if (!(await originMatches(page))) return spec.mode === "login" ? await redirected(page) : { ok: false, code: "login_required" };
    result = await step(page, true);
    return result;
  } finally {
    // Only a real human challenge keeps the page: a wrong password or unmatched selectors (unknown) closes it.
    const pending = spec.mode === "login" && page !== null && result !== null && result.ok === true && result.loggedIn === false && result.pending !== "unknown";
    try {
      await task.finish({ keep: pending ? [page] : [] });
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
    result = await step(page, false);
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
    ...(spec.login
      ? {
          login: {
            url: spec.login.url,
            user: spec.login.user,
            userSelector: spec.login.userSelector,
            submitSelector: spec.login.submitSelector,
            successSelector: spec.login.successSelector,
          },
        }
      : {}),
  };
  return (
    "// zks capture script (generated). Prints exactly one line: ZKS_RESULT <metadata json>.\n" +
    `const spec = ${JSON.stringify(embedded)};\nconst SECURITY = ${JSON.stringify(security)};\n` +
    `const ISOLATED_PAGE = ${JSON.stringify(ISOLATED_PAGE)};\n${BODY}`
  );
}

const FAILED: CaptureOutcome = { ok: false, code: "browser_failed" };

/** The one marker line's JSON object, or null when there is not exactly one valid marker. */
function markerObject(text: string): Record<string, unknown> | null {
  const markers = text.split(/\r?\n/).filter((line) => line.startsWith(CAPTURE_MARKER));
  if (markers.length !== 1) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse((markers[0] as string).slice(CAPTURE_MARKER.length));
  } catch {
    return null;
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) return null;
  return parsed as Record<string, unknown>;
}

/** An origin as URL.origin prints it ("null" for about:blank); never a path, query or space. */
const FINAL_ORIGIN = /^(?:null|[a-z][a-z0-9+.-]{0,30}:\/\/[A-Za-z0-9.\-[\]:]{1,260})$/;

/** Reads a login's marker line; only the documented shapes pass, anything else is browser_failed. */
export function parseLoginOutput(text: string): LoginOutcome {
  const result = markerObject(text);
  if (result === null) return FAILED as LoginOutcome;
  const keys = Object.keys(result).sort().join(",");
  const origin = result.finalOrigin;
  const validOrigin = typeof origin === "string" && FINAL_ORIGIN.test(origin);
  if (result.ok === true && validOrigin) {
    if (keys === "finalOrigin,loggedIn,ok" && result.loggedIn === true) return { ok: true, loggedIn: true, finalOrigin: origin };
    if (
      keys === "finalOrigin,loggedIn,ok,pending" &&
      result.loggedIn === false &&
      (LOGIN_PENDING as readonly unknown[]).includes(result.pending)
    ) {
      return { ok: true, loggedIn: false, finalOrigin: origin, pending: result.pending as LoginPending };
    }
    return FAILED as LoginOutcome;
  }
  if (result.ok === false && result.code === "login_redirected") {
    return keys === "code,finalOrigin,ok" && validOrigin ? { ok: false, code: "login_redirected", finalOrigin: origin } : (FAILED as LoginOutcome);
  }
  if (result.ok === false && keys === "code,ok" && (CAPTURE_ERROR_CODES as readonly unknown[]).includes(result.code)) {
    return { ok: false, code: result.code as Exclude<CaptureErrorCode, "login_redirected"> };
  }
  return FAILED as LoginOutcome;
}

/** Reads the one marker line of ego-browser output; anything else, or more than one marker, is browser_failed. */
export function parseCaptureOutput(text: string): CaptureOutcome {
  const result = markerObject(text);
  if (result === null) return FAILED;
  const keys = Object.keys(result).sort().join(",");
  if (result.ok === true && keys === "length,ok") {
    const length = result.length;
    return typeof length === "number" && Number.isInteger(length) && length > 0 && length <= MAX_LENGTH ? { ok: true, length } : FAILED;
  }
  // login_redirected belongs to a login only; a read or fill never reports it.
  if (result.ok === false && keys === "code,ok" && result.code !== "login_redirected" && (CAPTURE_ERROR_CODES as readonly unknown[]).includes(result.code)) {
    return { ok: false, code: result.code as CaptureErrorCode };
  }
  return FAILED;
}
