import type { Exec } from "../platform/exec.ts";
import {
  buildCaptureScript,
  parseCaptureOutput,
  parseLoginOutput,
  type CaptureOutcome,
  type CaptureScriptSpec,
  type LoginOutcome,
} from "./script.ts";

// Longer than every wait inside the script (click, selector, value poll, Keychain, login settle),
// so the script's own cleanup (about:blank after a reveal) runs before zks gives up on it.
export const CAPTURE_TIMEOUT_MS = 120_000;

/**
 * Pipes zks's own script to `ego-browser nodejs` (absolute path, no shell, fixed env) and returns
 * its output text for the marker parser only; null when ego failed. No other ego output, stdout
 * or stderr, ever leaves this module.
 */
async function runScript(exec: Exec, egoBrowser: string, spec: CaptureScriptSpec): Promise<string | null> {
  let res;
  try {
    res = await exec(egoBrowser, ["nodejs"], { input: buildCaptureScript(spec), timeoutMs: CAPTURE_TIMEOUT_MS });
  } catch {
    return null;
  }
  // `ego-browser nodejs` prints the script's console output on stderr; look for the one marker in both.
  const text = `${res.stdout.toString("utf8")}\n${res.stderr.toString("utf8")}`;
  res.stdout.fill(0);
  res.stderr.fill(0);
  return res.code === 0 ? text : null;
}

export async function runCapture(exec: Exec, egoBrowser: string, spec: CaptureScriptSpec): Promise<CaptureOutcome> {
  const text = await runScript(exec, egoBrowser, spec);
  return text === null ? { ok: false, code: "browser_failed" } : parseCaptureOutput(text);
}

/** `zks capture login`: the same pipe, read with the login result parser. */
export async function runLogin(exec: Exec, egoBrowser: string, spec: CaptureScriptSpec): Promise<LoginOutcome> {
  const text = await runScript(exec, egoBrowser, spec);
  return text === null ? { ok: false, code: "browser_failed" } : parseLoginOutput(text);
}
