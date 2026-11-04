import type { Exec } from "../platform/exec.ts";
import { buildCaptureScript, parseCaptureOutput, type CaptureOutcome, type CaptureScriptSpec } from "./script.ts";

export const CAPTURE_TIMEOUT_MS = 60_000;

/**
 * Pipes zks's own script to `ego-browser nodejs` (absolute path, no shell, fixed env) and reads
 * only its marker line. No other ego output, stdout or stderr, ever leaves this function.
 */
export async function runCapture(exec: Exec, egoBrowser: string, spec: CaptureScriptSpec): Promise<CaptureOutcome> {
  let res;
  try {
    res = await exec(egoBrowser, ["nodejs"], { input: buildCaptureScript(spec), timeoutMs: CAPTURE_TIMEOUT_MS });
  } catch {
    return { ok: false, code: "browser_failed" };
  }
  // `ego-browser nodejs` prints the script's console output on stderr; look for the one marker in both.
  const text = `${res.stdout.toString("utf8")}\n${res.stderr.toString("utf8")}`;
  res.stdout.fill(0);
  res.stderr.fill(0);
  if (res.code !== 0) return { ok: false, code: "browser_failed" };
  return parseCaptureOutput(text);
}
