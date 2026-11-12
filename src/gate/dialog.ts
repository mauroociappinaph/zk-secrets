import { SecretBuffer } from "../secret/secret-buffer.ts";
import type { Exec } from "../platform/exec.ts";

/** Answer of the apply dialog: "always" also trusts the new destinations for later applies. */
export type TrustDecision = "deny" | "once" | "always";

/** Human channel the agent cannot read: native macOS dialogs driven through osascript stdin. */
export interface HumanChannel {
  approve(title: string, lines: string[]): Promise<boolean>;
  /** Deny / Approve once / Always allow; anything but an explicit button press is "deny". */
  approveWithTrust(title: string, lines: string[]): Promise<TrustDecision>;
  promptSecret(title: string, message: string): Promise<SecretBuffer | null>;
}

/** Hard cap: a dialog with more lines is denied, never truncated (apply sends at most 25). */
export const MAX_LINES = 25;
const APPROVAL_TIMEOUT_SECONDS = 180;
const PROMPT_TIMEOUT_SECONDS = 300;

export function appleScriptString(text: string): string {
  // "…" (a truncation mark) goes as `character id 8230`, so the script itself stays ASCII.
  const escaped = text.replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/…/g, '" & (character id 8230) & "');
  return `"${escaped}"`;
}

/** Replaces every character outside printable ASCII (newlines, tabs, bidi controls) with "?"; keeps "…". */
export function sanitizeLine(text: string): string {
  return text.replace(/[^\x20-\x7E…]/g, "?");
}

export function createMacDialogs(exec: Exec, platform: NodeJS.Platform = process.platform): HumanChannel {
  /** Shows a caution dialog whose default and cancel button is "Deny"; returns the button pressed, or null. */
  const ask = async (title: string, lines: string[], buttons: string[]): Promise<string | null> => {
    if (platform !== "darwin" || lines.length > MAX_LINES) return null;
    const script = [
      `set msg to ${appleScriptString(lines.map(sanitizeLine).join("\n"))}`,
      `set r to display dialog msg with title ${appleScriptString(sanitizeLine(title))} buttons {${buttons.map(appleScriptString).join(", ")}} default button "Deny" cancel button "Deny" with icon caution giving up after ${APPROVAL_TIMEOUT_SECONDS}`,
      `if gave up of r then return "timeout"`,
      `return button returned of r`,
    ].join("\n");
    try {
      const res = await exec("/usr/bin/osascript", ["-"], { input: script, timeoutMs: (APPROVAL_TIMEOUT_SECONDS + 10) * 1000 });
      return res.code === 0 ? res.stdout.toString("utf8").trim() : null;
    } catch {
      return null;
    }
  };

  return {
    async approve(title, lines) {
      return (await ask(title, lines, ["Deny", "Approve"])) === "Approve";
    },
    async approveWithTrust(title, lines) {
      const button = await ask(title, lines, ["Deny", "Approve once", "Always allow"]);
      return button === "Approve once" ? "once" : button === "Always allow" ? "always" : "deny";
    },
    async promptSecret(title, message) {
      if (platform !== "darwin") return null;
      const script = [
        `set r to display dialog ${appleScriptString(message)} with title ${appleScriptString(title)} default answer "" with hidden answer buttons {"Cancel", "Save"} default button "Save" cancel button "Cancel" giving up after ${PROMPT_TIMEOUT_SECONDS}`,
        `if gave up of r then error number -128`,
        `return text returned of r`,
      ].join("\n");
      try {
        const res = await exec("/usr/bin/osascript", ["-"], { input: script, timeoutMs: (PROMPT_TIMEOUT_SECONDS + 10) * 1000 });
        if (res.code !== 0) return null;
        const bytes = res.stdout;
        const end = bytes.length > 0 && bytes[bytes.length - 1] === 0x0a ? bytes.length - 1 : bytes.length;
        const copy = Buffer.from(bytes.subarray(0, end));
        bytes.fill(0);
        if (copy.length === 0) return null;
        return SecretBuffer.adopt(copy);
      } catch {
        return null;
      }
    },
  };
}
