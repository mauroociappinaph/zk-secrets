import { SecretBuffer } from "../secret/secret-buffer.ts";
import type { Exec } from "../platform/exec.ts";

/** Human channel the agent cannot read: native macOS dialogs driven through osascript stdin. */
export interface HumanChannel {
  approve(title: string, lines: string[]): Promise<boolean>;
  promptSecret(title: string, message: string): Promise<SecretBuffer | null>;
}

const MAX_LINES = 25;
const APPROVAL_TIMEOUT_SECONDS = 180;
const PROMPT_TIMEOUT_SECONDS = 300;

export function appleScriptString(text: string): string {
  return `"${text.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}

function joinLines(lines: string[]): string {
  const shown = lines.slice(0, MAX_LINES);
  if (lines.length > MAX_LINES) shown.push(`... and ${lines.length - MAX_LINES} more`);
  return shown.join("\n");
}

export function createMacDialogs(exec: Exec, platform: NodeJS.Platform = process.platform): HumanChannel {
  return {
    async approve(title, lines) {
      if (platform !== "darwin") return false;
      const script = [
        `set msg to ${appleScriptString(joinLines(lines))}`,
        `set r to display dialog msg with title ${appleScriptString(title)} buttons {"Deny", "Approve"} default button "Deny" cancel button "Deny" with icon caution giving up after ${APPROVAL_TIMEOUT_SECONDS}`,
        `if gave up of r then return "timeout"`,
        `return button returned of r`,
      ].join("\n");
      try {
        const res = await exec("/usr/bin/osascript", ["-"], { input: script, timeoutMs: (APPROVAL_TIMEOUT_SECONDS + 10) * 1000 });
        return res.code === 0 && res.stdout.toString("utf8").trim() === "Approve";
      } catch {
        return false;
      }
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
