import type { SecretBuffer } from "./secret-buffer.ts";

const REDACTED = "[REDACTED]";
const MIN_REDACT_LENGTH = 4;

/**
 * Last line of defense: every text that leaves the process passes through scrub(),
 * which removes any registered secret in raw, JSON-escaped, URL-encoded or base64 form.
 */
export class Redactor {
  #needles = new Set<string>();

  register(secret: SecretBuffer): void {
    const raw = secret.reveal();
    if (raw.length < MIN_REDACT_LENGTH) return;
    this.#needles.add(raw);
    this.#needles.add(JSON.stringify(raw).slice(1, -1));
    this.#needles.add(encodeURIComponent(raw));
    this.#needles.add(Buffer.from(raw, "utf8").toString("base64"));
    this.#needles.add(Buffer.from(raw, "utf8").toString("hex"));
  }

  scrub(text: string): string {
    let out = text;
    for (const needle of [...this.#needles].sort((a, b) => b.length - a.length)) {
      if (needle.length >= MIN_REDACT_LENGTH) out = out.split(needle).join(REDACTED);
    }
    return out;
  }

  clear(): void {
    this.#needles.clear();
  }
}
