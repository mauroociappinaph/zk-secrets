import { timingSafeEqual } from "node:crypto";
import { inspect } from "node:util";

const REDACTED = "[REDACTED]";

/**
 * Holds a secret value in a Buffer that is never rendered by toString, JSON or util.inspect.
 * Sinks call reveal() at the last moment; dispose() zeroes the bytes.
 */
export class SecretBuffer {
  #bytes: Buffer;
  #disposed = false;

  private constructor(bytes: Buffer) {
    this.#bytes = bytes;
  }

  /** Takes ownership of the buffer: the caller must not reuse it. */
  static adopt(bytes: Buffer): SecretBuffer {
    return new SecretBuffer(bytes);
  }

  static fromString(value: string): SecretBuffer {
    return new SecretBuffer(Buffer.from(value, "utf8"));
  }

  get length(): number {
    return this.#bytes.length;
  }

  get disposed(): boolean {
    return this.#disposed;
  }

  /** Returns the plaintext. Only provider sinks and the redactor may call this. */
  reveal(): string {
    if (this.#disposed) throw new Error("secret already disposed");
    return this.#bytes.toString("utf8");
  }

  /**
   * True when `bytes` holds exactly these raw bytes (no string round trip, so non-UTF-8 bytes
   * compare as they are). Constant time for equal lengths; `bytes` is not modified or kept.
   */
  equals(bytes: Buffer): boolean {
    if (this.#disposed) throw new Error("secret already disposed");
    return bytes.length === this.#bytes.length && timingSafeEqual(this.#bytes, bytes);
  }

  dispose(): void {
    this.#bytes.fill(0);
    this.#disposed = true;
  }

  toString(): string {
    return REDACTED;
  }

  toJSON(): string {
    return REDACTED;
  }

  [inspect.custom](): string {
    return REDACTED;
  }
}
