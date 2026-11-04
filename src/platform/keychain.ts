import { SecretBuffer } from "../secret/secret-buffer.ts";
import type { Exec } from "./exec.ts";

export const ZKS_KEYCHAIN_SERVICE = "zks";

export interface Keychain {
  get(service: string, account: string): Promise<SecretBuffer | null>;
  set(service: string, account: string, value: SecretBuffer): Promise<void>;
  remove(service: string, account: string): Promise<boolean>;
  has(service: string, account: string): Promise<boolean>;
  /** Last modification time from the item's attributes (never its value); null when missing. */
  modifiedAt(service: string, account: string): Promise<Date | null>;
}

const KEYCHAIN_ITEM_NOT_FOUND = 44;

function stripTrailingNewline(bytes: Buffer): Buffer {
  return bytes.length > 0 && bytes[bytes.length - 1] === 0x0a ? bytes.subarray(0, bytes.length - 1) : bytes;
}

function quoteForSecurityShell(value: string): string {
  if (!/^[A-Za-z0-9._:/@+=-]+$/.test(value)) throw new Error("unsafe keychain identifier");
  return value;
}

/** macOS Keychain through /usr/bin/security; values pass through stdin, never argv. */
export function createKeychain(exec: Exec): Keychain {
  return {
    async get(service, account) {
      const res = await exec("/usr/bin/security", ["find-generic-password", "-s", service, "-a", account, "-w"]);
      if (res.code === KEYCHAIN_ITEM_NOT_FOUND) return null;
      if (res.code !== 0) throw new Error(`keychain read failed for ${service}/${account} (exit ${res.code})`);
      const copy = Buffer.from(stripTrailingNewline(res.stdout));
      res.stdout.fill(0);
      return SecretBuffer.adopt(copy);
    },
    async set(service, account, value) {
      // `security -i` reads commands from stdin; -X takes hex so no quoting of the value is needed.
      const hex = Buffer.from(value.reveal(), "utf8").toString("hex");
      const command = Buffer.from(
        `add-generic-password -U -s ${quoteForSecurityShell(service)} -a ${quoteForSecurityShell(account)} -X ${hex}\n`,
      );
      const res = await exec("/usr/bin/security", ["-i"], { input: command });
      command.fill(0);
      if (res.code !== 0 || res.stderr.length > 0) {
        throw new Error(`keychain write failed for ${service}/${account}`);
      }
    },
    async remove(service, account) {
      const res = await exec("/usr/bin/security", ["delete-generic-password", "-s", service, "-a", account]);
      return res.code === 0;
    },
    async has(service, account) {
      const res = await exec("/usr/bin/security", ["find-generic-password", "-s", service, "-a", account]);
      return res.code === 0;
    },
    async modifiedAt(service, account) {
      // Without -w, security prints only attributes; "mdat" looks like "20261104175302Z\000".
      const res = await exec("/usr/bin/security", ["find-generic-password", "-s", service, "-a", account]);
      if (res.code !== 0) return null;
      return parseKeychainDate(res.stdout.toString("utf8"));
    },
  };
}

export function parseKeychainDate(attributes: string): Date | null {
  // Anchored to the attribute's own line, so a label or comment that contains "mdat" cannot fake it.
  const m = /^\s*"mdat"<timedate>=0x[0-9A-F]+\s+"(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z\\000"\s*$/m.exec(attributes);
  if (!m) return null;
  const [, y, mo, d, h, mi, s] = m;
  return new Date(Date.UTC(Number(y), Number(mo) - 1, Number(d), Number(h), Number(mi), Number(s)));
}
