import { ZKS_KEYCHAIN_SERVICE, type Keychain } from "../platform/keychain.ts";
import { SecretBuffer } from "../secret/secret-buffer.ts";
import type { AuditAnchor } from "./types.ts";

/** Keychain account (service "zks") holding the audit head as `<count>:<hash>`. */
export const AUDIT_ANCHOR_ACCOUNT = "audit-head";
const ANCHOR = /^(\d{1,15}):([0-9a-f]{64})$/;

/** Returns the stored anchor, or null when it is missing or malformed. */
export async function readAuditAnchor(keychain: Keychain): Promise<AuditAnchor | null> {
  const value = await keychain.get(ZKS_KEYCHAIN_SERVICE, AUDIT_ANCHOR_ACCOUNT);
  if (!value) return null;
  try {
    const match = ANCHOR.exec(value.reveal());
    return match ? { count: Number(match[1]), hash: match[2] as string } : null;
  } finally {
    value.dispose();
  }
}

export async function writeAuditAnchor(keychain: Keychain, anchor: AuditAnchor): Promise<void> {
  const value = SecretBuffer.fromString(`${anchor.count}:${anchor.hash}`);
  try {
    await keychain.set(ZKS_KEYCHAIN_SERVICE, AUDIT_ANCHOR_ACCOUNT, value);
  } finally {
    value.dispose();
  }
}
