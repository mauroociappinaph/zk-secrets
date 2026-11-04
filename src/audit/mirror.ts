import { createHmac } from "node:crypto";
import { ZKS_KEYCHAIN_SERVICE, type Keychain } from "../platform/keychain.ts";
import type { AuditStore, Mirror, MirrorResult } from "./types.ts";

export const MIRROR_BATCH = 200;
const MIRROR_TIMEOUT_MS = 10_000;
const MAX_BATCHES_PER_SYNC = 25;

export interface MirrorDeps {
  fetch: typeof fetch;
  keychain: Keychain;
  readConfig(): Promise<{ sheets?: { webhookUrl?: string } }>;
  now(): Date;
}

export function signPayload(key: string, payload: string): string {
  return createHmac("sha256", key).update(payload).digest("hex");
}

function pendingCount(store: AuditStore): number {
  return store.pendingMirror(MIRROR_BATCH * MAX_BATCHES_PER_SYNC).length;
}

/**
 * Google Sheets mirror through an Apps Script web app. Records are metadata only and every
 * request is HMAC-signed; the local hash chain stays the source of truth. Never throws.
 */
export function createSheetsMirror(deps: MirrorDeps): Mirror {
  return {
    async sync(store: AuditStore): Promise<MirrorResult> {
      let pushed = 0;
      try {
        const url = (await deps.readConfig()).sheets?.webhookUrl;
        if (!url) return { configured: false, pushed, pending: pendingCount(store) };

        const key = await deps.keychain.get(ZKS_KEYCHAIN_SERVICE, "sheets-hmac");
        if (!key || key.length === 0) {
          return {
            configured: true,
            pushed,
            pending: pendingCount(store),
            error: "missing sheets-hmac token; run zks auth set sheets-hmac",
          };
        }
        try {
          for (let batch = 0; batch < MAX_BATCHES_PER_SYNC; batch++) {
            const records = store.pendingMirror(MIRROR_BATCH);
            if (records.length === 0) break;
            const payload = JSON.stringify({ sentAt: deps.now().toISOString(), records });
            const response = await deps.fetch(url, {
              method: "POST",
              headers: { "content-type": "application/json" },
              body: JSON.stringify({ payload, signature: signPayload(key.reveal(), payload) }),
              redirect: "follow",
              signal: AbortSignal.timeout(MIRROR_TIMEOUT_MS),
            });
            const body = (await response.json().catch(() => null)) as { ok?: unknown; accepted?: unknown } | null;
            if (!response.ok || body?.ok !== true || !Array.isArray(body.accepted)) {
              return { configured: true, pushed, pending: pendingCount(store), error: `mirror rejected the batch (HTTP ${response.status})` };
            }
            const known = new Set(records.map((r) => r.auditId));
            const accepted = body.accepted.filter((id): id is string => typeof id === "string" && known.has(id));
            store.markMirrored(accepted, deps.now().toISOString());
            pushed += accepted.length;
            if (accepted.length < records.length) break;
          }
        } finally {
          key.dispose();
        }
        return { configured: true, pushed, pending: pendingCount(store) };
      } catch {
        return { configured: true, pushed, pending: safePending(store), error: "mirror unreachable" };
      }
    },
  };
}

function safePending(store: AuditStore): number {
  try {
    return pendingCount(store);
  } catch {
    return -1;
  }
}
