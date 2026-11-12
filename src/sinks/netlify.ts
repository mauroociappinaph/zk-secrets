import type { NetlifyTarget } from "../policy/types.ts";
import { requestJson, withToken, type JsonResponse } from "./http.ts";
import { SinkError, type Sink } from "./types.ts";

export const NETLIFY_API = "https://api.netlify.com/api/v1";

function failed(res: JsonResponse): SinkError {
  return new SinkError("netlify_failed", `Netlify HTTP ${res.status}`, res.status);
}

/**
 * Upserts a Netlify env var of an account (or one of its sites): a missing variable is created
 * with `is_secret` for sensitive values; an existing one gets the value for the target context.
 * A sensitive value never goes into an existing variable that is not secret.
 */
export const netlifySink: Sink = {
  async apply(op, value, ctx) {
    const target = op.target as NetlifyTarget;
    const query = target.siteId ? `?${new URLSearchParams({ site_id: target.siteId })}` : "";
    const base = `${NETLIFY_API}/accounts/${encodeURIComponent(target.accountId)}/env`;
    const one = `${base}/${encodeURIComponent(op.name)}${query}`;

    await withToken(ctx.keychain, "netlify", async (token) => {
      const call = (method: string, url: string, body?: unknown) =>
        requestJson(ctx.fetch, "netlify", method, url, { authorization: `Bearer ${token}`, "user-agent": "zks" }, body);

      // Only the metadata flag is used; the response body is dropped.
      const existing = await call("GET", one);
      if (existing.status === 404) {
        const created = await call("POST", `${base}${query}`, [
          { key: op.name, values: [{ value: value.reveal(), context: target.context }], is_secret: op.variable.sensitive },
        ]);
        if (!created.ok) throw failed(created);
        return;
      }
      if (!existing.ok) throw failed(existing);
      if (op.variable.sensitive && (existing.body as { is_secret?: unknown } | null)?.is_secret !== true) {
        throw new SinkError(
          "netlify_not_secret",
          `the Netlify variable ${op.name} exists and is not secret; delete it in Netlify or mark it secret, then apply again`,
        );
      }
      const updated = await call("PATCH", one, { context: target.context, value: value.reveal() });
      if (!updated.ok) throw failed(updated);
    });
    return {};
  },
};
