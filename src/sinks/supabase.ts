import type { SupabaseTarget } from "../policy/types.ts";
import { postJson, withToken } from "./http.ts";
import { SinkError, type Sink } from "./types.ts";

export const SUPABASE_API = "https://api.supabase.com";

/** Sets an Edge Functions secret through the Supabase Management API. */
export const supabaseSink: Sink = {
  async apply(op, value, ctx) {
    const target = op.target as SupabaseTarget;
    const url = `${SUPABASE_API}/v1/projects/${encodeURIComponent(target.projectRef)}/secrets`;
    const res = await withToken(ctx.keychain, "supabase", (token) =>
      postJson(ctx.fetch, "supabase", url, { authorization: `Bearer ${token}` }, [{ name: op.name, value: value.reveal() }]),
    );
    if (!res.ok) throw new SinkError("supabase_failed", `Supabase HTTP ${res.status}`, res.status);
    return {};
  },
};
