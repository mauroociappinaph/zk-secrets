import type { VercelTarget } from "../policy/types.ts";
import { postJson, safeCode, withToken } from "./http.ts";
import { SinkError, type Sink } from "./types.ts";

export const VERCEL_API = "https://api.vercel.com";

function firstId(created: unknown): string | undefined {
  const item = Array.isArray(created) ? created[0] : created;
  const id = (item as { id?: unknown } | undefined)?.id;
  return typeof id === "string" ? id : undefined;
}

/** Upserts a project env var. Sensitive vars use type "sensitive": unreadable after creation. */
export const vercelSink: Sink = {
  async apply(op, value, ctx) {
    const target = op.target as VercelTarget;
    const query = new URLSearchParams({ upsert: "true" });
    if (target.teamId) query.set("teamId", target.teamId);
    const url = `${VERCEL_API}/v10/projects/${encodeURIComponent(target.projectId)}/env?${query}`;
    const body: Record<string, unknown> = {
      key: op.name,
      value: value.reveal(),
      type: op.variable.sensitive ? "sensitive" : "plain",
      target: target.environments,
    };
    if (target.gitBranch) body.gitBranch = target.gitBranch;

    const res = await withToken(ctx.keychain, "vercel", (token) =>
      postJson(ctx.fetch, "vercel", url, { authorization: `Bearer ${token}` }, body),
    );
    if (!res.ok) {
      const code = safeCode((res.body as { error?: { code?: unknown } } | null)?.error?.code) ?? `http_${res.status}`;
      throw new SinkError("vercel_failed", `Vercel ${code}`, res.status);
    }
    const version = firstId((res.body as { created?: unknown } | null)?.created);
    return version ? { version } : {};
  },
};
