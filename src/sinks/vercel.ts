import type { VercelTarget } from "../policy/types.ts";
import { postJson, requestJson, safeCode, withToken, type JsonResponse } from "./http.ts";
import { SinkError, providerTime, type Sink } from "./types.ts";

export const VERCEL_API = "https://api.vercel.com";

function firstId(created: unknown): string | undefined {
  const item = Array.isArray(created) ? created[0] : created;
  const id = (item as { id?: unknown } | undefined)?.id;
  return typeof id === "string" ? id : undefined;
}

function failed(res: JsonResponse): SinkError {
  const code = safeCode((res.body as { error?: { code?: unknown } } | null)?.error?.code) ?? `http_${res.status}`;
  return new SinkError("vercel_failed", `Vercel ${code}`, res.status);
}

interface VercelEnv {
  key?: unknown;
  target?: unknown;
  gitBranch?: unknown;
  updatedAt?: unknown;
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
    if (!res.ok) throw failed(res);
    const version = firstId((res.body as { created?: unknown } | null)?.created);
    return version ? { version } : {};
  },

  /**
   * Lists the project's env vars and keeps only the name, environments, branch and updatedAt of
   * NAME (the rest of the body, values included, is dropped). Missing when any environment has no
   * entry; otherwise the oldest updatedAt among them.
   */
  async lastModified(op, ctx) {
    const target = op.target as VercelTarget;
    const query = target.teamId ? `?${new URLSearchParams({ teamId: target.teamId })}` : "";
    const url = `${VERCEL_API}/v10/projects/${encodeURIComponent(target.projectId)}/env${query}`;
    const res = await withToken(ctx.keychain, "vercel", (token) =>
      requestJson(ctx.fetch, "vercel", "GET", url, { authorization: `Bearer ${token}` }),
    );
    if (!res.ok) throw failed(res);
    const envs = (res.body as { envs?: unknown } | null)?.envs;
    const entries = (Array.isArray(envs) ? (envs as VercelEnv[]) : []).filter(
      ({ key, gitBranch }) => key === op.name && (target.gitBranch ? gitBranch === target.gitBranch : !gitBranch),
    );
    let oldest: Date | null = null;
    for (const environment of target.environments) {
      const matching = entries.filter(({ target: envTargets }) => Array.isArray(envTargets) && envTargets.includes(environment));
      if (matching.length === 0) return { status: "missing" };
      for (const { updatedAt } of matching) {
        const time = providerTime(updatedAt);
        if (time === null) return { status: "unsupported", reason: "Vercel returned no updatedAt for this variable" };
        if (oldest === null || time < oldest) oldest = time;
      }
    }
    return oldest === null ? { status: "missing" } : { status: "found", time: oldest };
  },
};
