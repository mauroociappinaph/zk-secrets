import type { RailwayTarget } from "../policy/types.ts";
import { postJson, withToken } from "./http.ts";
import { SinkError, type Sink } from "./types.ts";

export const RAILWAY_API = "https://backboard.railway.com/graphql/v2";
const UPSERT = "mutation zksUpsert($input: VariableUpsertInput!) { variableUpsert(input: $input) }";

/** Upserts a service (or shared) variable through the Railway public GraphQL API. */
export const railwaySink: Sink = {
  async apply(op, value, ctx) {
    const target = op.target as RailwayTarget;
    const input: Record<string, unknown> = {
      projectId: target.projectId,
      environmentId: target.environmentId,
      name: op.name,
      value: value.reveal(),
    };
    if (target.serviceId) input.serviceId = target.serviceId;
    if (target.skipDeploys !== undefined) input.skipDeploys = target.skipDeploys;

    const res = await withToken(ctx.keychain, "railway", (token) =>
      postJson(
        ctx.fetch,
        "railway",
        RAILWAY_API,
        target.tokenType === "project" ? { "project-access-token": token } : { authorization: `Bearer ${token}` },
        { query: UPSERT, variables: { input } },
      ),
    );
    const errors = (res.body as { errors?: unknown[] } | null)?.errors;
    if (!res.ok || (Array.isArray(errors) && errors.length > 0)) {
      throw new SinkError("railway_failed", `Railway rejected the upsert (HTTP ${res.status})`, res.status);
    }
    return {};
  },
};
