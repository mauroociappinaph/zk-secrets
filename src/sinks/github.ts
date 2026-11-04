import type { GithubTarget } from "../policy/types.ts";
import { SinkError, type Sink } from "./types.ts";

/**
 * GitHub Actions secrets (sensitive) or variables (plain) through the authenticated `gh` CLI.
 * The value goes on stdin; gh reads the body from stdin when --body is absent.
 */
export const githubSink: Sink = {
  async apply(op, value, ctx) {
    const target = op.target as GithubTarget;
    const kind = op.variable.sensitive ? "secret" : "variable";
    const args = [kind, "set", op.name, "--repo", target.repo];
    if (target.environment) args.push("--env", target.environment);

    const input = Buffer.from(value.reveal(), "utf8");
    try {
      const res = await ctx.exec("gh", args, { input, timeoutMs: 60_000 }).catch(() => null);
      if (!res) throw new SinkError("github_unavailable", "GitHub CLI (gh) is not available");
      if (res.code !== 0) throw new SinkError("github_failed", `gh ${kind} set exited ${res.code}`);
      return {};
    } finally {
      input.fill(0);
    }
  },
};
