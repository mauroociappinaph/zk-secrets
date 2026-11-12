import type { Operation } from "./types.ts";

/** Where a write really goes, with every identifier the provider uses; shown in the approval dialog. */
export function describeDestination(op: Operation): string {
  const target = op.target;
  switch (target.provider) {
    case "vercel":
      return (
        `vercel project ${target.projectId}${target.teamId ? ` team ${target.teamId}` : ""} ` +
        `env ${target.environments.join("+")}${target.gitBranch ? ` branch ${target.gitBranch}` : ""}`
      );
    case "aws-ssm":
    case "aws-sm":
      return (
        `${target.provider} ${target.region} ${target.prefix}${op.name}` +
        `${target.roleArn ? ` role ${target.roleArn}` : ""}${target.profile ? ` profile ${target.profile}` : ""}` +
        `${target.kmsKeyId ? ` kms ${target.kmsKeyId}` : ""}`
      );
    case "github":
      return `github ${target.repo}${target.environment ? ` env ${target.environment}` : ""} ${op.variable.sensitive ? "secret" : "variable"}`;
    case "railway":
      return `railway project ${target.projectId} env ${target.environmentId}${target.serviceId ? ` service ${target.serviceId}` : ""}`;
    case "supabase":
      return `supabase project ${target.projectRef}`;
  }
}

/** What happens after the write, so the human knows which deploys or restarts it needs. zks never triggers them. */
export function describeEffect(op: Operation): string {
  const target = op.target;
  switch (target.provider) {
    case "vercel":
      return "applies on the next deployment; redeploy to use it now";
    case "railway":
      return target.skipDeploys === true ? "applies on the next Railway deploy (skipDeploys)" : "Railway redeploys the service";
    case "github":
      return "used by the next workflow run";
    case "aws-ssm":
    case "aws-sm":
      return "consumers read it on their next fetch";
    case "supabase":
      return "Edge Functions use it on their next invocation";
  }
}

/** Operations grouped by effect, in the order each effect first appears. */
export function summarizeEffects(ops: Operation[]): Array<{ effect: string; operations: number; targets: string[] }> {
  const groups = new Map<string, { effect: string; operations: number; targets: string[] }>();
  for (const op of ops) {
    const effect = describeEffect(op);
    const group = groups.get(effect) ?? { effect, operations: 0, targets: [] };
    group.operations++;
    if (!group.targets.includes(op.targetKey)) group.targets.push(op.targetKey);
    groups.set(effect, group);
  }
  return [...groups.values()];
}
