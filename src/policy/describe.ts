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
