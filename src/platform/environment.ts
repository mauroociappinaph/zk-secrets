import { SAFE_PATH, type ExecBase } from "./exec.ts";

/**
 * Empties the given environment in place and leaves only HOME, USER, LOGNAME, LANG and PATH.
 * cli.ts runs it on process.env before loading anything else, so no agent-controlled variable
 * (AWS_*, *_PROXY, NODE_*, GH_*, OP_*, XDG_*, SSL_CERT_*, ...) can redirect a write.
 */
export function sanitizeProcessEnv(env: NodeJS.ProcessEnv, base: ExecBase): void {
  for (const key of Object.keys(env)) delete env[key];
  env.HOME = base.home;
  env.USER = base.user;
  env.LOGNAME = base.user;
  env.LANG = "en_US.UTF-8";
  env.PATH = SAFE_PATH;
}

/** Self-declared agent label for the audit log: ZKS_AGENT_LABEL, then pi:<PI_SESSION_ID>, then AI_AGENT. */
export function agentLabel(env: NodeJS.ProcessEnv): string {
  if (env.ZKS_AGENT_LABEL) return env.ZKS_AGENT_LABEL;
  if (env.PI_SESSION_ID) return `pi:${env.PI_SESSION_ID}`;
  return env.AI_AGENT || "human";
}
