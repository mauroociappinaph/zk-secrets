import type { ExecResult } from "../platform/exec.ts";
import type { DockerSwarmTarget } from "../policy/types.ts";
import { SinkError, type Sink } from "./types.ts";

const SECRET_ID = /^[A-Za-z0-9]{1,64}$/;
const TIMEOUT_MS = 60_000;

function unavailable(): SinkError {
  return new SinkError("docker_unavailable", "docker is not available; install Docker and rerun ./install.sh");
}

/**
 * Docker Swarm secret through the pinned docker CLI: `docker secret create NAME -` with the value
 * on stdin. Swarm secrets are immutable, so an existing one is `secret_exists` unless the target
 * sets `replace: true` (rm, then create). docker's own output is never echoed.
 */
export const dockerSwarmSink: Sink = {
  async apply(op, value, ctx) {
    const target = op.target as DockerSwarmTarget;
    const docker = ctx.tools.docker;
    if (!docker) throw unavailable();
    const prefix = target.context ? ["--context", target.context] : [];
    const run = async (args: string[], input?: Buffer): Promise<ExecResult> => {
      try {
        return await ctx.exec(docker, [...prefix, "secret", ...args], { timeoutMs: TIMEOUT_MS, ...(input ? { input } : {}) });
      } catch {
        throw unavailable();
      }
    };

    const inspect = await run(["inspect", "--format", "{{.ID}}", op.name]);
    if (inspect.code === 0) {
      if (target.replace !== true) {
        throw new SinkError("secret_exists", `docker secret ${op.name} already exists; set replace: true on the target to remove and recreate it`);
      }
      const rm = await run(["rm", op.name]);
      if (rm.code !== 0) throw new SinkError("docker_failed", `docker secret rm ${op.name} failed (exit ${rm.code}); a service may still use it`);
    }

    const input = Buffer.from(value.reveal(), "utf8");
    let created: ExecResult;
    try {
      created = await run(["create", op.name, "-"], input);
    } finally {
      input.fill(0);
    }
    if (created.code !== 0) throw new SinkError("docker_failed", `docker secret create ${op.name} failed (exit ${created.code})`);
    const id = created.stdout.toString("utf8").trim();
    return SECRET_ID.test(id) ? { version: id } : {};
  },
};
