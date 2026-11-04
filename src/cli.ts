// Entry point. It sanitizes process.env before any other zks or SDK module is loaded, so no
// agent-controlled variable (AWS_ENDPOINT_URL, HTTPS_PROXY, GH_HOST, ...) can redirect a write.
import { userInfo } from "node:os";
import { agentLabel, sanitizeProcessEnv } from "./platform/environment.ts";

const agentId = agentLabel(process.env);
const { homedir: home, username: user } = userInfo();
sanitizeProcessEnv(process.env, { home, user });

try {
  const { main } = await import("./main.ts");
  process.exitCode = await main({ home, user, agentId });
} catch {
  process.stdout.write(`${JSON.stringify({ ok: false, error: { code: "internal", message: "zks crashed" } })}\n`);
  process.exitCode = 1;
}
