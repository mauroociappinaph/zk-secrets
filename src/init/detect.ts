
import { readFile } from "node:fs/promises";
import { join } from "node:path";

export interface DetectedPolicy {
  project: string;
  targets: Record<string, unknown>;
  variables: Record<string, unknown>;
  detected: string[];
}

const SENSITIVE_PATTERNS = /SECRET|KEY|TOKEN|PASSWORD|PRIVATE|CREDENTIAL|AUTH/i;

const ENV_EXAMPLE_NAMES = [".env.example", ".env.sample", ".env.template"];

async function tryRead(cwd: string, file: string): Promise<string | null> {
  try {
    return await readFile(join(cwd, file), "utf8");
  } catch {
    return null;
  }
}

export async function detectPolicy(cwd: string, project: string): Promise<DetectedPolicy> {
  const detected: string[] = [];
  const targets: Record<string, unknown> = {};
  const variables: Record<string, unknown> = {};

  const vercelJson = await tryRead(cwd, "vercel.json");
  if (vercelJson) {
    try {
      const v = JSON.parse(vercelJson);
      if (v.projectId || v.orgId) {
        targets["vercel-prod"] = {
          provider: "vercel",
          projectId: v.projectId ?? "prj_REPLACE_ME",
          teamId: v.orgId ?? "team_REPLACE_ME",
          environments: ["production", "preview"],
        };
        detected.push("vercel.json");
      }
    } catch { /* ignore */ }
  }

  const railwayToml = await tryRead(cwd, "railway.toml");
  if (railwayToml) {
    targets["railway-prod"] = {
      provider: "railway",
      projectId: "REPLACE_ME",
      environmentId: "REPLACE_ME",
      serviceId: "REPLACE_ME",
    };
    detected.push("railway.toml");
  }

  const netlifyToml = await tryRead(cwd, "netlify.toml");
  if (netlifyToml) {
    targets["netlify-prod"] = {
      provider: "netlify",
      accountId: "REPLACE_ME",
      context: "all",
    };
    detected.push("netlify.toml");
  }

  const compose = await tryRead(cwd, "docker-compose.yml") ?? await tryRead(cwd, "docker-compose.yaml");
  if (compose) {
    targets["compose-prod"] = { provider: "compose", dir: "./zks-secrets" };
    detected.push("docker-compose.yml");
  }

  let envExample: string | null = null;
  let envExampleName = "";
  for (const name of ENV_EXAMPLE_NAMES) {
    const content = await tryRead(cwd, name);
    if (content) { envExample = content; envExampleName = name; break; }
  }
  if (envExample) {
    detected.push(envExampleName);
    for (const line of envExample.split("\n")) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith("#")) continue;
      const eq = trimmed.indexOf("=");
      if (eq < 1) continue;
      const name = trimmed.slice(0, eq).trim();
      if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(name)) continue;
      const sensitive = SENSITIVE_PATTERNS.test(name);
      if (sensitive) {
        variables[name] = {
          sensitive: true,
          source: { kind: "generate", bytes: 32 },
          targets: Object.keys(targets).length > 0 ? [Object.keys(targets)[0]!] : [],
        };
      } else {
        variables[name] = {
          sensitive: false,
          value: "REPLACE_ME",
          targets: Object.keys(targets).length > 0 ? [Object.keys(targets)[0]!] : [],
        };
      }
    }
  }

  const envFile = await tryRead(cwd, ".env");
  if (envFile && Object.keys(variables).length === 0) {
    for (const line of envFile.split("\n")) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith("#")) continue;
      const eq = trimmed.indexOf("=");
      if (eq < 1) continue;
      const name = trimmed.slice(0, eq).trim();
      if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(name)) continue;
      const sensitive = SENSITIVE_PATTERNS.test(name);
      if (sensitive) {
        variables[name] = { sensitive: true, source: { kind: "generate", bytes: 32 }, targets: [] };
      } else {
        const value = trimmed.slice(eq + 1).trim().replace(/^["']|["']$/g, "");
        variables[name] = { sensitive: false, value: value || "REPLACE_ME", targets: [] };
      }
    }
    if (Object.keys(variables).length > 0) detected.push(".env");
  }

  if (Object.keys(targets).length === 0) {
    targets["vercel-prod"] = { provider: "vercel", projectId: "prj_REPLACE_ME", teamId: "team_REPLACE_ME", environments: ["production", "preview"] };
    detected.push("(no provider config found; added vercel placeholder)");
  }

  if (Object.keys(variables).length === 0) {
    variables["API_SIGNING_KEY"] = { sensitive: true, source: { kind: "generate", bytes: 32 }, targets: [Object.keys(targets)[0]!] };
    variables["NEXT_PUBLIC_SITE_URL"] = { sensitive: false, value: "https://example.com", targets: [Object.keys(targets)[0]!] };
    detected.push("(no variables found; added placeholders)");
  }

  const targetKeys = Object.keys(targets);
  if (targetKeys.length === 1) {
    for (const v of Object.values(variables)) {
      if (Array.isArray((v as any).targets) && (v as any).targets.length === 0) {
        (v as any).targets = [targetKeys[0]];
      }
    }
  }

  return { project, targets, variables, detected };
}
