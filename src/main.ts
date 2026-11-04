import { randomBytes } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { readAuditAnchor } from "./audit/anchor.ts";
import { createSheetsMirror } from "./audit/mirror.ts";
import { openAuditStore } from "./audit/store.ts";
import { createMacDialogs } from "./gate/dialog.ts";
import { createExec } from "./platform/exec.ts";
import { checkIntegrity } from "./platform/integrity.ts";
import { ZKS_KEYCHAIN_SERVICE, createKeychain } from "./platform/keychain.ts";
import { zksPaths } from "./platform/paths.ts";
import { TOKEN_ACCOUNTS, run, type Deps, type ZksConfig } from "./run.ts";
import { createAwsClientFactory } from "./sinks/aws-clients.ts";
import { createSinks } from "./sinks/index.ts";

const appRoot = join(dirname(fileURLToPath(import.meta.url)), "..");

export interface Identity {
  /** Real home and user name from the OS user database, never from the environment. */
  home: string;
  user: string;
  agentId: string;
}

/** Runs zks after cli.ts has sanitized process.env. */
export async function main(identity: Identity): Promise<number> {
  process.umask(0o077);
  const paths = zksPaths(identity.home);
  const readConfig = async (): Promise<ZksConfig> => {
    try {
      return JSON.parse(await readFile(paths.configFile, "utf8")) as ZksConfig;
    } catch {
      return {};
    }
  };
  const exec = createExec({ home: identity.home, user: identity.user });
  const keychain = createKeychain(exec);
  const pkg = JSON.parse(await readFile(join(appRoot, "package.json"), "utf8")) as { version: string };

  const deps: Deps = {
    version: pkg.version,
    cwd: process.cwd(),
    user: identity.user,
    agentId: identity.agentId,
    now: () => new Date(),
    exec,
    keychain,
    human: createMacDialogs(exec),
    fetch: globalThis.fetch,
    aws: createAwsClientFactory(),
    sinks: createSinks(),
    openAudit: () => openAuditStore(paths.auditDb),
    mirror: createSheetsMirror({ fetch: globalThis.fetch, keychain, readConfig, now: () => new Date() }),
    readFile: (path) => readFile(path),
    createFile: async (path, data) => {
      try {
        await writeFile(path, data, { flag: "wx", mode: 0o644 });
        return true;
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === "EEXIST") return false;
        throw error;
      }
    },
    readConfig,
    writeConfig: async (config) => {
      await mkdir(paths.configDir, { recursive: true, mode: 0o700 });
      await writeFile(paths.configFile, `${JSON.stringify(config, null, 2)}\n`, { mode: 0o600 });
    },
    doctor: async () => {
      const which = async (tool: string) => (await exec("/usr/bin/which", [tool]).catch(() => null))?.code === 0;
      const tokens: Record<string, boolean> = {};
      for (const account of TOKEN_ACCOUNTS) tokens[account] = await keychain.has(ZKS_KEYCHAIN_SERVICE, account);
      const anchor = await readAuditAnchor(keychain).catch(() => null);
      const store = openAuditStore(paths.auditDb);
      const audit = { ...store.verify(anchor ?? undefined), anchored: anchor !== null };
      store.close();
      return {
        version: pkg.version,
        platform: process.platform,
        node: process.versions.node,
        approvalDialog: process.platform === "darwin" ? "macOS osascript" : "unavailable: every apply is denied",
        install: { root: appRoot, ...checkIntegrity(paths.integrityFile, appRoot) },
        tools: { op: await which("op"), gh: await which("gh"), aws: await which("aws") },
        tokens,
        audit: { path: paths.auditDb, ...audit },
        mirror: { sheetsWebhook: Boolean((await readConfig()).sheets?.webhookUrl) },
      };
    },
    randomBytes,
  };

  const out = await run(process.argv.slice(2), deps);
  process.stdout.write(out.stdout);
  return out.exitCode;
}
