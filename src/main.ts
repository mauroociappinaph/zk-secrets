import { randomBytes } from "node:crypto";
import { accessSync, constants, readFileSync, statSync } from "node:fs";
import { chmod, mkdir, readFile, writeFile } from "node:fs/promises";
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
import { NO_PINS, TOOLS_FILE, parseToolPins, pinnedExec, resolveTools, sha256File, type ToolPaths, type ToolPins } from "./platform/tools.ts";
import { loadTrust, type TrustFile } from "./policy/trust.ts";
import { TOKEN_ACCOUNTS, run, type Deps, type ZksConfig } from "./run.ts";
import { createAwsClientFactory } from "./sinks/aws-clients.ts";
import { createSinks } from "./sinks/index.ts";

const appRoot = join(dirname(fileURLToPath(import.meta.url)), "..");

function isExecutableFile(path: string): boolean {
  try {
    accessSync(path, constants.X_OK);
    return statSync(path).isFile();
  } catch {
    return false;
  }
}

/** <install>/tools.json from install.sh; a development checkout has none and looks on SAFE_PATH. */
function loadTools(): { tools: ToolPaths; pins: ToolPins; source: "tools.json" | "safe-path" } {
  let text: string | null = null;
  try {
    text = readFileSync(join(appRoot, TOOLS_FILE), "utf8");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") text = "";
  }
  return {
    tools: resolveTools(text, isExecutableFile),
    pins: text === null ? { ...NO_PINS } : parseToolPins(text),
    source: text === null ? "safe-path" : "tools.json",
  };
}

/** Per tool: "ok" (hash matches), "changed", "unpinned" (legacy tools.json or dev run) or "missing". */
async function pinStatus(tools: ToolPaths, pins: ToolPins): Promise<Record<string, string>> {
  const names: Record<keyof ToolPaths, string> = { egoBrowser: "ego-browser", gh: "gh", op: "op" };
  const status: Record<string, string> = {};
  for (const key of Object.keys(names) as (keyof ToolPaths)[]) {
    const path = tools[key];
    const pin = pins[key];
    if (path === null) status[names[key]] = "missing";
    else if (pin === null) status[names[key]] = "unpinned";
    else status[names[key]] = (await sha256File(path).catch(() => null)) === pin ? "ok" : "changed";
  }
  return status;
}

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
  const readTrust = async (): Promise<TrustFile | null> => {
    let text: string;
    try {
      text = await readFile(paths.trustFile, "utf8");
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
      throw error;
    }
    try {
      return JSON.parse(text) as TrustFile;
    } catch {
      // Unparsable: an unsigned empty file, which loadTrust reports as invalid.
      return { version: 1, destinations: [], mac: "" };
    }
  };
  const { tools, pins, source: toolsSource } = loadTools();
  // gh, op and ego-browser run only while their binary keeps the sha256 install.sh pinned.
  const exec = pinnedExec(createExec({ home: identity.home, user: identity.user }), tools, pins, {
    hashFile: sha256File,
    warn: (line) => void process.stderr.write(line),
  });
  const keychain = createKeychain(exec);
  const pkg = JSON.parse(await readFile(join(appRoot, "package.json"), "utf8")) as { version: string };

  const deps: Deps = {
    version: pkg.version,
    cwd: process.cwd(),
    user: identity.user,
    agentId: identity.agentId,
    now: () => new Date(),
    exec,
    tools,
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
    readTrust,
    writeTrust: async (file) => {
      await mkdir(paths.configDir, { recursive: true, mode: 0o700 });
      await writeFile(paths.trustFile, `${JSON.stringify(file, null, 2)}\n`, { mode: 0o600 });
      await chmod(paths.trustFile, 0o600);
    },
    doctor: async () => {
      const which = async (tool: string) => (await exec("/usr/bin/which", [tool]).catch(() => null))?.code === 0;
      const tokens: Record<string, boolean> = {};
      for (const account of TOKEN_ACCOUNTS) tokens[account] = await keychain.has(ZKS_KEYCHAIN_SERVICE, account);
      const anchor = await readAuditAnchor(keychain).catch(() => null);
      const store = openAuditStore(paths.auditDb);
      const audit = { ...store.verify(anchor ?? undefined), anchored: anchor !== null };
      store.close();
      const trust = await loadTrust({ keychain, readTrust, writeTrust: async () => undefined }).catch(() => ({ valid: false, destinations: [] }));
      return {
        version: pkg.version,
        platform: process.platform,
        node: process.versions.node,
        approvalDialog: process.platform === "darwin" ? "macOS osascript" : "unavailable: every apply is denied",
        install: { root: appRoot, ...checkIntegrity(paths.integrityFile, appRoot) },
        tools: {
          source: toolsSource,
          "ego-browser": tools.egoBrowser !== null && isExecutableFile(tools.egoBrowser),
          op: tools.op !== null && isExecutableFile(tools.op),
          gh: tools.gh !== null && isExecutableFile(tools.gh),
          aws: await which("aws"),
          pins: await pinStatus(tools, pins),
        },
        tokens,
        audit: { path: paths.auditDb, ...audit },
        mirror: { sheetsWebhook: Boolean((await readConfig()).sheets?.webhookUrl) },
        trust: trust.valid ? "ok" : "invalid",
        trustedDestinations: trust.destinations.length,
      };
    },
    randomBytes,
  };

  const out = await run(process.argv.slice(2), deps);
  process.stdout.write(out.stdout);
  return out.exitCode;
}
