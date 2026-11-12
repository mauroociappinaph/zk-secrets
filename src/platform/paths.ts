import { join } from "node:path";

export interface ZksPaths {
  configDir: string;
  configFile: string;
  integrityFile: string;
  trustFile: string;
  stateDir: string;
  auditDb: string;
}

/** zks paths under the real home directory (os.userInfo().homedir); $HOME is never used. */
export function zksPaths(home: string): ZksPaths {
  const configDir = join(home, ".config", "zks");
  const stateDir = join(home, ".local", "state", "zks");
  return {
    configDir,
    configFile: join(configDir, "config.json"),
    integrityFile: join(configDir, "integrity.json"),
    trustFile: join(configDir, "trust.json"),
    stateDir,
    auditDb: join(stateDir, "audit.db"),
  };
}

/** Root-owned install prefix written by `sudo ./install.sh --system`. */
export const SYSTEM_LIBEXEC = "/usr/local/libexec/zks";

export interface InstallLayout {
  mode: "system" | "user";
  /** System installs keep the manifest root-owned next to the app, out of the user's reach. */
  integrityFile: string;
}

export function installLayout(appRoot: string, home: string): InstallLayout {
  if (appRoot.startsWith(`${SYSTEM_LIBEXEC}/`)) return { mode: "system", integrityFile: join(SYSTEM_LIBEXEC, "integrity.json") };
  return { mode: "user", integrityFile: zksPaths(home).integrityFile };
}
