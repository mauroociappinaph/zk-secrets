import { join } from "node:path";

export interface ZksPaths {
  configDir: string;
  configFile: string;
  integrityFile: string;
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
    stateDir,
    auditDb: join(stateDir, "audit.db"),
  };
}
