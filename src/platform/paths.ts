import { homedir } from "node:os";
import { join } from "node:path";

export interface ZksPaths {
  configDir: string;
  configFile: string;
  integrityFile: string;
  stateDir: string;
  auditDb: string;
}

export function zksPaths(home: string = homedir()): ZksPaths {
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
