import { createHash } from "node:crypto";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative } from "node:path";

export interface IntegrityManifest {
  version: string;
  root: string;
  digest: string;
  files: number;
}

/** Walks root and returns one SHA-256 over every file path and content, in sorted order. */
export function digestTree(root: string): { digest: string; files: number } {
  const paths: string[] = [];
  const walk = (dir: string) => {
    for (const entry of readdirSync(dir).sort()) {
      const full = join(dir, entry);
      const stat = statSync(full);
      if (stat.isDirectory()) walk(full);
      else if (stat.isFile()) paths.push(full);
    }
  };
  walk(root);
  const hash = createHash("sha256");
  for (const path of paths) {
    hash.update(relative(root, path));
    hash.update("\0");
    hash.update(createHash("sha256").update(readFileSync(path)).digest());
  }
  return { digest: hash.digest("hex"), files: paths.length };
}

export function checkIntegrity(manifestPath: string, appRoot: string): Record<string, unknown> {
  let manifest: IntegrityManifest;
  try {
    manifest = JSON.parse(readFileSync(manifestPath, "utf8")) as IntegrityManifest;
  } catch {
    return { status: "not-installed", detail: "no integrity manifest; run ./install.sh" };
  }
  if (manifest.root !== appRoot) return { status: "not-installed", detail: `running from ${appRoot}, installed at ${manifest.root}` };
  const current = digestTree(appRoot);
  return {
    status: current.digest === manifest.digest ? "ok" : "mismatch",
    files: current.files,
    expectedFiles: manifest.files,
  };
}
