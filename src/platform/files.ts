import { constants, type BigIntStats } from "node:fs";
import { lstat, open, realpath, unlink } from "node:fs/promises";

/** lstat metadata of one path; never its contents. */
export interface FileInfo {
  regular: boolean;
  symlink: boolean;
  size: number;
  dev: bigint;
  ino: bigint;
}

/** The filesystem calls of `zks capture file`; the final path component is never followed. */
export interface FileIo {
  realpath(path: string): Promise<string>;
  lstat(path: string): Promise<FileInfo>;
  /**
   * Opens with O_NOFOLLOW, checks that the open file is still the regular file lstat saw (same
   * device, inode and size) and returns exactly its bytes; a partial read is zeroed before throwing.
   */
  readNoFollow(path: string, expected: FileInfo): Promise<Buffer>;
  unlink(path: string): Promise<void>;
}

/** The file was replaced or changed size between lstat and the read. */
export class FileChangedError extends Error {
  readonly code = "EFILECHANGED";
  constructor() {
    super("the file changed while it was read");
  }
}

function infoOf(stats: BigIntStats): FileInfo {
  return { regular: stats.isFile(), symlink: stats.isSymbolicLink(), size: Number(stats.size), dev: stats.dev, ino: stats.ino };
}

export function createFileIo(): FileIo {
  return {
    realpath: (path) => realpath(path),
    lstat: async (path) => infoOf(await lstat(path, { bigint: true })),
    async readNoFollow(path, expected) {
      // O_NONBLOCK: a FIFO swapped in after lstat cannot block the open.
      const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
      try {
        const now = infoOf(await handle.stat({ bigint: true }));
        if (!now.regular || now.dev !== expected.dev || now.ino !== expected.ino || now.size !== expected.size) {
          throw new FileChangedError();
        }
        // One spare byte detects a file that grew after the stat.
        const bytes = Buffer.alloc(expected.size + 1);
        let total = 0;
        try {
          while (total < bytes.length) {
            const { bytesRead } = await handle.read(bytes, total, bytes.length - total, total);
            if (bytesRead === 0) break;
            total += bytesRead;
          }
        } catch (error) {
          bytes.fill(0);
          throw error;
        }
        if (total !== expected.size) {
          bytes.fill(0);
          throw new FileChangedError();
        }
        return bytes.subarray(0, total);
      } finally {
        await handle.close();
      }
    },
    unlink: (path) => unlink(path),
  };
}
