import { gzipSync, gunzipSync } from "node:zlib";

/**
 * A compressor port: compresses and decompresses byte buffers.
 * Following Hismia's pattern: framework-free, port/adapter, domain errors.
 */
export interface Compressor {
  compress(data: Buffer): Buffer;
  decompress(data: Buffer): Buffer;
}

/** Gzip compressor using node:zlib. */
export class GzipCompressor implements Compressor {
  compress(data: Buffer): Buffer {
    return gzipSync(data, { level: 6 });
  }
  decompress(data: Buffer): Buffer {
    return gunzipSync(data);
  }
}

/** Error thrown when compression or decompression fails. */
export class CompressionError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.code = code;
    this.name = "CompressionError";
  }
}

/**
 * Compress a UTF-8 string to a base64-encoded gzip string for storage.
 * Returns the original string if compression does not reduce size.
 */
export function compressText(text: string, compressor: Compressor = new GzipCompressor()): string {
  const input = Buffer.from(text, "utf8");
  const compressed = compressor.compress(input);
  if (compressed.length >= input.length) return text;
  return "gz:" + compressed.toString("base64");
}

/**
 * Decompress a string produced by compressText. Returns the original if not compressed.
 */
export function decompressText(stored: string, compressor: Compressor = new GzipCompressor()): string {
  if (!stored.startsWith("gz:")) return stored;
  const compressed = Buffer.from(stored.slice(3), "base64");
  const decompressed = compressor.decompress(compressed);
  return decompressed.toString("utf8");
}
