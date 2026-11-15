import assert from "node:assert/strict";
import { test } from "node:test";
import { GzipCompressor, compressText, decompressText } from "../src/compression/compressor.ts";

test("gzip round-trips a buffer", () => {
  const c = new GzipCompressor();
  const input = Buffer.from("hello world ".repeat(100));
  const compressed = c.compress(input);
  assert.ok(compressed.length < input.length);
  const decompressed = c.decompress(compressed);
  assert.deepEqual(decompressed, input);
});

test("compressText round-trips", () => {
  const text = "A".repeat(1000);
  const stored = compressText(text);
  assert.ok(stored.startsWith("gz:"));
  assert.equal(decompressText(stored), text);
});

test("compressText leaves short text uncompressed", () => {
  const text = "short";
  const stored = compressText(text);
  assert.equal(stored, text);
  assert.equal(decompressText(stored), text);
});

test("decompressText passes through uncompressed text", () => {
  assert.equal(decompressText("plain text"), "plain text");
});

test("compressText handles empty string", () => {
  const stored = compressText("");
  assert.equal(stored, "");
  assert.equal(decompressText(stored), "");
});

test("gzip handles binary data", () => {
  const c = new GzipCompressor();
  const input = Buffer.from([0, 1, 2, 255, 254, 253]);
  const compressed = c.compress(input);
  const decompressed = c.decompress(compressed);
  assert.deepEqual(decompressed, input);
});
