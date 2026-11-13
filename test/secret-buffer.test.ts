import assert from "node:assert/strict";
import { test } from "node:test";
import { SecretBuffer } from "../src/secret/secret-buffer.ts";

// S3 (a) of odd/tasks/zks-v0.5.0.md: raw-byte comparison without a string round trip.

test("S3: equals compares the raw bytes, including non-UTF-8 ones", () => {
  const secret = SecretBuffer.adopt(Buffer.from([0xff, 0xfe, 0x41]));
  assert.equal(secret.equals(Buffer.from([0xff, 0xfe, 0x41])), true);
  assert.equal(secret.equals(Buffer.from([0xfe, 0xff, 0x41])), false);
  assert.equal(secret.equals(Buffer.from([0xff, 0xfe])), false, "a shorter buffer");
  assert.equal(secret.equals(Buffer.from([0xff, 0xfe, 0x41, 0x0a])), false, "a longer buffer");
  assert.equal(secret.equals(Buffer.from(secret.reveal(), "utf8")), false, "the decoded text is not the same bytes");
  const other = Buffer.from([0xff, 0xfe, 0x41]);
  secret.equals(other);
  assert.deepEqual([...other], [0xff, 0xfe, 0x41], "the compared buffer is left as is");
  secret.dispose();
  assert.throws(() => secret.equals(Buffer.from([0, 0, 0])), /secret already disposed/);
});
