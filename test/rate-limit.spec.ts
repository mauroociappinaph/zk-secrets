import assert from "node:assert/strict";
import { test } from "node:test";
import { TokenBucketRateLimiter, checkRateLimit, policyFor, RateLimitError } from "../src/rate-limit/rate-limiter.ts";

test("token bucket allows hits up to the limit", () => {
  const limiter = new TokenBucketRateLimiter();
  for (let i = 0; i < 5; i++) {
    const r = limiter.hit("k", 5, 60_000);
    assert.equal(r.allowed, true);
  }
  const r = limiter.hit("k", 5, 60_000);
  assert.equal(r.allowed, false);
  assert.equal(r.remaining, 0);
});

test("token bucket resets after the window", async () => {
  const limiter = new TokenBucketRateLimiter();
  for (let i = 0; i < 3; i++) limiter.hit("k", 3, 50);
  assert.equal(limiter.hit("k", 3, 50).allowed, false);
  await new Promise((r) => setTimeout(r, 60));
  assert.equal(limiter.hit("k", 3, 50).allowed, true);
});

test("token bucket tracks keys independently", () => {
  const limiter = new TokenBucketRateLimiter();
  for (let i = 0; i < 2; i++) limiter.hit("a", 2, 60_000);
  assert.equal(limiter.hit("a", 2, 60_000).allowed, false);
  assert.equal(limiter.hit("b", 2, 60_000).allowed, true);
});

test("reset clears a key", () => {
  const limiter = new TokenBucketRateLimiter();
  for (let i = 0; i < 2; i++) limiter.hit("k", 2, 60_000);
  assert.equal(limiter.hit("k", 2, 60_000).allowed, false);
  limiter.reset("k");
  assert.equal(limiter.hit("k", 2, 60_000).allowed, true);
});

test("policyFor returns the matching policy", () => {
  const p = policyFor("provider:vercel");
  assert.ok(p);
  assert.equal(p.name, "provider-api");
  assert.equal(policyFor("unknown:key"), undefined);
});

test("checkRateLimit throws RateLimitError when exceeded", () => {
  const limiter = new TokenBucketRateLimiter();
  for (let i = 0; i < 10; i++) limiter.hit("apply:x", 10, 60_000);
  assert.throws(() => checkRateLimit(limiter, "apply:x"), (e: unknown) => {
    assert.ok(e instanceof RateLimitError);
    assert.equal((e as RateLimitError).code, "rate_limited");
    return true;
  });
});

test("checkRateLimit is a no-op for unknown keys", () => {
  const limiter = new TokenBucketRateLimiter();
  assert.doesNotThrow(() => checkRateLimit(limiter, "unknown:key"));
});
