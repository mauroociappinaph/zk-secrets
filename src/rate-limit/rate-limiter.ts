import { SinkError } from "../sinks/types.ts";

/**
 * A rate limiter port: limits how many times a key can be hit within a time window.
 * Following Hismia's pattern: framework-free, port/adapter, domain errors.
 */
export interface RateLimitResult {
  readonly allowed: boolean;
  readonly remaining: number;
  readonly resetAt: number;
}

export interface RateLimiter {
  /** Record a hit for `key`. Returns whether the hit is allowed. */
  hit(key: string, limit: number, windowMs: number): RateLimitResult;
  /** Reset the counter for a key (for testing or manual intervention). */
  reset(key: string): void;
}

/**
 * Token bucket rate limiter: allows `limit` hits per `windowMs` milliseconds.
 * Tokens refill at a constant rate; a hit consumes one token.
 */
export class TokenBucketRateLimiter implements RateLimiter {
  private readonly buckets = new Map<string, { tokens: number; lastRefill: number }>();

  hit(key: string, limit: number, windowMs: number): RateLimitResult {
    const now = Date.now();
    let bucket = this.buckets.get(key);
    if (!bucket) {
      bucket = { tokens: limit, lastRefill: now };
      this.buckets.set(key, bucket);
    }

    // Refill tokens based on elapsed time.
    const elapsed = now - bucket.lastRefill;
    const refill = Math.floor((elapsed / windowMs) * limit);
    if (refill > 0) {
      bucket.tokens = Math.min(limit, bucket.tokens + refill);
      bucket.lastRefill = now;
    }

    if (bucket.tokens <= 0) {
      const resetAt = bucket.lastRefill + windowMs;
      return { allowed: false, remaining: 0, resetAt };
    }

    bucket.tokens -= 1;
    const resetAt = bucket.lastRefill + windowMs;
    return { allowed: true, remaining: bucket.tokens, resetAt };
  }

  reset(key: string): void {
    this.buckets.delete(key);
  }
}

/** Error thrown when a rate limit is exceeded. */
export class RateLimitError extends SinkError {
  readonly resetAt: number;
  constructor(key: string, resetAt: number) {
    super("rate_limited", `Rate limit exceeded for ${key}; retry after ${new Date(resetAt).toISOString()}`, 429);
    this.resetAt = resetAt;
  }
}

/**
 * Rate limit policies following Hismia's pattern: framework-free, named policies
 * with a max, time window, and an appliesTo predicate.
 */
export interface RateLimitPolicy {
  readonly name: string;
  readonly max: number;
  readonly windowMs: number;
  readonly appliesTo: (key: string) => boolean;
}

export const RATE_LIMIT_POLICIES: readonly RateLimitPolicy[] = [
  {
    name: "provider-api",
    max: 60,
    windowMs: 60_000,
    appliesTo: (key) => key.startsWith("provider:"),
  },
  {
    name: "apply",
    max: 100,
    windowMs: 60_000,
    appliesTo: (key) => key.startsWith("apply:"),
  },
  {
    name: "capture",
    max: 20,
    windowMs: 60_000,
    appliesTo: (key) => key.startsWith("capture:"),
  },
];

/** Find the policy that applies to a key, or undefined. */
export function policyFor(key: string): RateLimitPolicy | undefined {
  return RATE_LIMIT_POLICIES.find((p) => p.appliesTo(key));
}

/** Check a key against its policy using the given limiter. Throws RateLimitError if exceeded. */
export function checkRateLimit(limiter: RateLimiter, key: string): void {
  const policy = policyFor(key);
  if (!policy) return;
  const result = limiter.hit(key, policy.max, policy.windowMs);
  if (!result.allowed) throw new RateLimitError(key, result.resetAt);
}
