import type { RateLimitConfig, RateLimitStatus } from './types.js';

/**
 * Token Bucket Rate Limiter
 *
 * Each host gets an independent bucket.
 * Tokens refill at `requestsPerMinute` rate.
 * `burstSize` defines the maximum bucket capacity (allows short bursts).
 *
 * Usage:
 *   const limiter = new RateLimiter({ requestsPerMinute: 60, burstSize: 10 });
 *   limiter.check('api.stripe.com')   // peek without consuming
 *   limiter.consume('api.stripe.com') // consume one token
 */

interface Bucket {
  tokens: number;
  lastRefill: number; // epoch ms
}

function refillBucket(bucket: Bucket, config: RateLimitConfig, nowMs: number): void {
  const elapsedMinutes = (nowMs - bucket.lastRefill) / 60_000;
  const newTokens = elapsedMinutes * config.requestsPerMinute;
  bucket.tokens = Math.min(config.burstSize, bucket.tokens + newTokens);
  bucket.lastRefill = nowMs;
}

function msUntilNextToken(bucket: Bucket, config: RateLimitConfig): number {
  // How many ms until 1 token refills
  const tokensNeeded = 1 - bucket.tokens;
  if (tokensNeeded <= 0) return 0;
  return Math.ceil((tokensNeeded / config.requestsPerMinute) * 60_000);
}

export class RateLimiter {
  private readonly buckets = new Map<string, Bucket>();
  private readonly perHost: Record<string, RateLimitConfig>;
  private readonly defaultConfig: RateLimitConfig;

  constructor(
    defaultConfig: RateLimitConfig,
    perHost: Record<string, RateLimitConfig> = {},
  ) {
    this.defaultConfig = defaultConfig;
    this.perHost = perHost;
  }

  private configFor(host: string): RateLimitConfig {
    return this.perHost[host] ?? this.defaultConfig;
  }

  private getBucket(host: string, nowMs: number): Bucket {
    const config = this.configFor(host);
    let bucket = this.buckets.get(host);
    if (!bucket) {
      bucket = { tokens: config.burstSize, lastRefill: nowMs };
      this.buckets.set(host, bucket);
    }
    refillBucket(bucket, config, nowMs);
    return bucket;
  }

  /**
   * Check whether the next request to `host` would be allowed.
   * Does NOT consume a token.
   */
  check(host: string): RateLimitStatus {
    const nowMs = Date.now();
    const config = this.configFor(host);
    const bucket = this.getBucket(host, nowMs);
    const allowed = bucket.tokens >= 1;
    const waitMs = allowed ? 0 : msUntilNextToken(bucket, config);
    return {
      allowed,
      remaining: Math.max(0, Math.floor(bucket.tokens)),
      resetAt: new Date(nowMs + waitMs),
    };
  }

  /**
   * Attempt to consume one token for `host`.
   * Returns true if the request is allowed, false if rate limited.
   */
  consume(host: string): boolean {
    const nowMs = Date.now();
    const bucket = this.getBucket(host, nowMs);
    if (bucket.tokens < 1) return false;
    bucket.tokens -= 1;
    return true;
  }

  /**
   * Reset the bucket for a host (useful for tests).
   */
  reset(host: string): void {
    this.buckets.delete(host);
  }
}
