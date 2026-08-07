import type { EdgeClock } from "./types.js";

type Bucket = { tokens: number; updatedAt: number };

/** Small in-memory guard for control-plane endpoints. It never uses forwarded
 * headers unless the caller explicitly passes a trusted-proxy address. */
export class RateGuard {
  private readonly buckets = new Map<string, Bucket>();

  constructor(
    private readonly burst: number,
    private readonly perMinute: number,
    private readonly maxKeys: number,
    private readonly now: EdgeClock = Date.now,
  ) {}

  allow(key: string): boolean {
    const timestamp = this.now();
    this.prune(timestamp);
    let bucket = this.buckets.get(key);
    if (!bucket) {
      if (this.buckets.size >= this.maxKeys) return false;
      bucket = { tokens: this.burst, updatedAt: timestamp };
      this.buckets.set(key, bucket);
    }
    const elapsed = Math.max(0, timestamp - bucket.updatedAt) / 60_000;
    bucket.tokens = Math.min(this.burst, bucket.tokens + elapsed * this.perMinute);
    bucket.updatedAt = timestamp;
    if (bucket.tokens < 1) return false;
    bucket.tokens -= 1;
    return true;
  }

  private prune(timestamp: number): void {
    const staleBefore = timestamp - 5 * 60_000;
    for (const [key, bucket] of this.buckets) if (bucket.updatedAt < staleBefore) this.buckets.delete(key);
  }
}
