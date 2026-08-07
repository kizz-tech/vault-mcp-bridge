import { createLocalJWKSet, jwtVerify, type JWK } from "jose";
import { hashOpaque, randomOpaque, safeEqual } from "./crypto.js";
import { pruneStore } from "./store.js";
import { DEFAULT_EDGE_LIMITS, type EdgeLimits } from "./limits.js";
import type { EdgeClock, EdgeStore } from "./types.js";

export type OwnerAuthConfig = {
  nodeEnv: "development" | "test" | "production";
  issuer?: string;
  audience?: string;
  jwks?: { keys: JWK[] };
  /** Development/test only. Never set this from a URL or renderer input. */
  devBearerToken?: string;
  devOwnerId?: string;
  ownerAuthorizationUrl?: string;
  autoApproveOwnerId?: string;
};

export type OwnerPrincipal = { ownerId: string };

/** Stable, non-PII owner key. A bare `sub` is not globally unique across
 * issuers and must never be used as the installation ownership key. */
export const canonicalOwnerId = (issuer: string, subject: string): string => {
  if (!issuer || !subject) throw new Error("owner identity is incomplete");
  return `owner_${hashOpaque(`${issuer}\u0000${subject}`)}`;
};

export class OwnerSessionCapacityError extends Error {
  constructor() {
    super("owner session capacity reached");
    this.name = "OwnerSessionCapacityError";
  }
}

export class OwnerAuthenticator {
  private readonly jwks?: ReturnType<typeof createLocalJWKSet>;

  constructor(private readonly config: OwnerAuthConfig) {
    if (config.jwks) this.jwks = createLocalJWKSet(config.jwks);
  }

  async verify(token: string | null): Promise<OwnerPrincipal | null> {
    if (!token) return null;
    if (this.config.nodeEnv !== "production" && this.config.devBearerToken && this.config.devOwnerId && safeEqual(token, this.config.devBearerToken)) {
      return { ownerId: this.config.devOwnerId };
    }
    if (this.config.nodeEnv === "production" && (!this.jwks || !this.config.issuer || !this.config.audience)) return null;
    if (!this.jwks || !this.config.issuer || !this.config.audience) return null;
    try {
      const result = await jwtVerify(token, this.jwks, {
        issuer: this.config.issuer,
        audience: this.config.audience,
        algorithms: ["RS256", "ES256", "EdDSA"],
      });
      const subject = typeof result.payload.sub === "string" ? result.payload.sub : "";
      return subject ? { ownerId: canonicalOwnerId(this.config.issuer, subject) } : null;
    } catch {
      return null;
    }
  }
}

export class OwnerSessionService {
  constructor(
    private readonly store: EdgeStore,
    private readonly now: EdgeClock = Date.now,
    private readonly ttlSeconds = 60 * 60,
    private readonly limits: EdgeLimits = DEFAULT_EDGE_LIMITS,
  ) {}

  create(ownerId: string): { value: string; expiresAt: number } {
    const now = this.now();
    pruneStore(this.store, now);
    if (this.store.ownerSessions.size >= this.limits.maxOwnerSessions) throw new OwnerSessionCapacityError();
    const value = `session_${randomOpaque(36)}`;
    this.store.ownerSessions.set(hashOpaque(value), {
      sessionHash: hashOpaque(value),
      ownerId,
      createdAt: now,
      expiresAt: now + this.ttlSeconds * 1000,
    });
    return { value, expiresAt: now + this.ttlSeconds * 1000 };
  }

  resolve(value: string | null): OwnerPrincipal | null {
    if (!value) return null;
    const hash = hashOpaque(value);
    const session = this.store.ownerSessions.get(hash);
    if (!session || session.expiresAt <= this.now()) {
      this.store.ownerSessions.delete(hash);
      return null;
    }
    return { ownerId: session.ownerId };
  }

  revoke(value: string | null): void {
    if (value) this.store.ownerSessions.delete(hashOpaque(value));
  }
}
