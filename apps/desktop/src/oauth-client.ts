import { createHash, randomBytes } from "node:crypto";
import { createServer, type Server } from "node:http";
import { jwtVerify, createRemoteJWKSet, type JWTPayload } from "jose";

import type { ProductConfig } from "./product-config.js";
import type { SecretStore } from "./secret-store.js";

export interface BrowserOpener {
  openExternal(url: string): Promise<void>;
}

export interface OwnerTokenProvider {
  getAccessToken(): Promise<string | undefined>;
  clear(): Promise<void>;
}

export interface OAuthTokenSet {
  readonly accessToken: string;
  readonly refreshToken?: string;
  readonly expiresAt?: number;
  readonly idToken?: string;
}

export interface OAuthTokenVerifier {
  verify(idToken: string, input: { issuer: string; audience: string; nonce: string; jwksUri: string }): Promise<JWTPayload>;
}

const TOKEN_REFERENCE = "owner.oauth.tokens";
const CALLBACK_TIMEOUT_MS = 180_000;
const MAX_CALLBACK_BYTES = 16 * 1024;

function base64url(value: Buffer): string {
  return value.toString("base64url");
}

function randomToken(bytes = 32): string {
  return base64url(randomBytes(bytes));
}

function defaultVerifier(): OAuthTokenVerifier {
  return {
    async verify(idToken, input) {
      const jwks = createRemoteJWKSet(new URL(input.jwksUri));
      const verified = await jwtVerify(idToken, jwks, {
        issuer: input.issuer,
        audience: input.audience
      });
      if (verified.payload.nonce !== input.nonce) throw new Error("oauth_nonce_invalid");
      return verified.payload;
    }
  };
}

function safeCallbackServer(): Promise<{ server: Server; callbackUrl: string; wait: Promise<URL> }> {
  return new Promise((resolve, reject) => {
    const server = createServer((request, response) => {
      if (request.method !== "GET" || (request.socket.remoteAddress !== "127.0.0.1" && request.socket.remoteAddress !== "::1")) {
        response.statusCode = 404;
        response.end();
        return;
      }
      const rawUrl = request.url ?? "/";
      if (rawUrl.length > MAX_CALLBACK_BYTES) {
        response.statusCode = 400;
        response.end();
        return;
      }
      const requestUrl = new URL(rawUrl, "http://127.0.0.1");
      if (requestUrl.pathname !== "/callback") {
        response.statusCode = 404;
        response.end();
        return;
      }
      const chunks: Buffer[] = [];
      let size = 0;
      request.on("data", (chunk: Buffer | string) => {
        size += Buffer.byteLength(chunk);
        if (size <= MAX_CALLBACK_BYTES) chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
      });
      request.on("end", () => {
        response.statusCode = 200;
        response.setHeader("content-type", "text/html; charset=utf-8");
        response.end("<!doctype html><title>Vault Bridge</title><p>You can return to Vault Bridge.</p>");
        callbackResolve?.(requestUrl);
        server.close();
      });
    });
    let callbackResolve: ((url: URL) => void) | undefined;
    let callbackReject: ((error: Error) => void) | undefined;
    const wait = new Promise<URL>((resolveWait, rejectWait) => {
      callbackResolve = resolveWait;
      callbackReject = rejectWait;
    });
    server.once("error", (error) => {
      callbackReject?.(error instanceof Error ? error : new Error("oauth_callback_failed"));
      reject(error);
    });
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      if (!address || typeof address === "string") {
        server.close();
        reject(new Error("oauth_callback_failed"));
        return;
      }
      resolve({ server, callbackUrl: `http://127.0.0.1:${address.port}/callback`, wait });
    });
  });
}

function assertClaim(value: unknown, expected: string, code: string): void {
  if (typeof value !== "string" || value !== expected) throw new Error(code);
}

function parseTokenSet(value: unknown): OAuthTokenSet {
  if (!value || typeof value !== "object") throw new Error("oauth_token_invalid");
  const candidate = value as Record<string, unknown>;
  if (typeof candidate.access_token !== "string" || candidate.access_token.length < 8 || candidate.access_token.length > 128 * 1024) {
    throw new Error("oauth_token_invalid");
  }
  const expires = typeof candidate.expires_in === "number" && Number.isFinite(candidate.expires_in)
    ? Date.now() + Math.max(0, Math.min(candidate.expires_in, 31_536_000)) * 1000
    : undefined;
  return {
    accessToken: candidate.access_token,
    ...(typeof candidate.refresh_token === "string" ? { refreshToken: candidate.refresh_token } : {}),
    ...(expires !== undefined ? { expiresAt: expires } : {}),
    ...(typeof candidate.id_token === "string" ? { idToken: candidate.id_token } : {})
  };
}

function serializeTokenSet(value: OAuthTokenSet): string {
  return JSON.stringify(value);
}

function deserializeTokenSet(value: string): OAuthTokenSet | undefined {
  try {
    const parsed: unknown = JSON.parse(value);
    if (!parsed || typeof parsed !== "object") return undefined;
    const candidate = parsed as Record<string, unknown>;
    if (typeof candidate.accessToken !== "string") return undefined;
    return {
      accessToken: candidate.accessToken,
      ...(typeof candidate.refreshToken === "string" ? { refreshToken: candidate.refreshToken } : {}),
      ...(typeof candidate.expiresAt === "number" ? { expiresAt: candidate.expiresAt } : {}),
      ...(typeof candidate.idToken === "string" ? { idToken: candidate.idToken } : {})
    };
  } catch {
    return undefined;
  }
}

export class SafeStorageOwnerTokenProvider implements OwnerTokenProvider {
  public constructor(private readonly secrets: SecretStore) {}

  async getAccessToken(): Promise<string | undefined> {
    const value = await this.secrets.get(TOKEN_REFERENCE);
    if (!value) return undefined;
    const tokens = deserializeTokenSet(value);
    if (!tokens || (tokens.expiresAt !== undefined && tokens.expiresAt <= Date.now() + 30_000)) return undefined;
    return tokens.accessToken;
  }

  async clear(): Promise<void> {
    await this.secrets.remove(TOKEN_REFERENCE);
  }
}

/**
 * Native OAuth authorization-code flow.  The callback is an ephemeral
 * loopback listener and the browser only receives public OIDC parameters.
 */
export class NativeOAuthClient implements OwnerTokenProvider {
  private readonly verifier: OAuthTokenVerifier;
  private refreshPromise: Promise<string | undefined> | undefined;

  public constructor(
    private readonly config: ProductConfig,
    private readonly secrets: SecretStore,
    private readonly opener: BrowserOpener,
    options: { verifier?: OAuthTokenVerifier; now?: () => number } = {}
  ) {
    this.verifier = options.verifier ?? defaultVerifier();
    this.now = options.now ?? Date.now;
  }

  private readonly now: () => number;

  async getAccessToken(): Promise<string | undefined> {
    const value = await this.secrets.get(TOKEN_REFERENCE);
    if (!value) return undefined;
    const tokens = deserializeTokenSet(value);
    if (!tokens) return undefined;
    if (tokens.expiresAt === undefined || tokens.expiresAt > this.now() + 30_000) return tokens.accessToken;
    if (!tokens.refreshToken) return undefined;
    if (!this.refreshPromise) {
      this.refreshPromise = this.refresh(tokens).finally(() => { this.refreshPromise = undefined; });
    }
    return this.refreshPromise;
  }

  async clear(): Promise<void> {
    await this.secrets.remove(TOKEN_REFERENCE);
  }

  async connect(): Promise<void> {
    const callback = await safeCallbackServer();
    const state = randomToken();
    const nonce = randomToken();
    const verifier = randomToken(48);
    const challenge = createHash("sha256").update(verifier, "ascii").digest("base64url");
    const authorization = new URL(this.config.ownerAuthorizationEndpoint);
    authorization.searchParams.set("response_type", "code");
    authorization.searchParams.set("client_id", this.config.ownerClientId);
    authorization.searchParams.set("redirect_uri", callback.callbackUrl);
    authorization.searchParams.set("scope", this.config.ownerScope ?? "openid profile");
    authorization.searchParams.set("state", state);
    authorization.searchParams.set("nonce", nonce);
    authorization.searchParams.set("code_challenge", challenge);
    authorization.searchParams.set("code_challenge_method", "S256");
      let raceTimer: NodeJS.Timeout | undefined;
      try {
        await this.opener.openExternal(authorization.toString());
        const responseUrl = await Promise.race([
          callback.wait,
          new Promise<URL>((_, reject) => { raceTimer = setTimeout(() => reject(new Error("oauth_timeout")), CALLBACK_TIMEOUT_MS); })
      ]);
      assertClaim(responseUrl.searchParams.get("state"), state, "oauth_state_invalid");
      const error = responseUrl.searchParams.get("error");
      if (error) throw new Error("oauth_authorization_denied");
      const code = responseUrl.searchParams.get("code");
      if (!code || code.length > 4096) throw new Error("oauth_code_invalid");
      const tokenResponse = await fetch(this.config.ownerTokenEndpoint, {
        method: "POST",
        redirect: "error",
        headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" },
        body: new URLSearchParams({
          grant_type: "authorization_code",
          code,
          client_id: this.config.ownerClientId,
          redirect_uri: callback.callbackUrl,
          code_verifier: verifier
        })
      });
      if (!tokenResponse.ok) throw new Error("oauth_token_exchange_failed");
      const body = await tokenResponse.text();
      if (Buffer.byteLength(body, "utf8") > MAX_CALLBACK_BYTES * 8) throw new Error("oauth_token_invalid");
      const tokens = parseTokenSet(JSON.parse(body) as unknown);
      if (!tokens.idToken) throw new Error("oauth_id_token_required");
      const claims = await this.verifier.verify(tokens.idToken, {
        issuer: this.config.ownerIssuer,
        audience: this.config.ownerClientId,
        nonce,
        jwksUri: this.config.ownerJwksUri
      });
      assertClaim(claims.iss, this.config.ownerIssuer, "oauth_issuer_invalid");
      const audience = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
      if (!audience.includes(this.config.ownerClientId)) throw new Error("oauth_audience_invalid");
      assertClaim(claims.nonce, nonce, "oauth_nonce_invalid");
      await this.secrets.put(TOKEN_REFERENCE, serializeTokenSet({ accessToken: tokens.accessToken, ...(tokens.refreshToken ? { refreshToken: tokens.refreshToken } : {}), ...(tokens.idToken ? { idToken: tokens.idToken } : {}), expiresAt: tokens.expiresAt ?? this.now() + 3600_000 }));
    } finally {
      if (raceTimer) clearTimeout(raceTimer);
      callback.server.close();
    }
  }

  static tokenReference(): string {
    return TOKEN_REFERENCE;
  }

  private async refresh(previous: OAuthTokenSet): Promise<string | undefined> {
    if (!previous.refreshToken) return undefined;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 15_000);
    try {
      const response = await fetch(this.config.ownerTokenEndpoint, {
        method: "POST",
        redirect: "error",
        signal: controller.signal,
        headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" },
        body: new URLSearchParams({
          grant_type: "refresh_token",
          refresh_token: previous.refreshToken,
          client_id: this.config.ownerClientId
        })
      });
      if (!response.ok) return undefined;
      const body = await response.text();
      if (Buffer.byteLength(body, "utf8") > MAX_CALLBACK_BYTES * 8) return undefined;
      const next = parseTokenSet(JSON.parse(body) as unknown);
      const stored: OAuthTokenSet = {
        accessToken: next.accessToken,
        refreshToken: next.refreshToken ?? previous.refreshToken,
        expiresAt: next.expiresAt ?? this.now() + 3600_000,
        ...(next.idToken ? { idToken: next.idToken } : previous.idToken ? { idToken: previous.idToken } : {})
      };
      await this.secrets.put(TOKEN_REFERENCE, serializeTokenSet(stored));
      return stored.accessToken;
    } catch {
      return undefined;
    } finally {
      clearTimeout(timeout);
    }
  }
}

export { TOKEN_REFERENCE };
