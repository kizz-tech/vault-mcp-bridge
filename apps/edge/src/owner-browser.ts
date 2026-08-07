import { randomBytes } from "node:crypto";
import { createLocalJWKSet, jwtVerify, type JWK, type JWTPayload } from "jose";
import { canonicalOwnerId } from "./owner.js";
import { hashOpaque, pkceChallenge } from "./crypto.js";

export { canonicalOwnerId } from "./owner.js";

/** The public algorithms accepted for an owner-provider ID token. */
export const OWNER_BROWSER_ID_TOKEN_ALGORITHMS = ["RS256", "ES256", "EdDSA"] as const;

export const OWNER_BROWSER_STATE_TTL_MS = 5 * 60 * 1_000;
export const OWNER_BROWSER_STATE_CAP = 512;
export const OWNER_BROWSER_TOKEN_TIMEOUT_MS = 15 * 1_000;
export const OWNER_BROWSER_MAX_CALLBACK_BYTES = 16 * 1_024;
export const OWNER_BROWSER_MAX_RESPONSE_BYTES = 256 * 1_024;
export const OWNER_BROWSER_MAX_CODE_BYTES = 4 * 1_024;

type OwnerBrowserAlgorithm = (typeof OWNER_BROWSER_ID_TOKEN_ALGORITHMS)[number];

export type OwnerBrowserStateRecord = {
  /** PKCE verifier kept only in the bounded, ephemeral state store. */
  verifier: string;
  /** OIDC nonce kept only in the bounded, ephemeral state store. */
  nonce: string;
  /** The validated same-origin edge URL to resume after sign-in. */
  returnUrl: string;
  /** Absolute expiry (milliseconds since Unix epoch). */
  expiresAt?: number;
};

export type OwnerBrowserStateStore = {
  set(stateHash: string, record: OwnerBrowserStateRecord, now?: number): void;
  consume(stateHash: string, now?: number): OwnerBrowserStateRecord | undefined;
  prune?(now?: number): void;
};

export type MemoryOwnerBrowserStateStoreOptions = {
  maxEntries?: number;
  ttlMs?: number;
  now?: () => number;
  clock?: () => number;
};

/**
 * Small, process-local state store for the browser owner flow.
 *
 * Keys are SHA-256 hashes of the browser-visible state value. The raw state is
 * never retained by this store, which keeps accidental diagnostics or heap
 * snapshots from exposing the bearer-like correlation value.
 */
export class MemoryOwnerBrowserStateStore implements OwnerBrowserStateStore {
  private readonly records = new Map<string, OwnerBrowserStateRecord>();
  private readonly maxEntries: number;
  private readonly ttlMs: number;
  private readonly now: () => number;

  public constructor(options?: MemoryOwnerBrowserStateStoreOptions);
  public constructor(maxEntries?: number, ttlMs?: number, now?: () => number);
  public constructor(
    optionsOrMaxEntries: MemoryOwnerBrowserStateStoreOptions | number = {},
    ttlMs = OWNER_BROWSER_STATE_TTL_MS,
    now: () => number = Date.now,
  ) {
    const options = typeof optionsOrMaxEntries === "number"
      ? { maxEntries: optionsOrMaxEntries, ttlMs, now }
      : optionsOrMaxEntries;
    this.maxEntries = positiveInteger(options.maxEntries ?? OWNER_BROWSER_STATE_CAP, "maxEntries");
    this.ttlMs = positiveInteger(options.ttlMs ?? OWNER_BROWSER_STATE_TTL_MS, "ttlMs");
    this.now = options.now ?? options.clock ?? Date.now;
  }

  public get size(): number {
    return this.records.size;
  }

  public get capacity(): number {
    return this.maxEntries;
  }

  public get ttl(): number {
    return this.ttlMs;
  }

  /** Useful for diagnostics/tests; values contain no raw state. */
  public entries(): IterableIterator<readonly [string, OwnerBrowserStateRecord]> {
    return this.records.entries();
  }

  public prune(now = this.now()): void {
    for (const [stateHash, record] of this.records) {
      if (record.expiresAt === undefined || !Number.isFinite(record.expiresAt) || record.expiresAt <= now) this.records.delete(stateHash);
    }
  }

  public set(stateHash: string, record: OwnerBrowserStateRecord, now = this.now()): void {
    validateStateHash(stateHash);
    const expiresAt = record.expiresAt ?? now + this.ttlMs;
    const normalizedRecord: OwnerBrowserStateRecord = { ...record, expiresAt: Math.min(expiresAt, now + this.ttlMs) };
    validateStateRecord(normalizedRecord);
    if (normalizedRecord.expiresAt === undefined || normalizedRecord.expiresAt <= now) throw new OwnerBrowserError("state_expired", "owner browser state is already expired");
    this.prune(now);
    if (this.records.has(stateHash)) throw new OwnerBrowserError("state_collision", "owner browser state already exists");
    if (this.records.size >= this.maxEntries) throw new OwnerBrowserError("state_capacity", "owner browser state capacity reached");
    this.records.set(stateHash, normalizedRecord);
  }

  /** Map-like alias retained for embedders that call insertion `put`. */
  public put(stateHash: string, record: OwnerBrowserStateRecord, now = this.now()): void {
    this.set(stateHash, record, now);
  }

  /** Atomically removes and returns a state record. */
  public consume(stateHash: string, now = this.now()): OwnerBrowserStateRecord | undefined {
    validateStateHash(stateHash);
    this.prune(now);
    const record = this.records.get(stateHash);
    if (!record) return undefined;
    this.records.delete(stateHash);
    return { ...record };
  }

  /** Map-like alias retained for embedders that call one-use reads `take`. */
  public take(stateHash: string, now = this.now()): OwnerBrowserStateRecord | undefined {
    return this.consume(stateHash, now);
  }
}

export type OwnerBrowserFetch = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;
export type OwnerBrowserRandom = (size: number) => Uint8Array | ArrayBuffer | string;

export type OwnerBrowserIdTokenVerificationContext = {
  issuer: string;
  audience: string;
  nonce: string;
  algorithms: readonly OwnerBrowserAlgorithm[];
};

/** Optional synchronous/asynchronous verification seam for deterministic tests. */
export type OwnerBrowserIdTokenVerifier = (
  idToken: string,
  context: OwnerBrowserIdTokenVerificationContext,
) => Promise<OwnerBrowserIdTokenVerifierResult> | OwnerBrowserIdTokenVerifierResult;

export type OwnerBrowserIdTokenVerifierResult = JWTPayload | { payload: JWTPayload; protectedHeader?: { alg?: string } };

const isVerifierEnvelope = (value: OwnerBrowserIdTokenVerifierResult): value is { payload: JWTPayload; protectedHeader?: { alg?: string } } =>
  typeof value === "object" && value !== null && "payload" in value && typeof value.payload === "object" && value.payload !== null;

export type OwnerBrowserOidcBridgeOptions = {
  issuer?: string;
  ownerIssuer?: string;
  clientId?: string;
  ownerClientId?: string;
  audience?: string;
  ownerAudience?: string;
  authorizationEndpoint?: string;
  authorizationUrl?: string;
  ownerAuthorizationUrl?: string;
  tokenEndpoint?: string;
  tokenUrl?: string;
  ownerTokenEndpoint?: string;
  ownerTokenUrl?: string;
  /** Exact callback URI registered with the owner identity provider. */
  redirectUri?: string;
  callbackUri?: string;
  callbackUrl?: string;
  ownerRedirectUri?: string;
  ownerCallbackUri?: string;
  ownerCallbackUrl?: string;
  /** Origin to which a validated /oauth/authorize return URL must belong. */
  origin?: string;
  edgeOrigin?: string;
  returnOrigin?: string;
  jwks?: { keys: JWK[] } | JWK[];
  ownerJwks?: { keys: JWK[] } | JWK[];
  idTokenJwks?: { keys: JWK[] } | JWK[];
  /** Test seam; no remote JWKS resolver is ever created by this module. */
  verifyIdToken?: OwnerBrowserIdTokenVerifier;
  idTokenVerifier?: OwnerBrowserIdTokenVerifier;
  fetch?: OwnerBrowserFetch;
  fetchImpl?: OwnerBrowserFetch;
  now?: () => number;
  clock?: (() => number) | { now: () => number };
  random?: OwnerBrowserRandom;
  randomBytes?: OwnerBrowserRandom;
  stateStore?: OwnerBrowserStateStore;
  stateTtlMs?: number;
  maxStates?: number;
  tokenTimeoutMs?: number;
  timeoutMs?: number;
  maxResponseBytes?: number;
  maxCallbackBytes?: number;
  scope?: string;
  ownerScope?: string;
  /** HTTP is accepted only for an explicit loopback development deployment. */
  allowLoopbackDev?: boolean;
  allowLoopbackHttp?: boolean;
  allowInsecureLoopback?: boolean;
  allowHttpLoopback?: boolean;
  development?: boolean;
};

export type OwnerBrowserLogin = {
  authorizationUrl: string;
  /** Alias for callers that call the returned value simply `url`. */
  url: string;
  state: string;
  codeChallenge: string;
  redirectUri: string;
  callbackUrl: string;
};

export type OwnerBrowserCallbackResult = {
  ownerId: string;
  returnUrl: string;
};

export type OwnerBrowserErrorCode =
  | "configuration"
  | "invalid_return_url"
  | "invalid_callback"
  | "invalid_state"
  | "state_expired"
  | "state_capacity"
  | "state_collision"
  | "authorization_denied"
  | "invalid_code"
  | "token_timeout"
  | "token_exchange_failed"
  | "token_response_too_large"
  | "token_response_invalid"
  | "id_token_invalid";

export class OwnerBrowserError extends Error {
  public constructor(readonly code: OwnerBrowserErrorCode, message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = "OwnerBrowserError";
  }
}

const positiveInteger = (value: number, name: string): number => {
  if (!Number.isSafeInteger(value) || value < 1) throw new OwnerBrowserError("configuration", `${name} must be a positive integer`);
  return value;
};

const boundedString = (value: string, name: string, max: number): string => {
  if (value.length < 1 || value.length > max || !/^[\x21-\x7E]+$/u.test(value)) {
    throw new OwnerBrowserError("configuration", `${name} is invalid`);
  }
  return value;
};

const isLoopback = (hostname: string): boolean => {
  const normalized = hostname.toLowerCase();
  return normalized === "localhost" || normalized === "127.0.0.1" || normalized === "[::1]" || normalized === "::1";
};

const assertTransportUrl = (value: string, name: string, allowLoopbackDev: boolean, requireOrigin = false): URL => {
  let url: URL;
  try {
    url = new URL(value);
  } catch (error) {
    throw new OwnerBrowserError("configuration", `${name} must be an absolute URL`, { cause: error });
  }
  if (url.username || url.password || url.hash) throw new OwnerBrowserError("configuration", `${name} contains forbidden URL components`);
  if (url.protocol !== "https:" && !(url.protocol === "http:" && allowLoopbackDev && isLoopback(url.hostname))) {
    throw new OwnerBrowserError("configuration", `${name} must use HTTPS (or explicit loopback development HTTP)`);
  }
  if (requireOrigin && (url.pathname !== "/" && url.pathname !== "") || (requireOrigin && url.search)) {
    throw new OwnerBrowserError("configuration", `${name} must be an origin URL`);
  }
  return url;
};

const normalizeJwks = (value: { keys: JWK[] } | JWK[] | undefined): { keys: JWK[] } | undefined => {
  if (!value) return undefined;
  const keys = Array.isArray(value) ? value : value.keys;
  if (!Array.isArray(keys) || keys.length === 0) throw new OwnerBrowserError("configuration", "owner JWKS must contain keys");
  return { keys: keys.map((key) => ({ ...key })) };
};

const normalizeRandom = (random: OwnerBrowserRandom, size: number): Buffer => {
  const value = random(size);
  if (typeof value === "string") {
    const bytes = Buffer.from(value, "utf8");
    if (bytes.length === 0) throw new OwnerBrowserError("configuration", "random source returned no bytes");
    return bytes;
  }
  if (value instanceof ArrayBuffer) return Buffer.from(new Uint8Array(value));
  if (ArrayBuffer.isView(value)) return Buffer.from(value.buffer, value.byteOffset, value.byteLength);
  throw new OwnerBrowserError("configuration", "random source returned invalid bytes");
};

const randomToken = (random: OwnerBrowserRandom, bytes: number): string => {
  const value = normalizeRandom(random, bytes).toString("base64url");
  return boundedString(value, "random token", 256);
};

const validateStateHash = (stateHash: string): void => {
  if (stateHash.length < 1 || stateHash.length > 256 || !/^[\x21-\x7E]+$/u.test(stateHash)) throw new OwnerBrowserError("configuration", "state hash is invalid");
};

const validateStateRecord = (record: OwnerBrowserStateRecord): void => {
  if (!record || typeof record !== "object") throw new OwnerBrowserError("configuration", "owner browser state is invalid");
  boundedString(record.verifier, "code verifier", 256);
  boundedString(record.nonce, "nonce", 256);
  boundedString(record.returnUrl, "return URL", 16 * 1_024);
  if (record.expiresAt !== undefined && !Number.isFinite(record.expiresAt)) throw new OwnerBrowserError("configuration", "state expiry is invalid");
};

const hashState = (state: string): string => hashOpaque(state);

const singleParameter = (params: URLSearchParams, name: string, maxLength: number, required = false, allowSpaces = false): string | undefined => {
  const values = params.getAll(name);
  if (values.length > 1) throw new OwnerBrowserError("invalid_callback", `${name} is duplicated`);
  const value = values[0];
  if (required && !value) throw new OwnerBrowserError("invalid_callback", `${name} is required`);
  const pattern = allowSpaces ? /^[\x20-\x7E]+$/u : /^[\x21-\x7E]+$/u;
  if (value !== undefined && (value.length < 1 || value.length > maxLength || !pattern.test(value))) {
    throw new OwnerBrowserError("invalid_callback", `${name} is invalid`);
  }
  return value;
};

const responseHeader = (response: Response, name: string): string | null => {
  const headers = response.headers;
  if (headers && typeof headers.get === "function") return headers.get(name);
  return null;
};

const responseIsOk = (response: Response): boolean => {
  if (typeof response.ok === "boolean") return response.ok;
  return typeof response.status === "number" && response.status >= 200 && response.status < 300;
};

/**
 * Browser-facing OIDC owner sign-in seam for the edge.
 *
 * It deliberately has no HTTP routes and does not create remote JWKS
 * resolvers. The embedding edge may call `startLogin` to redirect a browser
 * and `handleCallback` from its exact callback route.
 */
export class OwnerBrowserOidcBridge {
  public readonly issuer: string;
  public readonly clientId: string;
  public readonly authorizationEndpoint: string;
  public readonly tokenEndpoint: string;
  public readonly redirectUri: string;
  public readonly origin: string;
  public readonly scope: string;

  private readonly authorizationUrl: URL;
  private readonly tokenUrl: URL;
  private readonly callbackUrl: URL;
  private readonly originUrl: URL;
  private readonly stateStore: OwnerBrowserStateStore;
  private readonly stateTtlMs: number;
  private readonly tokenTimeoutMs: number;
  private readonly maxResponseBytes: number;
  private readonly maxCallbackBytes: number;
  private readonly now: () => number;
  private readonly random: OwnerBrowserRandom;
  private readonly fetchImpl: OwnerBrowserFetch;
  private readonly verificationKeySet: ReturnType<typeof createLocalJWKSet> | undefined;
  private readonly injectedVerifier: OwnerBrowserIdTokenVerifier | undefined;
  private readonly allowLoopbackDev: boolean;

  public constructor(options: OwnerBrowserOidcBridgeOptions) {
    this.allowLoopbackDev = options.allowLoopbackDev ?? options.allowLoopbackHttp ?? options.allowInsecureLoopback ?? options.allowHttpLoopback ?? options.development ?? false;
    const clockNow = typeof options.clock === "function" ? options.clock : options.clock?.now;
    this.now = options.now ?? clockNow ?? Date.now;
    this.random = options.random ?? options.randomBytes ?? ((size) => randomBytes(size));
    this.fetchImpl = options.fetch ?? options.fetchImpl ?? ((input, init) => globalThis.fetch(input, init));
    this.stateTtlMs = positiveInteger(options.stateTtlMs ?? OWNER_BROWSER_STATE_TTL_MS, "stateTtlMs");
    this.tokenTimeoutMs = positiveInteger(options.tokenTimeoutMs ?? options.timeoutMs ?? OWNER_BROWSER_TOKEN_TIMEOUT_MS, "tokenTimeoutMs");
    this.maxResponseBytes = positiveInteger(options.maxResponseBytes ?? OWNER_BROWSER_MAX_RESPONSE_BYTES, "maxResponseBytes");
    this.maxCallbackBytes = positiveInteger(options.maxCallbackBytes ?? OWNER_BROWSER_MAX_CALLBACK_BYTES, "maxCallbackBytes");

    this.issuer = this.parseIssuer(options.issuer ?? options.ownerIssuer ?? "");
    this.clientId = boundedString(options.clientId ?? options.ownerClientId ?? options.audience ?? options.ownerAudience ?? "", "clientId", 512);
    this.authorizationUrl = assertTransportUrl(options.authorizationEndpoint ?? options.authorizationUrl ?? options.ownerAuthorizationUrl ?? "", "authorization endpoint", this.allowLoopbackDev);
    this.tokenUrl = assertTransportUrl(options.tokenEndpoint ?? options.tokenUrl ?? options.ownerTokenEndpoint ?? options.ownerTokenUrl ?? "", "token endpoint", this.allowLoopbackDev);
    if (this.authorizationUrl.searchParams.has("client_secret") || this.tokenUrl.searchParams.has("client_secret")) {
      throw new OwnerBrowserError("configuration", "public owner client endpoints must not contain client_secret");
    }
    const callbackValue = options.redirectUri ?? options.callbackUri ?? options.callbackUrl ?? options.ownerRedirectUri ?? options.ownerCallbackUri ?? options.ownerCallbackUrl ?? "";
    this.callbackUrl = assertTransportUrl(callbackValue, "redirect URI", this.allowLoopbackDev);
    this.redirectUri = this.callbackUrl.toString();
    const originValue = options.origin ?? options.edgeOrigin ?? options.returnOrigin ?? this.callbackUrl.origin;
    this.originUrl = assertTransportUrl(originValue, "edge origin", this.allowLoopbackDev, true);
    this.origin = this.originUrl.origin;
    this.authorizationEndpoint = this.authorizationUrl.toString();
    this.tokenEndpoint = this.tokenUrl.toString();
    const scope = options.scope ?? options.ownerScope ?? "openid profile";
    if (scope.length < 1 || scope.length > 1_024 || !/^[\x20-\x7E]+$/u.test(scope)) throw new OwnerBrowserError("configuration", "scope is invalid");
    this.scope = scope;

    const suppliedStore = options.stateStore;
    this.stateStore = suppliedStore ?? new MemoryOwnerBrowserStateStore({
      maxEntries: options.maxStates ?? OWNER_BROWSER_STATE_CAP,
      ttlMs: this.stateTtlMs,
      now: this.now,
    });
    this.injectedVerifier = options.verifyIdToken ?? options.idTokenVerifier;
    const jwks = normalizeJwks(options.jwks ?? options.ownerJwks ?? options.idTokenJwks);
    if (jwks) {
      try {
        this.verificationKeySet = createLocalJWKSet(jwks);
      } catch (error) {
        throw new OwnerBrowserError("configuration", "owner JWKS is invalid", { cause: error });
      }
    }
  }

  private parseIssuer(value: string): string {
    const issuerUrl = assertTransportUrl(value, "issuer", this.allowLoopbackDev);
    if (issuerUrl.search) throw new OwnerBrowserError("configuration", "issuer must not contain a query");
    if (value.trim() !== value) throw new OwnerBrowserError("configuration", "issuer must not contain surrounding whitespace");
    // Preserve the configured spelling. Issuer comparison is intentionally
    // exact, including a provider's choice of a trailing slash.
    return value;
  }

  /**
   * Creates a public authorization URL and stores only a hash of its state.
   */
  public startLogin(input: { returnUrl: string | URL }): OwnerBrowserLogin {
    const returnUrl = this.validateReturnUrl(input.returnUrl);
    const state = randomToken(this.random, 32);
    const nonce = randomToken(this.random, 32);
    const verifier = randomToken(this.random, 48);
    const codeChallenge = pkceChallenge(verifier);
    const now = this.now();
    const record: OwnerBrowserStateRecord = { verifier, nonce, returnUrl, expiresAt: now + this.stateTtlMs };
    try {
      this.stateStore.set(hashState(state), record, now);
    } catch (error) {
      if (error instanceof OwnerBrowserError) throw error;
      throw new OwnerBrowserError("state_capacity", "owner browser state capacity reached", { cause: error });
    }
    const authorization = new URL(this.authorizationUrl.toString());
    authorization.searchParams.set("response_type", "code");
    authorization.searchParams.set("client_id", this.clientId);
    authorization.searchParams.set("redirect_uri", this.redirectUri);
    authorization.searchParams.set("scope", this.scope);
    authorization.searchParams.set("state", state);
    authorization.searchParams.set("nonce", nonce);
    authorization.searchParams.set("code_challenge", codeChallenge);
    authorization.searchParams.set("code_challenge_method", "S256");
    const authorizationUrl = authorization.toString();
    return { authorizationUrl, url: authorizationUrl, state, codeChallenge, redirectUri: this.redirectUri, callbackUrl: this.redirectUri };
  }

  /**
   * Validates the exact callback route, consumes state before any token
   * exchange, and returns a canonical owner id plus the safe return URL.
   */
  public async handleCallback(callbackUrl: string | URL): Promise<OwnerBrowserCallbackResult> {
    const callback = this.parseCallback(callbackUrl);
    const state = singleParameter(callback.searchParams, "state", 512, true) as string;
    const now = this.now();
    const record = this.stateStore.consume(hashState(state), now);
    if (!record || record.expiresAt === undefined || record.expiresAt <= now) throw new OwnerBrowserError("invalid_state", "owner browser state is invalid or expired");

    const error = singleParameter(callback.searchParams, "error", 256);
    if (error) {
      const description = singleParameter(callback.searchParams, "error_description", 1_024, false, true);
      throw new OwnerBrowserError("authorization_denied", description ? `owner authorization failed: ${error}: ${description}` : `owner authorization failed: ${error}`);
    }
    const code = singleParameter(callback.searchParams, "code", OWNER_BROWSER_MAX_CODE_BYTES, true) as string;
    const tokenSet = await this.exchangeCode(code, record);
    const payload = await this.verifyIdToken(tokenSet.id_token, record.nonce);
    const subject = typeof payload.sub === "string" && payload.sub.length > 0 && payload.sub.length <= 512 ? payload.sub : undefined;
    if (!subject) throw new OwnerBrowserError("id_token_invalid", "owner ID token subject is invalid");
    return { ownerId: canonicalOwnerId(this.issuer, subject), returnUrl: record.returnUrl };
  }

  private validateReturnUrl(value: string | URL): string {
    let returnUrl: URL;
    try {
      returnUrl = new URL(value.toString());
    } catch (error) {
      throw new OwnerBrowserError("invalid_return_url", "return URL must be absolute", { cause: error });
    }
    if (returnUrl.username || returnUrl.password || returnUrl.hash || returnUrl.origin !== this.origin || returnUrl.pathname !== "/oauth/authorize") {
      throw new OwnerBrowserError("invalid_return_url", "return URL must be the same-origin /oauth/authorize route");
    }
    if (returnUrl.protocol !== "https:" && !(returnUrl.protocol === "http:" && this.allowLoopbackDev && isLoopback(returnUrl.hostname))) {
      throw new OwnerBrowserError("invalid_return_url", "return URL must use HTTPS (or explicit loopback development HTTP)");
    }
    if (returnUrl.toString().length > 16 * 1_024) throw new OwnerBrowserError("invalid_return_url", "return URL is too long");
    return returnUrl.toString();
  }

  private parseCallback(value: string | URL): URL {
    const encoded = value.toString();
    if (Buffer.byteLength(encoded, "utf8") > this.maxCallbackBytes) throw new OwnerBrowserError("invalid_callback", "callback URL is too large");
    let callback: URL;
    try {
      callback = new URL(encoded);
    } catch (error) {
      throw new OwnerBrowserError("invalid_callback", "callback URL is invalid", { cause: error });
    }
    if (callback.username || callback.password || callback.hash || callback.origin !== this.callbackUrl.origin || callback.pathname !== this.callbackUrl.pathname) {
      throw new OwnerBrowserError("invalid_callback", "callback URL does not match the registered redirect URI");
    }
    for (const [key, valuePart] of this.callbackUrl.searchParams) {
      if (callback.searchParams.get(key) !== valuePart) throw new OwnerBrowserError("invalid_callback", "callback URL does not match the registered redirect URI");
    }
    const allowedParameters = new Set(["state", "code", "error", "error_description", "error_uri", ...this.callbackUrl.searchParams.keys()]);
    for (const key of callback.searchParams.keys()) {
      if (!allowedParameters.has(key)) throw new OwnerBrowserError("invalid_callback", "callback URL contains unexpected parameters");
    }
    if (callback.protocol !== "https:" && !(callback.protocol === "http:" && this.allowLoopbackDev && isLoopback(callback.hostname))) {
      throw new OwnerBrowserError("invalid_callback", "callback URL must use HTTPS (or explicit loopback development HTTP)");
    }
    return callback;
  }

  private async exchangeCode(code: string, record: OwnerBrowserStateRecord): Promise<{ id_token: string }> {
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    const timeout = new Promise<never>((_, reject) => {
      timer = setTimeout(() => {
        controller.abort();
        reject(new OwnerBrowserError("token_timeout", "owner token exchange timed out"));
      }, this.tokenTimeoutMs);
    });
    try {
      const fetchPromise = this.fetchImpl(this.tokenEndpoint, {
        method: "POST",
        redirect: "error",
        signal: controller.signal,
        headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" },
        body: new URLSearchParams({
          grant_type: "authorization_code",
          code,
          client_id: this.clientId,
          redirect_uri: this.redirectUri,
          code_verifier: record.verifier,
        }).toString(),
      });
      const response = await Promise.race([fetchPromise, timeout]);
      if (!responseIsOk(response)) throw new OwnerBrowserError("token_exchange_failed", "owner token exchange failed");
      const contentLength = responseHeader(response, "content-length");
      if (contentLength && /^\d+$/u.test(contentLength) && Number(contentLength) > this.maxResponseBytes) {
        throw new OwnerBrowserError("token_response_too_large", "owner token response is too large");
      }
      // Keep the same deadline while reading the body. A response that sends
      // headers and then stalls must not hold the edge request indefinitely.
      const body = await Promise.race([this.readResponseBody(response), timeout]);
      let parsed: unknown;
      try {
        parsed = JSON.parse(body) as unknown;
      } catch (error) {
        throw new OwnerBrowserError("token_response_invalid", "owner token response is not valid JSON", { cause: error });
      }
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new OwnerBrowserError("token_response_invalid", "owner token response is invalid");
      const idToken = (parsed as Record<string, unknown>).id_token;
      if (typeof idToken !== "string" || idToken.length < 1 || idToken.length > this.maxResponseBytes) throw new OwnerBrowserError("token_response_invalid", "owner ID token is missing or invalid");
      return { id_token: idToken };
    } catch (error) {
      if (error instanceof OwnerBrowserError) throw error;
      if (controller.signal.aborted) throw new OwnerBrowserError("token_timeout", "owner token exchange timed out", { cause: error });
      throw new OwnerBrowserError("token_exchange_failed", "owner token exchange failed", { cause: error });
    } finally {
      if (timer !== undefined) clearTimeout(timer);
    }
  }

  private async readResponseBody(response: Response): Promise<string> {
    if (response.body && typeof response.body.getReader === "function") {
      const reader = response.body.getReader();
      const chunks: Uint8Array[] = [];
      let total = 0;
      try {
        while (true) {
          const result = await reader.read();
          if (result.done) break;
          const chunk = result.value instanceof Uint8Array ? result.value : new Uint8Array(result.value);
          total += chunk.byteLength;
          if (total > this.maxResponseBytes) {
            await reader.cancel();
            throw new OwnerBrowserError("token_response_too_large", "owner token response is too large");
          }
          chunks.push(chunk);
        }
      } catch (error) {
        if (error instanceof OwnerBrowserError) throw error;
        throw new OwnerBrowserError("token_exchange_failed", "owner token response could not be read", { cause: error });
      }
      const body = Buffer.concat(chunks.map((chunk) => Buffer.from(chunk)));
      return body.toString("utf8");
    }
    try {
      const body = typeof response.text === "function"
        ? await response.text()
        : typeof response.json === "function" ? JSON.stringify(await response.json()) : "";
      if (Buffer.byteLength(body, "utf8") > this.maxResponseBytes) throw new OwnerBrowserError("token_response_too_large", "owner token response is too large");
      return body;
    } catch (error) {
      if (error instanceof OwnerBrowserError) throw error;
      throw new OwnerBrowserError("token_exchange_failed", "owner token response could not be read", { cause: error });
    }
  }

  private async verifyIdToken(idToken: string, nonce: string): Promise<JWTPayload> {
    const context: OwnerBrowserIdTokenVerificationContext = {
      issuer: this.issuer,
      audience: this.clientId,
      nonce,
      algorithms: OWNER_BROWSER_ID_TOKEN_ALGORITHMS,
    };
    try {
      if (this.injectedVerifier) {
        const result = await this.injectedVerifier(idToken, context);
        const envelope = isVerifierEnvelope(result);
        const payload = envelope ? result.payload : result;
        const algorithm = envelope ? result.protectedHeader?.alg : undefined;
        if (algorithm !== undefined && !this.isAllowedAlgorithm(algorithm)) throw new Error("algorithm is not allowed");
        this.assertClaims(payload, nonce);
        return payload;
      }
      if (!this.verificationKeySet) throw new Error("owner JWKS is not configured");
      const result = await jwtVerify(idToken, this.verificationKeySet, {
        issuer: this.issuer,
        audience: this.clientId,
        algorithms: [...OWNER_BROWSER_ID_TOKEN_ALGORITHMS],
      });
      if (!this.isAllowedAlgorithm(result.protectedHeader.alg)) throw new Error("algorithm is not allowed");
      this.assertClaims(result.payload, nonce);
      return result.payload;
    } catch (error) {
      if (error instanceof OwnerBrowserError) throw error;
      throw new OwnerBrowserError("id_token_invalid", "owner ID token verification failed", { cause: error });
    }
  }

  private assertClaims(payload: JWTPayload, nonce: string): void {
    if (payload.iss !== this.issuer) throw new Error("issuer is not allowed");
    const audience = payload.aud;
    if (audience !== this.clientId && !(Array.isArray(audience) && audience.includes(this.clientId))) throw new Error("audience is not allowed");
    if (payload.nonce !== nonce) throw new Error("nonce is not allowed");
  }

  private isAllowedAlgorithm(value: string | undefined): value is OwnerBrowserAlgorithm {
    return typeof value === "string" && (OWNER_BROWSER_ID_TOKEN_ALGORITHMS as readonly string[]).includes(value);
  }
}

/** Compatibility alias for callers using the shorter name. */
export const OwnerBrowserBridge = OwnerBrowserOidcBridge;
