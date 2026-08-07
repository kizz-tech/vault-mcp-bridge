import { createLocalJWKSet, exportJWK, generateKeyPair, jwtVerify, SignJWT, type JWK, type KeyInput } from "jose";
import { OAuthVerificationBundleSchema, type OAuthVerificationBundle } from "@vault-mcp-bridge/contracts";
import { hashOpaque, iso, pkceChallenge, randomOpaque } from "./crypto.js";
import { pruneStore } from "./store.js";
import { DEFAULT_EDGE_LIMITS, resolveLimits, type EdgeLimits } from "./limits.js";
import type { EdgeClock, EdgeStore, InstallationRecord, RegisteredClient } from "./types.js";

export const OAUTH_SCOPE = "vault:read";
export const ACCESS_TOKEN_TTL_SECONDS = 600;
export const REFRESH_TOKEN_TTL_SECONDS = 30 * 24 * 60 * 60;
export const AUTHORIZATION_CODE_TTL_SECONDS = 300;

export class OAuthError extends Error {
  constructor(
    readonly error: string,
    message: string,
    readonly statusCode = 400,
    readonly safeToRedirect = false,
  ) {
    super(message);
    this.name = "OAuthError";
  }
}

export type OAuthServiceOptions = {
  store: EdgeStore;
  issuer: string;
  now?: EdgeClock;
  /** Production callers provide a durable key-store result. */
  signingKey?: {
    privateKey: KeyInput;
    publicJwk: JWK;
  };
  limits?: Partial<EdgeLimits>;
  accessTokenTtlSeconds?: number;
  refreshTokenTtlSeconds?: number;
  authorizationCodeTtlSeconds?: number;
};

export type RegisterClientInput = {
  installationId: string;
  clientName?: string;
  redirectUris: string[];
  grantTypes?: string[];
  responseTypes?: string[];
  tokenEndpointAuthMethod?: string;
  resource: string;
};

export type AuthorizeInput = {
  installation: InstallationRecord;
  clientId: string;
  redirectUri: string;
  responseType: string;
  scope: string;
  state?: string;
  codeChallenge: string;
  codeChallengeMethod: string;
  resource: string;
  nonce?: string;
  ownerId: string;
};

export type TokenResponse = {
  access_token: string;
  token_type: "Bearer";
  expires_in: number;
  refresh_token: string;
  scope: string;
};

export type VerifiedAccessToken = {
  subject: string;
  installationId: string;
  vaultId: string;
  clientId: string;
  resource: string;
  scope: string;
  jti: string;
  revocationEpoch: number;
  issuedAt: number;
  expiresAt: number;
};

/** The edge process is deliberately a single writer for OAuth mutations.
 * Keep the queue keyed by the store object so two OAuthService instances in
 * one process cannot interleave issue/refresh/revoke updates. Durable store
 * flushes happen inside the mutation that requires them, preserving the same
 * ordering at the persistence boundary. */
const mutationChains = new WeakMap<EdgeStore, Promise<void>>();

const withMutation = async <T>(store: EdgeStore, operation: () => Promise<T>): Promise<T> => {
  const previous = mutationChains.get(store) ?? Promise.resolve();
  const queued = previous.then(operation, operation);
  const settled = queued.then(() => undefined, () => undefined);
  mutationChains.set(store, settled);
  return queued;
};

const flushStore = async (store: EdgeStore): Promise<void> => {
  if (store.flush) await store.flush();
};

const epochOf = (client: RegisteredClient): number => {
  const epoch = client.revocationEpoch;
  return typeof epoch === "number" && Number.isSafeInteger(epoch) && epoch >= 0 ? epoch : 0;
};

const isLoopback = (hostname: string): boolean => hostname === "localhost" || hostname === "127.0.0.1" || hostname === "[::1]";

const validateRedirectUri = (value: string): string => {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new OAuthError("invalid_client_metadata", "redirect URI is not a valid URL");
  }
  if (url.hash || url.username || url.password) throw new OAuthError("invalid_client_metadata", "redirect URI contains forbidden components");
  if (url.protocol !== "https:" && !(url.protocol === "http:" && isLoopback(url.hostname))) {
    throw new OAuthError("invalid_client_metadata", "redirect URI must use HTTPS or loopback HTTP");
  }
  return url.toString();
};

const normalizeScope = (scope: string): string => {
  const values = [...new Set(scope.trim().split(/\s+/u).filter(Boolean))];
  if (values.length === 0) return OAUTH_SCOPE;
  if (values.length !== 1 || values[0] !== OAUTH_SCOPE) throw new OAuthError("invalid_scope", "only vault:read is supported", 400, true);
  return OAUTH_SCOPE;
};

const requireBounded = (value: string | undefined, label: string, min: number, max: number): string => {
  if (!value || value.length < min || value.length > max || !/^[\x21-\x7E]+$/u.test(value)) {
    throw new OAuthError("invalid_request", `${label} is invalid`, 400, true);
  }
  return value;
};

const toPublicJwk = (key: JWK): OAuthVerificationBundle["keys"][number] => {
  const clone = { ...key } as Record<string, unknown>;
  delete clone.d;
  delete clone.p;
  delete clone.q;
  delete clone.dp;
  delete clone.dq;
  delete clone.qi;
  delete clone.oth;
  return clone as OAuthVerificationBundle["keys"][number];
};

export class OAuthService {
  readonly issuer: string;
  readonly publicJwk: OAuthVerificationBundle["keys"][number];
  private readonly privateKey: KeyInput;
  private readonly verificationKeySet: ReturnType<typeof createLocalJWKSet>;
  private readonly now: EdgeClock;
  private readonly accessTokenTtlSeconds: number;
  private readonly refreshTokenTtlSeconds: number;
  private readonly authorizationCodeTtlSeconds: number;
  private readonly limits: EdgeLimits;

  private constructor(
    private readonly store: EdgeStore,
    private readonly options: OAuthServiceOptions,
    privateKey: KeyInput,
    publicJwk: OAuthVerificationBundle["keys"][number],
  ) {
    this.issuer = options.issuer;
    this.privateKey = privateKey;
    this.publicJwk = publicJwk;
    this.verificationKeySet = createLocalJWKSet({ keys: [publicJwk] as unknown as JWK[] });
    this.now = options.now ?? Date.now;
    this.accessTokenTtlSeconds = options.accessTokenTtlSeconds ?? ACCESS_TOKEN_TTL_SECONDS;
    this.refreshTokenTtlSeconds = options.refreshTokenTtlSeconds ?? REFRESH_TOKEN_TTL_SECONDS;
    this.authorizationCodeTtlSeconds = options.authorizationCodeTtlSeconds ?? AUTHORIZATION_CODE_TTL_SECONDS;
    this.limits = resolveLimits(options.limits ?? DEFAULT_EDGE_LIMITS);
  }

  static async create(options: OAuthServiceOptions): Promise<OAuthService> {
    if (options.signingKey) {
      const publicJwk = toPublicJwk(options.signingKey.publicJwk);
      if (typeof publicJwk.kid !== "string" || publicJwk.kid.length < 1) throw new Error("signing key has no kid");
      publicJwk.use = "sig";
      publicJwk.alg = "EdDSA";
      return new OAuthService(options.store, options, options.signingKey.privateKey, publicJwk);
    }
    const { privateKey, publicKey } = await generateKeyPair("EdDSA");
    const publicJwk = toPublicJwk(await exportJWK(publicKey));
    publicJwk.kid = `edge_${randomOpaque(12)}`;
    publicJwk.use = "sig";
    publicJwk.alg = "EdDSA";
    return new OAuthService(options.store, options, privateKey, publicJwk);
  }

  registerClient(input: RegisterClientInput): RegisteredClient {
    pruneStore(this.store, this.now());
    if (!input.installationId || !input.resource) throw new OAuthError("invalid_client_metadata", "installation and resource are required");
    if (this.store.clients.size >= this.limits.maxClientsTotal || [...this.store.clients.values()].filter((client) => client.installationId === input.installationId).length >= this.limits.maxClientsPerInstallation) {
      throw new OAuthError("server_error", "edge capacity is temporarily unavailable", 503, false);
    }
    const redirectUris = [...new Set(input.redirectUris.map(validateRedirectUri))];
    if (redirectUris.length === 0 || redirectUris.length > 32) throw new OAuthError("invalid_client_metadata", "redirect_uris is required");
    const grantTypes = input.grantTypes ?? ["authorization_code", "refresh_token"];
    const responseTypes = input.responseTypes ?? ["code"];
    if (!grantTypes.includes("authorization_code") || !responseTypes.includes("code")) {
      throw new OAuthError("invalid_client_metadata", "authorization code flow is required");
    }
    if (input.tokenEndpointAuthMethod && input.tokenEndpointAuthMethod !== "none") {
      throw new OAuthError("invalid_client_metadata", "only public PKCE clients are supported");
    }
    const clientId = `client_${randomOpaque(24)}`;
    const client: RegisteredClient = {
      clientId,
      installationId: input.installationId,
      ...(input.clientName ? { clientName: input.clientName.slice(0, 256) } : {}),
      redirectUris,
      grantTypes: ["authorization_code", ...grantTypes.filter((value) => value !== "authorization_code")],
      responseTypes: ["code", ...responseTypes.filter((value) => value !== "code")],
      tokenEndpointAuthMethod: "none",
      revocationEpoch: 0,
      createdAt: iso(this.now()),
    };
    this.store.clients.set(clientId, client);
    return client;
  }

  getClient(clientId: string): RegisteredClient | null {
    return this.store.clients.get(clientId) ?? null;
  }

  authorize(input: AuthorizeInput): { code: string; state?: string; redirectUri: string } {
    pruneStore(this.store, this.now());
    const client = this.store.clients.get(input.clientId);
    if (!client) throw new OAuthError("unauthorized_client", "client is not registered", 400, false);
    if (client.installationId !== input.installation.installationId) throw new OAuthError("invalid_target", "client is bound to another installation", 400, false);
    const redirectUri = validateRedirectUri(input.redirectUri);
    if (!client.redirectUris.includes(redirectUri)) throw new OAuthError("invalid_request", "redirect URI is not registered", 400, false);
    if (input.responseType !== "code") throw new OAuthError("unsupported_response_type", "only code response type is supported", 400, true);
    const scope = normalizeScope(input.scope);
    const codeChallenge = requireBounded(input.codeChallenge, "code_challenge", 43, 128);
    if (input.codeChallengeMethod !== "S256") throw new OAuthError("invalid_request", "S256 PKCE is required", 400, true);
    const resource = requireBounded(input.resource, "resource", 1, 2048);
    if (resource !== input.installation.endpointBundle.mcpResourceUrl) throw new OAuthError("invalid_target", "resource is not bound to this installation", 400, true);
    const nonce = input.nonce ? requireBounded(input.nonce, "nonce", 1, 256) : undefined;
    const state = input.state ? requireBounded(input.state, "state", 1, 512) : undefined;
    if (this.store.authorizationCodes.size >= this.limits.maxAuthorizationCodes) throw new OAuthError("server_error", "edge capacity is temporarily unavailable", 503, false);
    const code = `code_${randomOpaque(40)}`;
    const createdAt = this.now();
    const revocationEpoch = epochOf(client);
    this.store.authorizationCodes.set(hashOpaque(code), {
      codeHash: hashOpaque(code),
      installationId: input.installation.installationId,
      ownerId: input.ownerId,
      clientId: input.clientId,
      redirectUri,
      codeChallenge,
      codeChallengeMethod: "S256",
      scope,
      resource,
      ...(nonce ? { nonce } : {}),
      revocationEpoch,
      createdAt,
      expiresAt: createdAt + this.authorizationCodeTtlSeconds * 1000,
    });
    return { code, redirectUri, ...(state ? { state } : {}) };
  }

  async exchangeAuthorizationCode(input: { code: string; clientId: string; redirectUri: string; codeVerifier: string; resource: string }): Promise<TokenResponse> {
    return withMutation(this.store, async () => {
      pruneStore(this.store, this.now());
      const record = this.store.authorizationCodes.get(hashOpaque(input.code));
      if (!record || record.expiresAt <= this.now() || record.consumedAt !== undefined) throw new OAuthError("invalid_grant", "authorization code is invalid or expired");
      if (record.clientId !== input.clientId) throw new OAuthError("invalid_grant", "authorization code belongs to another client");
      const client = this.store.clients.get(record.clientId);
      if (!client || client.installationId !== record.installationId || epochOf(client) !== (record.revocationEpoch ?? 0)) {
        throw new OAuthError("invalid_grant", "authorization code is invalid or expired");
      }
      if (record.redirectUri !== validateRedirectUri(input.redirectUri)) throw new OAuthError("invalid_grant", "redirect URI does not match authorization");
      if (!input.resource || input.resource !== record.resource) throw new OAuthError("invalid_grant", "resource does not match authorization");
      const verifier = requireBounded(input.codeVerifier, "code_verifier", 43, 128);
      if (pkceChallenge(verifier) !== record.codeChallenge) throw new OAuthError("invalid_grant", "PKCE verification failed");
      record.consumedAt = this.now();
      this.store.authorizationCodes.delete(record.codeHash);
      return this.issueTokensUnlocked(record.installationId, record.ownerId, record.clientId, record.scope, record.resource);
    });
  }

  async refresh(input: { refreshToken: string; clientId: string; resource: string }): Promise<TokenResponse> {
    return withMutation(this.store, async () => {
      pruneStore(this.store, this.now());
      const hash = hashOpaque(input.refreshToken);
      const record = this.store.refreshTokens.get(hash);
      if (!record || record.expiresAt <= this.now() || record.revokedAt !== undefined) throw new OAuthError("invalid_grant", "refresh token is invalid or expired");
      if (record.clientId !== input.clientId) throw new OAuthError("invalid_grant", "refresh token belongs to another client");
      const client = this.store.clients.get(record.clientId);
      if (!client || client.installationId !== record.installationId || epochOf(client) !== (record.revocationEpoch ?? 0)) throw new OAuthError("invalid_grant", "refresh token is invalid or expired");
      if (!input.resource || input.resource !== record.resource) throw new OAuthError("invalid_grant", "resource does not match authorization");
      this.store.refreshTokens.delete(hash);
      return this.issueTokensUnlocked(record.installationId, record.ownerId, record.clientId, record.scope, record.resource);
    });
  }

  async issueTokens(installationId: string, ownerId: string, clientId: string, scope: string, resource: string): Promise<TokenResponse> {
    return withMutation(this.store, () => this.issueTokensUnlocked(installationId, ownerId, clientId, scope, resource));
  }

  private async issueTokensUnlocked(installationId: string, ownerId: string, clientId: string, scope: string, resource: string): Promise<TokenResponse> {
    pruneStore(this.store, this.now());
    const installation = this.store.installations.get(installationId);
    if (!installation || installation.status === "revoked") throw new OAuthError("invalid_grant", "installation is revoked");
    const client = this.store.clients.get(clientId);
    if (!client || client.installationId !== installationId) throw new OAuthError("invalid_grant", "client is not registered");
    const revocationEpoch = epochOf(client);
    const nowSeconds = Math.floor(this.now() / 1000);
    const jti = `jti_${randomOpaque(24)}`;
    const accessToken = await new SignJWT({
      installation_id: installationId,
      vault_id: installation.vaultId,
      client_id: clientId,
      resource,
      scope,
      revocation_epoch: revocationEpoch,
    })
      .setProtectedHeader({ alg: "EdDSA", kid: String(this.publicJwk.kid) })
      .setIssuer(this.issuer)
      .setAudience(resource)
      .setSubject(ownerId)
      .setIssuedAt(nowSeconds)
      .setJti(jti)
      .setExpirationTime(nowSeconds + this.accessTokenTtlSeconds)
      .sign(this.privateKey);
    const refreshToken = `refresh_${randomOpaque(48)}`;
    if (this.store.refreshTokens.size >= this.limits.maxRefreshTokens) throw new OAuthError("server_error", "edge capacity is temporarily unavailable", 503, false);
    this.store.refreshTokens.set(hashOpaque(refreshToken), {
      tokenHash: hashOpaque(refreshToken),
      installationId,
      ownerId,
      clientId,
      scope,
      resource,
      revocationEpoch,
      createdAt: this.now(),
      expiresAt: this.now() + this.refreshTokenTtlSeconds * 1000,
    });
    return {
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: this.accessTokenTtlSeconds,
      refresh_token: refreshToken,
      scope,
    };
  }

  async verifyAccessToken(token: string, expected?: { installationId?: string; resource?: string }): Promise<VerifiedAccessToken> {
    const result = await jwtVerify(token, this.verificationKeySet, {
      issuer: this.issuer,
      algorithms: ["EdDSA"],
    });
    const payload = result.payload;
    const installationId = typeof payload.installation_id === "string" ? payload.installation_id : "";
    const vaultId = typeof payload.vault_id === "string" ? payload.vault_id : "";
    const clientId = typeof payload.client_id === "string" ? payload.client_id : "";
    const resource = typeof payload.resource === "string" ? payload.resource : typeof payload.aud === "string" ? payload.aud : "";
    const scope = typeof payload.scope === "string" ? payload.scope : "";
    const subject = typeof payload.sub === "string" ? payload.sub : "";
    const jti = typeof payload.jti === "string" ? payload.jti : "";
    const revocationEpoch = payload.revocation_epoch === undefined ? 0 : payload.revocation_epoch;
    // `iat` was not required by the original edge verifier; retain that
    // compatibility while exposing zero for legacy tokens in diagnostics.
    const issuedAt = typeof payload.iat === "number" ? payload.iat : 0;
    if (!installationId || !vaultId || !clientId || !resource || !scope || !subject || !jti || typeof payload.exp !== "number" || typeof revocationEpoch !== "number" || !Number.isSafeInteger(revocationEpoch) || revocationEpoch < 0) {
      throw new OAuthError("invalid_token", "access token claims are incomplete", 401);
    }
    const installation = this.store.installations.get(installationId);
    if (!installation || installation.status === "revoked" || installation.vaultId !== vaultId) throw new OAuthError("invalid_token", "installation is revoked", 401);
    const client = this.store.clients.get(clientId);
    if (!client || client.installationId !== installationId || epochOf(client) !== revocationEpoch) throw new OAuthError("invalid_token", "access token is revoked", 401);
    if (this.store.revokedAccessJtis.has(jti)) throw new OAuthError("invalid_token", "access token is revoked", 401);
    if (expected?.installationId && expected.installationId !== installationId) throw new OAuthError("invalid_token", "access token belongs to another installation", 401);
    if (expected?.resource && expected.resource !== resource) throw new OAuthError("invalid_token", "access token resource is invalid", 401);
    return { subject, installationId, vaultId, clientId, resource, scope, jti, revocationEpoch, issuedAt, expiresAt: payload.exp };
  }

  /** RFC 7662-shaped internal helper. It intentionally collapses every token
   * validation failure (signature, expiry, installation, client epoch, or
   * deny-list) into `active:false`; callers must authenticate separately. */
  async introspectAccessToken(token: string, expected?: { installationId?: string; resource?: string }): Promise<{ active: boolean }> {
    try {
      await this.verifyAccessToken(token, expected);
      return { active: true };
    } catch {
      return { active: false };
    }
  }

  /** Revoke every authorization code, refresh token, and access token issued
   * for one public client. The client record remains registered so a future
   * authorization can issue tokens at the next epoch. */
  async revokeClient(installationId: string, clientId: string): Promise<boolean> {
    return withMutation(this.store, async () => {
      const changed = this.revokeClientUnlocked(installationId, clientId);
      await flushStore(this.store);
      return changed;
    });
  }

  private revokeClientUnlocked(installationId: string, clientId: string): boolean {
    const client = this.store.clients.get(clientId);
    if (!client || client.installationId !== installationId) return false;
    const currentEpoch = epochOf(client);
    if (currentEpoch >= Number.MAX_SAFE_INTEGER) throw new OAuthError("server_error", "client revocation epoch exhausted", 503, false);
    client.revocationEpoch = currentEpoch + 1;
    for (const [hash, record] of this.store.authorizationCodes) {
      if (record.installationId === installationId && record.clientId === clientId) this.store.authorizationCodes.delete(hash);
    }
    for (const [hash, record] of this.store.refreshTokens) {
      if (record.installationId === installationId && record.clientId === clientId) this.store.refreshTokens.delete(hash);
    }
    return true;
  }

  /** OAuth token revocation remains idempotent for unknown values. When a
   * token identifies a registered client, revocation is deliberately scoped
   * to that client so every access/refresh/code credential is invalidated
   * immediately. */
  async revoke(token: string, expectedClientId?: string): Promise<void> {
    return withMutation(this.store, async () => {
      pruneStore(this.store, this.now());
      const refreshHash = hashOpaque(token);
      const refresh = this.store.refreshTokens.get(refreshHash);
      if (refresh) {
        if (!expectedClientId || expectedClientId === refresh.clientId) this.revokeClientUnlocked(refresh.installationId, refresh.clientId);
        await flushStore(this.store);
        return;
      }
      let result;
      try {
        result = await jwtVerify(token, this.verificationKeySet, { issuer: this.issuer, algorithms: ["EdDSA"] });
      } catch {
        // OAuth revocation is intentionally idempotent for unknown token values.
        await flushStore(this.store);
        return;
      }
      const tokenClientId = typeof result.payload.client_id === "string" ? result.payload.client_id : "";
      const installationId = typeof result.payload.installation_id === "string" ? result.payload.installation_id : "";
      if (tokenClientId && installationId && (!expectedClientId || expectedClientId === tokenClientId) && this.revokeClientUnlocked(installationId, tokenClientId)) {
        await flushStore(this.store);
        return;
      }
      // Signed tokens from an older runtime may not carry client bindings;
      // retain a bounded JTI deny-list as a compatibility fallback.
      if (typeof result.payload.jti === "string") {
        if (this.store.revokedAccessJtis.size >= this.limits.maxRevokedAccessJtis) throw new OAuthError("server_error", "edge capacity is temporarily unavailable", 503, false);
        const expiresAt = typeof result.payload.exp === "number" ? result.payload.exp * 1000 : this.now() + this.accessTokenTtlSeconds * 1000;
        this.store.revokedAccessJtis.set(result.payload.jti, expiresAt);
      }
      await flushStore(this.store);
    });
  }

  verificationBundle(audience: string, now = this.now()): OAuthVerificationBundle {
    const bundle: OAuthVerificationBundle = {
      issuer: this.issuer,
      audience,
      keys: [this.publicJwk],
      issuedAt: iso(now),
      expiresAt: iso(now + 365 * 24 * 60 * 60 * 1000),
    };
    return OAuthVerificationBundleSchema.parse(bundle);
  }

  jwks(): { keys: OAuthVerificationBundle["keys"] } {
    return { keys: [this.publicJwk] };
  }

  authorizationServerMetadata(): Record<string, unknown> {
    return {
      issuer: this.issuer,
      authorization_endpoint: `${this.issuer}/oauth/authorize`,
      token_endpoint: `${this.issuer}/oauth/token`,
      revocation_endpoint: `${this.issuer}/oauth/revoke`,
      revocation_endpoint_auth_methods_supported: ["none"],
      registration_endpoint: `${this.issuer}/oauth/register`,
      jwks_uri: `${this.issuer}/.well-known/jwks.json`,
      response_types_supported: ["code"],
      grant_types_supported: ["authorization_code", "refresh_token"],
      code_challenge_methods_supported: ["S256"],
      token_endpoint_auth_methods_supported: ["none"],
      scopes_supported: [OAUTH_SCOPE],
      client_id_metadata_document_supported: false,
    };
  }
}
