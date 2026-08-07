import type { EndpointBundle as ContractEndpointBundle, OAuthVerificationBundle as ContractOAuthVerificationBundle, SecretReference } from "@vault-mcp-bridge/contracts";
import type { KeyObject } from "node:crypto";

export type EdgeMode = "managed" | "self-hosted";
export type EdgeEnvironment = "development" | "test" | "production";
export type InstallationStatus = "provisioning" | "ready" | "revoked";

/** A reference to a secret held by the edge/deployment secret store.
 *
 * The reference is deliberately non-sensitive. It is safe to return from
 * owner-facing APIs and to persist in the desktop setup state. The value it
 * points to is never included in an endpoint bundle.
 */
export type CredentialReference = SecretReference;
export type OAuthVerificationBundle = ContractOAuthVerificationBundle;
export type EndpointBundle = ContractEndpointBundle;

export type InstallationRecord = {
  installationId: string;
  ownerId: string;
  vaultId: string;
  mode: EdgeMode;
  status: InstallationStatus;
  providerResourceId: string;
  endpointBundle: EndpointBundle;
  createdAt: string;
  updatedAt: string;
  revokedAt?: string;
};

export type RegisteredClient = {
  clientId: string;
  installationId: string;
  clientName?: string;
  redirectUris: string[];
  grantTypes: ["authorization_code", ...string[]];
  responseTypes: ["code", ...string[]];
  tokenEndpointAuthMethod: "none";
  /** Monotonic client-scoped epoch. Legacy durable records omit this field
   * and are migrated to zero when loaded. */
  revocationEpoch?: number;
  createdAt: string;
};

export type AuthorizationCodeRecord = {
  codeHash: string;
  installationId: string;
  ownerId: string;
  clientId: string;
  redirectUri: string;
  codeChallenge: string;
  codeChallengeMethod: "S256";
  scope: string;
  resource: string;
  nonce?: string;
  /** Epoch captured when the code was issued. Legacy records omit it and
   * are treated as epoch zero. */
  revocationEpoch?: number;
  createdAt: number;
  expiresAt: number;
  consumedAt?: number;
};

export type RefreshTokenRecord = {
  tokenHash: string;
  installationId: string;
  ownerId: string;
  clientId: string;
  scope: string;
  resource: string;
  /** Epoch captured when the refresh token was issued. Legacy records omit it
   * and are treated as epoch zero. */
  revocationEpoch?: number;
  createdAt: number;
  expiresAt: number;
  revokedAt?: number;
};

export type OwnerSession = {
  sessionHash: string;
  ownerId: string;
  createdAt: number;
  expiresAt: number;
};

export type InstallationIdempotencyRecord = {
  keyHash: string;
  ownerId: string;
  vaultId: string;
  installationId: string;
  createdAt: number;
};

export type CredentialKind = "tunnel" | "publisher-mtls" | "publisher-edge-attestation" | "mcp-edge-attestation";

export type CredentialLease = {
  leaseId: string;
  installationId: string;
  ownerId: string;
  kind: CredentialKind;
  clientPublicKey: string;
  serverPrivateKey: KeyObject;
  serverPublicKey: string;
  createdAt: number;
  expiresAt: number;
};

export type EdgeStore = {
  installations: Map<string, InstallationRecord>;
  clients: Map<string, RegisteredClient>;
  authorizationCodes: Map<string, AuthorizationCodeRecord>;
  refreshTokens: Map<string, RefreshTokenRecord>;
  ownerSessions: Map<string, OwnerSession>;
  /** JTI -> expiry in milliseconds; bounded by EdgeLimits.maxRevokedAccessJtis. */
  revokedAccessJtis: Map<string, number>;
  credentialLeases: Map<string, CredentialLease>;
  installationIdempotency: Map<string, InstallationIdempotencyRecord>;
  /** Production must inject a store backed by durable, access-controlled storage. */
  isDurable?: boolean;
  /** Optional durability checkpoint. Production adapters implement it and
   * HTTP mutation responses are withheld until it completes. */
  flush?: () => Promise<void>;
};

export type EdgeClock = () => number;
