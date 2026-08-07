import { z } from "zod";
import { CONTRACT_VERSION } from "./constants.js";
import { OpaqueIdSchema } from "./schemas.js";

const HttpsUrlSchema = z
  .string()
  .url()
  .refine((value) => new URL(value).protocol === "https:", "Expected an HTTPS URL");

const HostnameSchema = z
  .string()
  .min(1)
  .max(253)
  .regex(
    /^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/u,
    "Expected a DNS hostname"
  );

/** A secret is always addressed indirectly. Secret values are deliberately not representable. */
export const SecretReferenceSchema = z
  .object({
    provider: z.enum(["safe-storage", "keychain", "remote-file"]),
    id: OpaqueIdSchema
  })
  .strict();
export type SecretReference = z.infer<typeof SecretReferenceSchema>;

export const SshTargetSchema = z
  .object({
    host: z.string().min(1).max(253),
    user: z.string().min(1).max(64),
    port: z.number().int().min(1).max(65_535).default(22),
    hostKeyFingerprint: z.string().min(16).max(512).optional()
  })
  .strict();
export type SshTarget = z.infer<typeof SshTargetSchema>;

/** Local-only receipt shown in the vault row before setup can start. */
export const VaultPreviewReceiptSchema = z
  .object({
    vaultId: OpaqueIdSchema,
    displayName: z.string().min(1).max(256),
    documentCount: z.number().int().nonnegative(),
    totalBytes: z.number().int().nonnegative(),
    scannedAt: z.string().datetime({ offset: true }),
    unreadableCount: z.number().int().nonnegative(),
    /** Absolute paths are intentionally excluded from this portable receipt. */
    projectionVersion: z.literal(CONTRACT_VERSION)
  })
  .strict();
export type VaultPreviewReceipt = z.infer<typeof VaultPreviewReceiptSchema>;

export const JsonWebKeySchema = z
  .object({
    kty: z.string().min(1),
    kid: z.string().min(1).max(256),
    use: z.string().max(32).optional(),
    alg: z.string().max(32).optional(),
    n: z.string().optional(),
    e: z.string().optional(),
    crv: z.string().optional(),
    x: z.string().optional(),
    y: z.string().optional()
  })
  .passthrough();

/** Offline bundle mounted into the no-egress application container. */
export const OAuthVerificationBundleSchema = z
  .object({
    issuer: HttpsUrlSchema,
    audience: z.string().min(1).max(2048),
    keys: z.array(JsonWebKeySchema).min(1).max(16),
    issuedAt: z.string().datetime({ offset: true }),
    expiresAt: z.string().datetime({ offset: true })
  })
  .strict()
  .superRefine((bundle, context) => {
    if (Date.parse(bundle.expiresAt) <= Date.parse(bundle.issuedAt)) {
      context.addIssue({ code: "custom", path: ["expiresAt"], message: "expiresAt must follow issuedAt" });
    }
    const keyIds = bundle.keys.map((key) => key.kid);
    if (new Set(keyIds).size !== keyIds.length) {
      context.addIssue({ code: "custom", path: ["keys"], message: "JWK key ids must be unique" });
    }
  });
export type OAuthVerificationBundle = z.infer<typeof OAuthVerificationBundleSchema>;

/** Public references and opaque secret handles returned by the owner control plane. */
export const EndpointBundleSchema = z
  .object({
    version: z.literal(CONTRACT_VERSION),
    installationId: OpaqueIdSchema,
    vaultId: OpaqueIdSchema,
    mcpResourceUrl: HttpsUrlSchema,
    publisherUrl: HttpsUrlSchema,
    mcpHost: HostnameSchema,
    publisherHost: HostnameSchema,
    oauthIssuer: HttpsUrlSchema,
    oauthAuthorizationEndpoint: HttpsUrlSchema,
    oauthTokenEndpoint: HttpsUrlSchema,
    oauthJwksUri: HttpsUrlSchema,
    oauthProtectedResourceMetadataUrl: HttpsUrlSchema,
    oauthAudience: z.string().min(1).max(2048),
    tunnelCredential: SecretReferenceSchema,
    publisherMtlsCredential: SecretReferenceSchema,
    /** Shared only with the trusted edge and the MCP server; distinct from the publisher client certificate. */
    publisherEdgeAttestation: SecretReferenceSchema,
    /** Shared only with the MCP policy Worker and the MCP server. */
    mcpEdgeAttestation: SecretReferenceSchema,
    oauthVerificationBundle: OAuthVerificationBundleSchema
  })
  .strict()
  .superRefine((bundle, context) => {
    if (new URL(bundle.mcpResourceUrl).hostname !== bundle.mcpHost) {
      context.addIssue({ code: "custom", path: ["mcpResourceUrl"], message: "MCP URL host does not match mcpHost" });
    }
    if (new URL(bundle.publisherUrl).hostname !== bundle.publisherHost) {
      context.addIssue({ code: "custom", path: ["publisherUrl"], message: "Publisher URL host does not match publisherHost" });
    }
    if (bundle.mcpHost === bundle.publisherHost) {
      context.addIssue({ code: "custom", path: ["publisherHost"], message: "MCP and publisher hosts must be separate" });
    }
    const secretKeys = [bundle.tunnelCredential, bundle.publisherMtlsCredential, bundle.publisherEdgeAttestation, bundle.mcpEdgeAttestation]
      .map((reference) => `${reference.provider}:${reference.id}`);
    if (new Set(secretKeys).size !== secretKeys.length) {
      context.addIssue({ code: "custom", path: ["mcpEdgeAttestation"], message: "Endpoint credentials must be distinct" });
    }
    if (bundle.oauthVerificationBundle.audience !== bundle.oauthAudience) {
      context.addIssue({
        code: "custom",
        path: ["oauthVerificationBundle", "audience"],
        message: "OAuth audience does not match verification bundle"
      });
    }
  });
export type EndpointBundle = z.infer<typeof EndpointBundleSchema>;

export const SetupStageSchema = z.enum([
  "idle",
  "preflight",
  "staged",
  "deployed",
  "device-bound",
  "first-snapshot",
  "endpoint-verified",
  "ready"
]);
export type SetupStage = z.infer<typeof SetupStageSchema>;

export const ProductStatusSchema = z.enum(["idle", "synchronizing", "ready", "needs-attention", "paused"]);
export type ProductStatus = z.infer<typeof ProductStatusSchema>;

export const ServerCopyDispositionSchema = z.enum(["none", "active", "retained", "unknown"]);
export type ServerCopyDisposition = z.infer<typeof ServerCopyDispositionSchema>;

export const SetupFailureSchema = z
  .object({
    code: z.enum([
      "vault-missing",
      "ssh-failed",
      "host-key-changed",
      "docker-unavailable",
      "insufficient-capacity",
      "deployment-failed",
      "sync-blocked",
      "server-offline",
      "oauth-not-linked",
      "cancelled",
      "internal"
    ]),
    retryable: z.boolean(),
    occurredAt: z.string().datetime({ offset: true })
  })
  .strict();
export type SetupFailure = z.infer<typeof SetupFailureSchema>;

/** Persistable orchestration state. It contains references, never credential material. */
export const InstallationStateSchema = z
  .object({
    version: z.literal(CONTRACT_VERSION),
    installationId: OpaqueIdSchema,
    vaultId: OpaqueIdSchema,
    stage: SetupStageSchema,
    status: ProductStatusSchema,
    serverCopy: ServerCopyDispositionSchema,
    sshTarget: SshTargetSchema,
    endpoint: EndpointBundleSchema.optional(),
    lastPublishedAt: z.string().datetime({ offset: true }).optional(),
    lastGeneration: z.number().int().nonnegative().optional(),
    failure: SetupFailureSchema.optional(),
    updatedAt: z.string().datetime({ offset: true })
  })
  .strict();
export type InstallationState = z.infer<typeof InstallationStateSchema>;

export const JournalEventSchema = z
  .object({
    at: z.string().datetime({ offset: true }),
    code: z.enum([
      "ssh-connected",
      "server-checked",
      "deployment-staged",
      "container-started",
      "device-bound",
      "vault-synchronized",
      "endpoint-verified",
      "paused",
      "resumed",
      "failed"
    ]),
    installationId: OpaqueIdSchema
  })
  .strict();
export type JournalEvent = z.infer<typeof JournalEventSchema>;
