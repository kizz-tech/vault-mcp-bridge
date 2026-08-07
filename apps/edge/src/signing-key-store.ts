import { randomBytes } from "node:crypto";
import { exportJWK, exportPKCS8, generateKeyPair, importPKCS8, type JWK, type KeyInput } from "jose";
import type { SecretReference } from "@vault-mcp-bridge/contracts";
import type { CredentialVault } from "./providers.js";

const SIGNING_KEY_SCHEMA_VERSION = 1 as const;

export const OAUTH_SIGNING_KEY_REFERENCE: SecretReference = Object.freeze({
  provider: "remote-file",
  id: "edge_oauth_signing_key_v1",
});

type PersistedSigningKey = {
  schemaVersion: typeof SIGNING_KEY_SCHEMA_VERSION;
  algorithm: "EdDSA";
  privateKeyPkcs8: string;
  publicJwk: JWK;
};
export type OAuthSigningKey = {
  privateKey: KeyInput;
  publicJwk: JWK;
};

const publicOnly = (value: JWK): JWK => {
  const key = { ...value } as Record<string, unknown>;
  for (const field of ["d", "p", "q", "dp", "dq", "qi", "oth", "k"]) delete key[field];
  if (key.kty !== "OKP" || key.crv !== "Ed25519" || typeof key.x !== "string" || typeof key.kid !== "string") {
    throw new Error("EDGE_OAUTH_SIGNING_KEY_INVALID");
  }
  key.alg = "EdDSA";
  key.use = "sig";
  return key as JWK;
};

const parse = (value: string): PersistedSigningKey => {
  let parsed: unknown;
  try {
    parsed = JSON.parse(value) as unknown;
  } catch {
    throw new Error("EDGE_OAUTH_SIGNING_KEY_INVALID");
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("EDGE_OAUTH_SIGNING_KEY_INVALID");
  const record = parsed as Record<string, unknown>;
  if (record.schemaVersion !== SIGNING_KEY_SCHEMA_VERSION || record.algorithm !== "EdDSA") throw new Error("EDGE_OAUTH_SIGNING_KEY_INVALID");
  if (typeof record.privateKeyPkcs8 !== "string" || record.privateKeyPkcs8.length > 16 * 1024 || !record.privateKeyPkcs8.includes("BEGIN PRIVATE KEY")) {
    throw new Error("EDGE_OAUTH_SIGNING_KEY_INVALID");
  }
  if (!record.publicJwk || typeof record.publicJwk !== "object" || Array.isArray(record.publicJwk)) throw new Error("EDGE_OAUTH_SIGNING_KEY_INVALID");
  return {
    schemaVersion: SIGNING_KEY_SCHEMA_VERSION,
    algorithm: "EdDSA",
    privateKeyPkcs8: record.privateKeyPkcs8,
    publicJwk: publicOnly(record.publicJwk as JWK),
  };
};

/** Load the stable edge OAuth signer from the encrypted credential vault, or
 * create it once. The raw private key is never returned by an HTTP surface. */
export const loadOrCreateOAuthSigningKey = async (vault: CredentialVault): Promise<OAuthSigningKey> => {
  const existing = await vault.get(OAUTH_SIGNING_KEY_REFERENCE);
  if (existing) {
    const persisted = parse(existing);
    return {
      privateKey: await importPKCS8(persisted.privateKeyPkcs8, "EdDSA"),
      publicJwk: persisted.publicJwk,
    };
  }

  const { privateKey, publicKey } = await generateKeyPair("EdDSA", { extractable: true });
  const publicJwk = await exportJWK(publicKey);
  publicJwk.kid = `edge_${randomBytes(18).toString("base64url")}`;
  publicJwk.alg = "EdDSA";
  publicJwk.use = "sig";
  const persisted: PersistedSigningKey = {
    schemaVersion: SIGNING_KEY_SCHEMA_VERSION,
    algorithm: "EdDSA",
    privateKeyPkcs8: await exportPKCS8(privateKey),
    publicJwk: publicOnly(publicJwk),
  };
  await vault.put(OAUTH_SIGNING_KEY_REFERENCE, JSON.stringify(persisted));
  return { privateKey, publicJwk: persisted.publicJwk };
};
