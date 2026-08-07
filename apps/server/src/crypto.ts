import {
  createHash,
  createPublicKey,
  randomBytes,
  timingSafeEqual,
  verify,
  type KeyObject,
} from "node:crypto";

export const fromBase64Url = (value: string): Buffer => Buffer.from(value, "base64url");

export const sha256Base64Url = (value: string | Uint8Array): string =>
  createHash("sha256").update(value).digest("base64url");

export const hashPairingCode = (code: string): string => sha256Base64Url(code);

export const generatePairingCode = (): string => randomBytes(32).toString("base64url");

export const decodeEd25519PublicKey = (encoded: string): KeyObject => {
  const key = fromBase64Url(encoded);
  if (key.length < 32 || key.length > 128) throw new Error("invalid public key");
  return createPublicKey({ key, format: "der", type: "spki" });
};

export const verifyEd25519 = (payload: string | Uint8Array, encodedSignature: string, publicKey: KeyObject): boolean => {
  const signature = fromBase64Url(encodedSignature);
  if (signature.length !== 64) return false;
  return verify(null, Buffer.from(payload), publicKey, signature);
};

export const safeEqual = (left: string, right: string): boolean => {
  const a = Buffer.from(left);
  const b = Buffer.from(right);
  return a.length === b.length && timingSafeEqual(a, b);
};
