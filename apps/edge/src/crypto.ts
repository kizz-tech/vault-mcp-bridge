import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

export const randomOpaque = (bytes = 32): string => randomBytes(bytes).toString("base64url");

export const hashOpaque = (value: string): string => createHash("sha256").update(value, "utf8").digest("base64url");

export const safeEqual = (left: string, right: string): boolean => {
  const a = Buffer.from(left, "utf8");
  const b = Buffer.from(right, "utf8");
  return a.length === b.length && timingSafeEqual(a, b);
};

export const pkceChallenge = (verifier: string): string => createHash("sha256").update(verifier, "ascii").digest("base64url");

export const iso = (milliseconds: number): string => new Date(milliseconds).toISOString();

export const parseBearer = (header: unknown): string | null => {
  if (typeof header !== "string") return null;
  const match = /^Bearer\s+([^\s]+)$/iu.exec(header.trim());
  return match?.[1] ?? null;
};

export const parseCookie = (header: unknown, name: string): string | null => {
  if (typeof header !== "string") return null;
  for (const part of header.split(";")) {
    const [key, ...value] = part.trim().split("=");
    if (key === name) return value.join("=") || null;
  }
  return null;
};

export const formEncode = (value: Record<string, string>): string => new URLSearchParams(value).toString();
