export type EdgeLimits = {
  maxInstallations: number;
  maxInstallationsPerOwner: number;
  maxClientsTotal: number;
  maxClientsPerInstallation: number;
  maxAuthorizationCodes: number;
  maxRefreshTokens: number;
  maxOwnerSessions: number;
  maxCredentialLeases: number;
  maxRevokedAccessJtis: number;
  maxIdempotencyKeys: number;
  rateBurst: number;
  ratePerMinute: number;
  rateMaxKeys: number;
};

export const DEFAULT_EDGE_LIMITS: EdgeLimits = Object.freeze({
  maxInstallations: 256,
  maxInstallationsPerOwner: 16,
  maxClientsTotal: 1_024,
  maxClientsPerInstallation: 16,
  maxAuthorizationCodes: 1_024,
  maxRefreshTokens: 2_048,
  maxOwnerSessions: 512,
  maxCredentialLeases: 512,
  maxRevokedAccessJtis: 4_096,
  maxIdempotencyKeys: 512,
  rateBurst: 30,
  ratePerMinute: 120,
  rateMaxKeys: 4_096,
});

const positiveInteger = (name: string, value: number): number => {
  if (!Number.isSafeInteger(value) || value < 1) throw new Error(`EDGE_LIMIT_INVALID:${name}`);
  return value;
};

export const resolveLimits = (input?: Partial<EdgeLimits>): EdgeLimits => {
  const values = { ...DEFAULT_EDGE_LIMITS, ...(input ?? {}) };
  for (const [name, value] of Object.entries(values)) positiveInteger(name, value as number);
  if (values.ratePerMinute < values.rateBurst) throw new Error("EDGE_LIMIT_INVALID:ratePerMinute");
  return values;
};
