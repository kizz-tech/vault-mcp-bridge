export class OrchestratorError extends Error {
  readonly code: string;
  readonly retryable: boolean;

  constructor(code: string, message: string, options: { retryable?: boolean; cause?: unknown } = {}) {
    super(message, options.cause === undefined ? undefined : { cause: options.cause });
    this.name = "OrchestratorError";
    this.code = code;
    this.retryable = options.retryable ?? true;
  }
}

export class StateStoreError extends Error {
  constructor(message: string, options: { cause?: unknown } = {}) {
    super(message, options.cause === undefined ? undefined : { cause: options.cause });
    this.name = "StateStoreError";
  }
}

export class PersistenceSafetyError extends StateStoreError {
  readonly key: string;

  constructor(key: string) {
    super(`Refusing to persist secret-like field: ${key}`);
    this.name = "PersistenceSafetyError";
    this.key = key;
  }
}

export function safeErrorMessage(error: unknown): string {
  if (error instanceof OrchestratorError) return redactMessage(error.message).slice(0, 240);
  if (error instanceof Error) {
    const candidate = redactMessage(error.message.trim());
    return candidate.length > 0 ? candidate.slice(0, 240) : "Operation failed";
  }
  return "Operation failed";
}

export function errorCode(error: unknown): string {
  if (error instanceof OrchestratorError) return error.code;
  if (error instanceof Error && error.name.length > 0) {
    return error.name.toLowerCase().replace(/[^a-z0-9]+/g, "-").slice(0, 64) || "operation-failed";
  }
  return "operation-failed";
}

function redactMessage(value: string): string {
  return value
    .replace(/\b(?:bearer|token|secret|password|passphrase)\s*[:=]\s*[^\s]+/giu, "[redacted]")
    .replace(/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/gu, "[redacted]")
    .replace(/(?:^|\s)(?:\/(?:[^\s/]+\/)+[^\s]*|[A-Za-z]:\\[^\s]+)/gu, " [redacted]");
}
