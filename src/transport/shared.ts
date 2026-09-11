import {
  assertJsonComplexity,
  JsonComplexityError,
  parsePrincipalKeyRegistry,
  type PrincipalKeyRegistry,
} from "../core/index";

// JSON parsing temporarily holds encoded bytes, decoded text, and the parsed
// object graph at the same time. Keep this well below the Worker's 128 MiB
// memory limit while still allowing sizeable tool arguments and evidence.
export const MAX_BODY_BYTES = 1024 * 1024;

import type { D1Database, KVNamespace, RateLimit } from "@cloudflare/workers-types";

export interface BackgroundContext {
  waitUntil(promise: Promise<unknown>): void;
}

export interface TransportOptions {
  readonly apiKey?: string;
  readonly anonymousRateLimiter?: RateLimit;
  readonly circuitBreakerKv?: KVNamespace;
  readonly agentCardSigningKey?: string;
  readonly receiptSigningKey?: string;
  readonly db?: D1Database;
  readonly ctx?: BackgroundContext;
  /**
   * `VIZIER_PRINCIPAL_KEYS`: JSON mapping a principal id to the ES256 public
   * JWK(s) its delegation grants are signed with. Parsed here rather than at
   * the edge so a bad value cannot take the whole Worker down.
   */
  readonly principalKeySource?: string;
}

const EMPTY_PRINCIPAL_KEYS: PrincipalKeyRegistry = new Map();
const principalKeyCache = new Map<string, PrincipalKeyRegistry>();

/**
 * Resolve the registered principal keys, failing closed.
 *
 * An unparseable registry yields no keys, so every grant that reaches the
 * kernel is refused, while requests that carry no grant keep working. The
 * alternative — refusing all traffic on a config typo — trades a security
 * property that is already safe for an availability one that is not.
 */
export function resolvePrincipalKeys(
  options: TransportOptions,
): PrincipalKeyRegistry {
  const source = options.principalKeySource;
  if (source === undefined || source.trim().length === 0) {
    return EMPTY_PRINCIPAL_KEYS;
  }
  const cached = principalKeyCache.get(source);
  if (cached !== undefined) {
    return cached;
  }
  let registry: PrincipalKeyRegistry;
  try {
    registry = parsePrincipalKeyRegistry(source);
  } catch (error) {
    registry = EMPTY_PRINCIPAL_KEYS;
    console.error(
      JSON.stringify({
        event: "vizier.principal_keys.invalid",
        error: error instanceof Error ? error.message : "UnknownError",
      }),
    );
  }
  principalKeyCache.set(source, registry);
  return registry;
}

/** Whether `VIZIER_PRINCIPAL_KEYS` was set but could not be parsed. */
export function principalKeysMisconfigured(options: TransportOptions): boolean {
  const source = options.principalKeySource;
  return (
    source !== undefined &&
    source.trim().length > 0 &&
    resolvePrincipalKeys(options).size === 0
  );
}

export class TransportRequestError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    readonly details?: unknown,
  ) {
    super(message);
  }
}

export function jsonResponse(
  value: unknown,
  status = 200,
  extraHeaders?: Readonly<Record<string, string>>,
): Response {
  const headers = new Headers(extraHeaders);
  if (!headers.has("Cache-Control")) {
    headers.set("Cache-Control", "no-store");
  }
  headers.set("Content-Type", "application/json; charset=utf-8");
  headers.set("X-Content-Type-Options", "nosniff");
  return new Response(JSON.stringify(value), { status, headers });
}

export async function readLimitedJson(request: Request): Promise<unknown> {
  const contentType = request.headers.get("Content-Type")?.split(";", 1)[0]?.trim();
  if (contentType !== "application/json") {
    throw new TransportRequestError(
      415,
      "UNSUPPORTED_MEDIA_TYPE",
      "Content-Type must be application/json.",
    );
  }

  const declaredLength = request.headers.get("Content-Length");
  if (declaredLength !== null && Number(declaredLength) > MAX_BODY_BYTES) {
    throw new TransportRequestError(
      413,
      "PAYLOAD_TOO_LARGE",
      "Request body is too large.",
    );
  }
  if (request.body === null) {
    throw new TransportRequestError(
      400,
      "INVALID_JSON",
      "Request body must contain JSON.",
    );
  }

  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let totalBytes = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) {
        break;
      }
      totalBytes += value.byteLength;
      if (totalBytes > MAX_BODY_BYTES) {
        await reader.cancel("body size limit exceeded");
        throw new TransportRequestError(
          413,
          "PAYLOAD_TOO_LARGE",
          "Request body is too large.",
        );
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }

  const body = new Uint8Array(totalBytes);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }

  try {
    const text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(body);
    const value = JSON.parse(text) as unknown;
    assertJsonComplexity(value);
    return value;
  } catch (error) {
    if (error instanceof TransportRequestError) {
      throw error;
    }
    if (error instanceof JsonComplexityError) {
      throw new TransportRequestError(
        413,
        "JSON_TOO_COMPLEX",
        "Request JSON exceeds the structural complexity limit.",
      );
    }
    throw new TransportRequestError(
      400,
      "INVALID_JSON",
      "Request body contains invalid JSON.",
    );
  }
}
