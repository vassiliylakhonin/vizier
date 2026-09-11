import type { D1Database } from "@cloudflare/workers-types";
import { authenticateKey } from "../auth/keys";

export type EnforcementAuthorization =
  | "authenticated"
  | "evaluation"
  | "denied"
  | "quota_exceeded";

export interface AuthorizationOptions {
  readonly allowMissingCredentialForEvaluation?: boolean;
  readonly db?: D1Database;
}

function extractCredential(request: Request): string | null {
  const authHeader = request.headers.get("Authorization");
  if (authHeader !== null && authHeader.startsWith("Bearer ")) {
    const token = authHeader.slice("Bearer ".length).trim();
    if (token.length > 0) return token;
  }
  const vizierKeyHeader = request.headers.get("X-Vizier-Key");
  if (vizierKeyHeader !== null && vizierKeyHeader.trim().length > 0) {
    return vizierKeyHeader.trim();
  }
  return null;
}

async function digest(value: string): Promise<Uint8Array> {
  const bytes = new TextEncoder().encode(value);
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
}

function supportsTimingSafeEqual(
  subtle: SubtleCrypto,
): subtle is SubtleCrypto & {
  timingSafeEqual(
    left: ArrayBuffer | ArrayBufferView,
    right: ArrayBuffer | ArrayBufferView,
  ): boolean;
} {
  return "timingSafeEqual" in subtle;
}

async function secretsEqual(left: string, right: string): Promise<boolean> {
  const [leftDigest, rightDigest] = await Promise.all([digest(left), digest(right)]);
  if (supportsTimingSafeEqual(crypto.subtle)) {
    return crypto.subtle.timingSafeEqual(leftDigest, rightDigest);
  }
  let difference = 0;
  for (let index = 0; index < leftDigest.length; index += 1) {
    difference |= leftDigest[index]! ^ rightDigest[index]!;
  }
  return difference === 0;
}

export async function authorizeEnforcement(
  request: Request,
  apiKey: string | undefined,
  options: AuthorizationOptions = {},
): Promise<EnforcementAuthorization> {
  const token = extractCredential(request);
  const hasCredentialHeader =
    request.headers.has("Authorization") || request.headers.has("X-Vizier-Key");

  // If server has no master API key configured:
  if (apiKey === undefined || apiKey.length === 0) {
    if (token?.startsWith("vz_live_") && options.db) {
      const authRes = await authenticateKey(token, { apiKey, db: options.db });
      if (authRes.authenticated) return "authenticated";
      if (authRes.quota_exceeded) return "quota_exceeded";
      return "denied";
    }
    return "evaluation";
  }

  if (token === null) {
    return options.allowMissingCredentialForEvaluation === true &&
      !hasCredentialHeader
      ? "evaluation"
      : "denied";
  }

  // 1. Root master key
  if (await secretsEqual(token, apiKey)) {
    return "authenticated";
  }

  // 2. Tenant API key
  if (token.startsWith("vz_live_") && options.db) {
    const authRes = await authenticateKey(token, { apiKey, db: options.db });
    if (authRes.authenticated) {
      return "authenticated";
    }
    if (authRes.quota_exceeded) {
      return "quota_exceeded";
    }
    return "denied";
  }

  return "denied";
}
