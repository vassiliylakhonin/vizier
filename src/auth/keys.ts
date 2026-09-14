import type { D1Database } from "@cloudflare/workers-types";
import { sha256 } from "../core/receipts";
import type { TransportOptions } from "../transport/shared";

export interface ApiKeyRecord {
  readonly id: string;
  readonly org_id: string;
  readonly name: string;
  readonly key_hash: string;
  readonly key_prefix: string;
  readonly tier: "developer" | "team" | "enterprise";
  readonly monthly_quota: number;
  readonly current_usage: number;
  readonly period_month?: string;
  readonly created_at: number;
  readonly revoked_at: number | null;
}

export function getCurrentPeriodMonth(date: Date = new Date()): string {
  return date.toISOString().slice(0, 7);
}

export interface GeneratedApiKey {
  readonly id: string;
  readonly key: string;
  readonly key_prefix: string;
  readonly org_id: string;
  readonly name: string;
  readonly tier: "developer" | "team" | "enterprise";
  readonly monthly_quota: number;
  readonly created_at: number;
}

export interface KeyAuthResult {
  readonly authenticated: boolean;
  readonly key_record?: ApiKeyRecord;
  readonly is_master?: boolean;
  readonly quota_exceeded?: boolean;
  readonly error_code?: "INVALID_KEY" | "KEY_REVOKED" | "QUOTA_EXCEEDED";
  readonly error_message?: string;
}

export const TIER_QUOTAS: Record<"developer" | "team" | "enterprise", number> = {
  developer: 10000,
  team: 100000,
  enterprise: 1000000,
};

export async function generateApiKey(
  db: D1Database,
  params: {
    org_id: string;
    name: string;
    tier?: "developer" | "team" | "enterprise";
    monthly_quota?: number;
  },
): Promise<GeneratedApiKey> {
  const tier = params.tier ?? "developer";
  const monthlyQuota = params.monthly_quota ?? TIER_QUOTAS[tier];
  const id = `key_${crypto.randomUUID()}`;

  // Generate 24 random bytes -> 48 hex chars
  const randomBytes = new Uint8Array(24);
  crypto.getRandomValues(randomBytes);
  const randomHex = Array.from(randomBytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

  const fullKey = `vz_live_${randomHex}`;
  const keyPrefix = fullKey.slice(0, 16);
  const keyHash = await sha256(fullKey);
  const createdAt = Date.now();
  const currentMonth = getCurrentPeriodMonth(new Date(createdAt));

  await db
    .prepare(
      `INSERT INTO vizier_api_keys (
        id, org_id, name, key_hash, key_prefix, tier, monthly_quota, current_usage, period_month, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?)`,
    )
    .bind(id, params.org_id, params.name, keyHash, keyPrefix, tier, monthlyQuota, currentMonth, createdAt)
    .run();

  return {
    id,
    key: fullKey,
    key_prefix: keyPrefix,
    org_id: params.org_id,
    name: params.name,
    tier,
    monthly_quota: monthlyQuota,
    created_at: createdAt,
  };
}

export async function authenticateKey(
  providedKey: string,
  options: TransportOptions,
  now: Date = new Date(),
): Promise<KeyAuthResult> {
  const trimmed = providedKey.trim();

  // 1. Check root master API key (VIZIER_API_KEY)
  if (options.apiKey && trimmed === options.apiKey.trim()) {
    return { authenticated: true, is_master: true };
  }

  // 2. Check tenant key format
  if (!trimmed.startsWith("vz_live_")) {
    return {
      authenticated: false,
      error_code: "INVALID_KEY",
      error_message: "Invalid API key format. Tenant keys must start with 'vz_live_'.",
    };
  }

  if (!options.db) {
    // If no D1 database is attached, only master key can be used
    return {
      authenticated: false,
      error_code: "INVALID_KEY",
      error_message: "Tenant API key storage is unavailable.",
    };
  }

  const keyHash = await sha256(trimmed);
  const row = (await options.db
    .prepare("SELECT * FROM vizier_api_keys WHERE key_hash = ?")
    .bind(keyHash)
    .first()) as ApiKeyRecord | null;

  if (!row) {
    return {
      authenticated: false,
      error_code: "INVALID_KEY",
      error_message: "API key not found.",
    };
  }

  if (row.revoked_at !== null) {
    return {
      authenticated: false,
      error_code: "KEY_REVOKED",
      error_message: "API key has been revoked.",
    };
  }

  const currentMonth = getCurrentPeriodMonth(now);
  const effectiveUsage = (row.period_month === currentMonth) ? row.current_usage : 0;

  if (row.monthly_quota > 0 && effectiveUsage >= row.monthly_quota) {
    return {
      authenticated: false,
      quota_exceeded: true,
      key_record: { ...row, current_usage: effectiveUsage },
      error_code: "QUOTA_EXCEEDED",
      error_message: `Monthly API quota exceeded (${effectiveUsage}/${row.monthly_quota} requests used).`,
    };
  }

  return {
    authenticated: true,
    is_master: false,
    key_record: { ...row, current_usage: effectiveUsage },
  };
}

export async function incrementKeyUsage(
  db: D1Database,
  keyId: string,
  now: Date = new Date(),
): Promise<void> {
  const currentMonth = getCurrentPeriodMonth(now);
  try {
    await db
      .prepare(
        `UPDATE vizier_api_keys
         SET current_usage = CASE WHEN period_month = ? THEN current_usage + 1 ELSE 1 END,
             period_month = ?
         WHERE id = ?`,
      )
      .bind(currentMonth, currentMonth, keyId)
      .run();
  } catch (err) {
    console.error(
      JSON.stringify({
        event: "vizier.api_keys.increment_failed",
        key_id: keyId,
        error: err instanceof Error ? err.message : "Unknown error",
      }),
    );
  }
}

export async function listApiKeys(
  db: D1Database,
  orgId: string,
): Promise<readonly Omit<ApiKeyRecord, "key_hash">[]> {
  const result = await db
    .prepare(
      `SELECT id, org_id, name, key_prefix, tier, monthly_quota, current_usage, created_at, revoked_at
       FROM vizier_api_keys
       WHERE org_id = ?
       ORDER BY created_at DESC`,
    )
    .bind(orgId)
    .all();

  return (result.results ?? []) as unknown as readonly Omit<ApiKeyRecord, "key_hash">[];
}

export async function revokeApiKey(
  db: D1Database,
  keyId: string,
  orgId?: string,
): Promise<boolean> {
  const query = orgId
    ? "UPDATE vizier_api_keys SET revoked_at = ? WHERE id = ? AND org_id = ? AND revoked_at IS NULL"
    : "UPDATE vizier_api_keys SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL";

  const bindings = orgId ? [Date.now(), keyId, orgId] : [Date.now(), keyId];
  const result = await db.prepare(query).bind(...bindings).run();
  return (result.meta?.changes ?? 0) > 0;
}
