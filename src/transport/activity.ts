import type { D1Database } from "@cloudflare/workers-types";

import type { VerificationResponse } from "../core/types";
import type { TransportOptions } from "./shared";

/**
 * Pseudonymous daily activity per signed-grant principal.
 *
 * Off unless `VIZIER_ACTIVITY_KEY` is set (16+ characters). Counts only
 * decisions whose grant was verified: the key is an HMAC of the verified grant
 * issuer, so unsigned or anonymous traffic can never mint an identity. Stores
 * a day and two counters. `VIZIER_ACTIVITY_EXCLUDE` (JSON array of principal
 * ids: the maintainer, CI) marks matching rows excluded; it is reported
 * separately and never counted as demand.
 */

export const ACTIVITY_RETENTION_DAYS = 35;
export const FUNNEL_WINDOW_DAYS = 30;
export const FUNNEL_THRESHOLDS = { integrations: 3, repeat_integrations: 2 } as const;

const MIN_KEY_LENGTH = 16;

export function activityEnabled(options: TransportOptions): boolean {
  return (options.activityKey ?? "").length >= MIN_KEY_LENGTH;
}

async function hmacHex(key: string, value: string): Promise<string> {
  const enc = new TextEncoder();
  const k = await crypto.subtle.importKey("raw", enc.encode(key), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = new Uint8Array(await crypto.subtle.sign("HMAC", k, enc.encode(value)));
  return Array.from(sig, (b) => b.toString(16).padStart(2, "0")).join("");
}

function parseExclusions(source: string | undefined): string[] {
  if (source === undefined || source.trim().length === 0) return [];
  try {
    const parsed: unknown = JSON.parse(source);
    return Array.isArray(parsed) ? parsed.filter((v): v is string => typeof v === "string") : [];
  } catch {
    return [];
  }
}

export function utcDay(nowMs: number): string {
  return new Date(nowMs).toISOString().slice(0, 10);
}

/** Record one enforced decision. Never throws: it must not affect the decision. */
export async function recordActivity(
  options: TransportOptions,
  result: VerificationResponse,
): Promise<void> {
  const db = options.db;
  const key = options.activityKey;
  if (db === undefined || key === undefined || !activityEnabled(options)) return;
  const issuer = result.receipt.grant?.issuer;
  if (result.receipt.authority_provenance !== "principal_signed" || typeof issuer !== "string") return;
  const write = async (): Promise<void> => {
    const hash = await hmacHex(key, issuer);
    const excluded = parseExclusions(options.activityExcludeSource).includes(issuer) ? 1 : 0;
    const allow = result.decision === "ALLOW" ? 1 : 0;
    await db
      .prepare(
        "INSERT INTO integration_activity (integration_hash, day, allow_count, other_count, is_excluded) " +
          "VALUES (?, ?, ?, ?, ?) ON CONFLICT (integration_hash, day) DO UPDATE SET " +
          "allow_count = allow_count + excluded.allow_count, other_count = other_count + excluded.other_count, " +
          "is_excluded = excluded.is_excluded",
      )
      .bind(hash, utcDay(Date.now()), allow, 1 - allow, excluded)
      .run();
  };
  const guarded = write().catch((error: unknown) => {
    console.error(
      JSON.stringify({ event: "vizier.activity.failed", error: error instanceof Error ? error.name : "UnknownError" }),
    );
  });
  if (options.ctx !== undefined) options.ctx.waitUntil(guarded);
  else await guarded;
}

export async function pruneActivity(db: D1Database, nowMs: number): Promise<void> {
  const cutoff = utcDay(nowMs - ACTIVITY_RETENTION_DAYS * 86_400_000);
  await db.prepare("DELETE FROM integration_activity WHERE day < ?").bind(cutoff).run();
}

export interface DemandFunnel {
  window_days: number;
  from_day: string;
  enabled: true;
  /** Principals with a verified-grant ALLOW in the window (excluded ones omitted). */
  integrations_with_first_allow: number;
  /** Of those, principals with ALLOW on at least two distinct UTC days. */
  repeat_integrations: number;
  excluded_integrations: number;
  thresholds: typeof FUNNEL_THRESHOLDS;
  meets_thresholds: boolean;
  notes: string[];
}

export async function getDemandFunnel(db: D1Database, nowMs: number): Promise<DemandFunnel> {
  const fromDay = utcDay(nowMs - (FUNNEL_WINDOW_DAYS - 1) * 86_400_000);
  const rows = await db
    .prepare(
      "SELECT is_excluded AS excluded, COUNT(*) AS integrations, " +
        "SUM(CASE WHEN days >= 2 THEN 1 ELSE 0 END) AS repeat_integrations FROM (" +
        "SELECT integration_hash, MAX(is_excluded) AS is_excluded, COUNT(DISTINCT CASE WHEN allow_count > 0 THEN day END) AS days " +
        "FROM integration_activity WHERE day >= ? GROUP BY integration_hash HAVING days >= 1) GROUP BY is_excluded",
    )
    .bind(fromDay)
    .all<{ excluded: number; integrations: number; repeat_integrations: number | null }>();
  let counted = 0;
  let repeat = 0;
  let excluded = 0;
  for (const row of rows.results ?? []) {
    if (Number(row.excluded) === 1) excluded += Number(row.integrations);
    else {
      counted += Number(row.integrations);
      repeat += Number(row.repeat_integrations ?? 0);
    }
  }
  return {
    window_days: FUNNEL_WINDOW_DAYS,
    from_day: fromDay,
    enabled: true,
    integrations_with_first_allow: counted,
    repeat_integrations: repeat,
    excluded_integrations: excluded,
    thresholds: FUNNEL_THRESHOLDS,
    meets_thresholds:
      counted >= FUNNEL_THRESHOLDS.integrations && repeat >= FUNNEL_THRESHOLDS.repeat_integrations,
    notes: [
      "Counts distinct verified grant issuers, not people or companies; independence needs a human check.",
      "Only signed-grant calls are visible; anonymous and unsigned traffic is not measured.",
      "Install counts are not measured here.",
    ],
  };
}
