import type { D1Database } from "@cloudflare/workers-types";

import { decodeCompactJws } from "../crypto/jws";
import { verifyAction, type VerificationOptions } from "../core/index";
import type { VerificationRequest } from "../core/schemas";
import type { VerificationResponse } from "../core/types";
import type { TransportOptions } from "./shared";

/**
 * Grant lifecycle: revocation and optional single-use consumption.
 *
 * The authorization kernel stays free of I/O. This module resolves the state
 * the kernel needs (revoked ids, consumed single-use ids) before the call, and
 * records consumption after an ALLOW. State holds only grant ids and times.
 *
 * Revocation sources: the operator's `VIZIER_REVOKED_GRANTS` (a JSON array of
 * jti strings) and, when D1 is bound, rows written by `POST /v1/grants/revoke`.
 * Single-use is requested by the principal inside the signed grant
 * (`single_use: true`); consumption is an atomic insert into D1. Without D1
 * there is no durable, shared consumption state: per-isolate memory loses the
 * spend on restart and is invisible to other isolates, so a replayed grant
 * could be ALLOWed again. Enforcement therefore fails closed — a single-use
 * grant presented to an enforcing transport without D1 is BLOCK with
 * GRANT_SINGLE_USE_STATE_UNAVAILABLE, never ALLOW. Evaluation-only paths do
 * not consume and are unaffected, as are reusable grants.
 */

/** A grant may live 365 days (see grants.ts); keep state a little past that. */
export const GRANT_STATE_MAX_SECONDS = 366 * 24 * 60 * 60;

const memoryRevoked = new Map<string, number>();

interface UnverifiedGrantHints {
  readonly jti: string;
  readonly singleUse: boolean;
  readonly exp: number;
}

/**
 * Read lookup keys from a grant that has NOT been verified. The values are
 * only used to query state; every decision still comes from the kernel after
 * it verifies the signature.
 */
function readHints(token: string | undefined): UnverifiedGrantHints | null {
  if (token === undefined) return null;
  const parts = decodeCompactJws(token);
  const payload = parts?.payload;
  if (typeof payload !== "object" || payload === null) return null;
  const { jti, exp, single_use: singleUse } = payload as Record<string, unknown>;
  if (typeof jti !== "string" || jti.length === 0 || jti.length > 256) return null;
  return {
    jti,
    singleUse: singleUse === true,
    exp: typeof exp === "number" && Number.isFinite(exp) ? exp : 0,
  };
}

function parseStaticRevocations(source: string | undefined): ReadonlySet<string> {
  if (source === undefined || source.trim().length === 0) return new Set();
  try {
    const parsed = JSON.parse(source) as unknown;
    if (Array.isArray(parsed) && parsed.every((item) => typeof item === "string")) {
      return new Set(parsed as string[]);
    }
  } catch {
    // fall through
  }
  console.error(JSON.stringify({ event: "vizier.revoked_grants.invalid" }));
  return new Set();
}

async function dbHas(
  db: D1Database,
  table: "revoked_grants" | "consumed_grants",
  jti: string,
  nowSeconds: number,
): Promise<boolean> {
  const row = await db
    .prepare(`SELECT jti FROM ${table} WHERE jti = ? AND expires_at > ?`)
    .bind(jti, nowSeconds)
    .first();
  return row !== null && row !== undefined;
}

function memHas(map: Map<string, number>, jti: string, nowSeconds: number): boolean {
  const expires = map.get(jti);
  return expires !== undefined && expires > nowSeconds;
}

/** Record a revocation. Returns the epoch-seconds the record is kept until. */
export async function revokeGrant(
  options: TransportOptions,
  jti: string,
  expiresAt?: number,
): Promise<number> {
  const now = Math.floor(Date.now() / 1000);
  const keepUntil = Math.min(
    Math.max(expiresAt ?? 0, now) + 120,
    now + GRANT_STATE_MAX_SECONDS,
  );
  if (options.db === undefined) {
    memoryRevoked.set(jti, keepUntil);
  } else {
    await options.db
      .prepare(
        "INSERT INTO revoked_grants (jti, revoked_at, expires_at) VALUES (?, ?, ?) " +
          "ON CONFLICT(jti) DO UPDATE SET expires_at = MAX(expires_at, excluded.expires_at)",
      )
      .bind(jti, now, keepUntil)
      .run();
  }
  return keepUntil;
}

async function claimConsumption(
  options: TransportOptions,
  hints: UnverifiedGrantHints,
): Promise<boolean> {
  // Unreachable today: an enforcing transport without D1 BLOCKs the grant in
  // the kernel before any ALLOW. If that ever changes, fail closed here.
  if (options.db === undefined) return false;
  const now = Math.floor(Date.now() / 1000);
  const keepUntil = Math.min(Math.max(hints.exp, now) + 120, now + GRANT_STATE_MAX_SECONDS);
  // Expired rows are pruned daily; clear this id's own expired row first so a
  // reused id after expiry cannot be blocked by a stale row.
  await options.db
    .prepare("DELETE FROM consumed_grants WHERE jti = ? AND expires_at <= ?")
    .bind(hints.jti, now)
    .run();
  const outcome = await options.db
    .prepare("INSERT OR IGNORE INTO consumed_grants (jti, consumed_at, expires_at) VALUES (?, ?, ?)")
    .bind(hints.jti, now, keepUntil)
    .run();
  return Number(outcome.meta?.changes ?? 0) === 1;
}

/** Delete expired lifecycle rows. Called from the daily scheduled handler. */
export async function pruneGrantLifecycle(db: D1Database, nowSeconds: number): Promise<void> {
  await db.prepare("DELETE FROM revoked_grants WHERE expires_at <= ?").bind(nowSeconds).run();
  await db.prepare("DELETE FROM consumed_grants WHERE expires_at <= ?").bind(nowSeconds).run();
}

export interface GrantLifecycleOptions {
  /** Consume single-use grants on ALLOW. False for evaluation-only paths. */
  readonly enforce: boolean;
}

/**
 * Run the kernel with grant lifecycle state resolved. A single-use grant that
 * is ALLOWed is consumed atomically. If a concurrent request consumed it
 * first, the kernel is re-run with the grant marked used, so the loser gets a
 * BLOCK with GRANT_ALREADY_USED rather than a second ALLOW.
 */
export async function verifyWithGrantLifecycle(
  request: VerificationRequest,
  verifyOptions: VerificationOptions,
  options: TransportOptions,
  lifecycle: GrantLifecycleOptions,
): Promise<VerificationResponse> {
  const hints = readHints(request.grant);
  if (hints === null) {
    return verifyAction(request, verifyOptions);
  }
  const now = Math.floor(Date.now() / 1000);
  const revoked = new Set(parseStaticRevocations(options.revokedGrantSource));
  const used = new Set<string>();
  const [isRevoked, isUsed] = await Promise.all([
    options.db === undefined
      ? Promise.resolve(memHas(memoryRevoked, hints.jti, now))
      : dbHas(options.db, "revoked_grants", hints.jti, now),
    hints.singleUse && options.db !== undefined
      ? dbHas(options.db, "consumed_grants", hints.jti, now)
      : Promise.resolve(false),
  ]);
  if (isRevoked) revoked.add(hints.jti);
  if (isUsed) used.add(hints.jti);

  const withState = (usedIds: ReadonlySet<string>): VerificationOptions => ({
    ...verifyOptions,
    revokedGrantIds: revoked,
    usedGrantIds: usedIds,
    // Enforcement without a durable store fails single-use grants closed.
    // Evaluation-only paths do not consume, so they keep their old semantics.
    ...(lifecycle.enforce ? { singleUseStateDurable: options.db !== undefined } : {}),
  });
  const result = await verifyAction(request, withState(used));

  if (
    !lifecycle.enforce ||
    !hints.singleUse ||
    result.decision !== "ALLOW" ||
    result.receipt.authority_provenance !== "principal_signed" ||
    result.receipt.grant?.jti !== hints.jti
  ) {
    return result;
  }
  if (await claimConsumption(options, hints)) {
    return result;
  }
  return verifyAction(request, withState(new Set([...used, hints.jti])));
}

/** Test hook: clear per-isolate fallback state. */
export function resetGrantLifecycleMemory(): void {
  memoryRevoked.clear();
}
