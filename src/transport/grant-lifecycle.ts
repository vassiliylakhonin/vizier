import type { D1Database } from "@cloudflare/workers-types";

import { decodeCompactJws } from "../crypto/jws";
import {
  budgetKey,
  ceilingToMicrosFloor,
  priceAction,
  type BudgetState,
} from "../core/budget";
import {
  usageKey,
  usageWindowStart,
  type UsageState,
} from "../core/usage";
import { canonicalize, sha256, verifyAction, type VerificationOptions } from "../core/index";
import type { VerificationRequest } from "../core/schemas";
import type { VerificationResponse } from "../core/types";
import { pruneActivity, recordActivity } from "./activity";
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
  try {
    await db
      .prepare("DELETE FROM budget_admissions WHERE created_at <= ?")
      .bind(nowSeconds - 30 * 24 * 60 * 60)
      .run();
  } catch {
    // Table absent before migration 0015 is applied.
  }
  try {
    await pruneActivity(db, nowSeconds * 1000);
  } catch {
    // Table absent before migration 0016 is applied.
  }
  try {
    await db
      .prepare("DELETE FROM usage_ledger WHERE window_start + window_seconds + 86400 <= ?")
      .bind(nowSeconds)
      .run();
  } catch {
    // Table absent before migration 0017 is applied.
  }
}

export interface GrantLifecycleOptions {
  /** Consume single-use grants and claim budget on ALLOW. False for evaluation-only paths. */
  readonly enforce: boolean;
}

interface BudgetClaim {
  readonly key: string;
  readonly currency: string;
  readonly amountMicros: number;
  readonly ceilingMicros: number;
  /** Set when idempotency is on and the request carries an id. */
  readonly idempotency?: { readonly requestKey: string; readonly actionHash: string };
}

/**
 * Work out whether this request spends against a budget. Returns null when it
 * does not, or when its cost cannot be read (the kernel refuses that case).
 */
async function readBudgetClaim(request: VerificationRequest, idempotent: boolean): Promise<BudgetClaim | null> {
  const budget = request.authority.constraints.budget;
  if (budget === undefined || request.principal === null) return null;
  if (!budget.actions.includes(request.action.type)) return null;
  const pricing = priceAction(request, budget.currency);
  if (!pricing.priced) return null;
  const requestId = request.context.request_id;
  return {
    key: await budgetKey(request.principal.id, budget.id),
    currency: budget.currency,
    amountMicros: pricing.amountMicros,
    ceilingMicros: ceilingToMicrosFloor(budget.ceiling),
    ...(idempotent && requestId !== null
      ? {
          idempotency: {
            requestKey: await sha256(requestId),
            actionHash: await sha256(
              canonicalize({ agent: request.agent.id, type: request.action.type, parameters: request.action.parameters }),
            ),
          },
        }
      : {}),
  };
}

function budgetIdempotencyOn(options: TransportOptions): boolean {
  return options.budgetIdempotencySource?.trim() === "request_id";
}

interface UsageClaim {
  readonly key: string;
  readonly windowStart: number;
  readonly windowSeconds: number;
  /** Inclusive call bound for the window; null when only an amount is bound. */
  readonly maxCalls: number | null;
  readonly amountMicros: number;
  /** Inclusive spend bound for the window; null when only calls are bound. */
  readonly ceilingMicros: number | null;
  readonly currency: string | null;
}

/** No-bound sentinel: SQLite integers are 64-bit, so this always passes. */
const USAGE_NO_BOUND = Number.MAX_SAFE_INTEGER;

/**
 * Work out whether this request counts against a usage window. Returns null
 * when it does not, or when its cost cannot be read (the kernel refuses that
 * case with USAGE_UNPRICED before any ledger lookup).
 */
async function readUsageClaim(
  request: VerificationRequest,
  nowSeconds: number,
): Promise<UsageClaim | null> {
  const usage = request.authority.constraints.usage;
  if (usage === undefined || request.principal === null) return null;
  let amountMicros = 0;
  if (usage.max_amount !== undefined) {
    const pricing = priceAction(request, usage.currency ?? "");
    if (!pricing.priced) return null;
    amountMicros = pricing.amountMicros;
  }
  return {
    key: await usageKey(request.principal.id, usage.id),
    windowStart: usageWindowStart(nowSeconds, usage.window_seconds),
    windowSeconds: usage.window_seconds,
    maxCalls: usage.max_calls ?? null,
    amountMicros,
    ceilingMicros:
      usage.max_amount === undefined
        ? null
        : ceilingToMicrosFloor(usage.max_amount),
    currency: usage.currency ?? null,
  };
}

async function readUsageState(
  db: D1Database,
  claim: UsageClaim,
): Promise<UsageState> {
  try {
    const row = await db
      .prepare(
        "SELECT calls, spent_micros, currency FROM usage_ledger WHERE usage_key = ? AND window_start = ?",
      )
      .bind(claim.key, claim.windowStart)
      .first<{ calls: number; spent_micros: number; currency: string | null }>();
    if (row === null || row === undefined) {
      return { available: true, calls: 0, spentMicros: 0, storedCurrency: null };
    }
    return {
      available: true,
      calls: Number(row.calls),
      spentMicros: Number(row.spent_micros),
      storedCurrency: row.currency,
    };
  } catch {
    // A missing table or a D1 error is "unknown", never "nothing used".
    return { available: false };
  }
}

/**
 * Count the call atomically. The bound checks and the increment are one
 * UPDATE, so two concurrent calls cannot both fit under the same headroom.
 */
async function claimUsage(db: D1Database, claim: UsageClaim): Promise<boolean> {
  const now = Math.floor(Date.now() / 1000);
  try {
    await db
      .prepare(
        "INSERT OR IGNORE INTO usage_ledger (usage_key, window_start, window_seconds, calls, spent_micros, currency, updated_at) " +
          "VALUES (?, ?, ?, 0, 0, ?, ?)",
      )
      .bind(claim.key, claim.windowStart, claim.windowSeconds, claim.currency, now)
      .run();
    // A calls-only claim carries no currency; a NULL comparison would
    // silently reject every update, so the guard applies only when set.
    const currencyGuard =
      claim.currency === null ? "" : " AND (currency IS NULL OR currency = ?)";
    const bindings: unknown[] = [
      claim.amountMicros,
      now,
      claim.key,
      claim.windowStart,
      claim.maxCalls ?? USAGE_NO_BOUND,
      claim.amountMicros,
      claim.ceilingMicros ?? USAGE_NO_BOUND,
      ...(claim.currency === null ? [] : [claim.currency]),
    ];
    const outcome = await db
      .prepare(
        "UPDATE usage_ledger SET calls = calls + 1, spent_micros = spent_micros + ?, updated_at = ? " +
          "WHERE usage_key = ? AND window_start = ? AND calls + 1 <= ? AND spent_micros + ? <= ?" +
          currencyGuard,
      )
      .bind(...(bindings as never[]))
      .run();
    return Number(outcome.meta?.changes ?? 0) === 1;
  } catch {
    return false;
  }
}

/** Undo a claim when a later step (single-use) refuses the same call. */
async function releaseUsage(db: D1Database, claim: UsageClaim): Promise<void> {
  const now = Math.floor(Date.now() / 1000);
  await db
    .prepare(
      "UPDATE usage_ledger SET calls = calls - 1, spent_micros = spent_micros - ?, updated_at = ? " +
        "WHERE usage_key = ? AND window_start = ? AND calls >= 1 AND spent_micros >= ?",
    )
    .bind(claim.amountMicros, now, claim.key, claim.windowStart, claim.amountMicros)
    .run();
}

type Admission = "none" | "same" | "conflict" | "unknown";

async function readAdmission(db: D1Database, claim: BudgetClaim): Promise<Admission> {
  if (claim.idempotency === undefined) return "none";
  try {
    const row = await db
      .prepare("SELECT action_hash FROM budget_admissions WHERE budget_key = ? AND request_key = ?")
      .bind(claim.key, claim.idempotency.requestKey)
      .first<{ action_hash: string }>();
    if (row === null || row === undefined) return "none";
    return row.action_hash === claim.idempotency.actionHash ? "same" : "conflict";
  } catch {
    return "unknown";
  }
}

async function readBudgetState(db: D1Database, claim: BudgetClaim): Promise<BudgetState> {
  const admission = await readAdmission(db, claim);
  if (admission === "unknown") return { available: false };
  try {
    const row = await db
      .prepare("SELECT spent_micros, currency FROM budget_ledger WHERE budget_key = ?")
      .bind(claim.key)
      .first<{ spent_micros: number; currency: string }>();
    if (row === null || row === undefined) return { available: true, spentMicros: 0, storedCurrency: null };
    const spent = Number(row.spent_micros);
    // A repeat of an admitted request is already inside `spent`; do not count it twice.
    const base = admission === "same" ? Math.max(0, spent - claim.amountMicros) : spent;
    return {
      available: true,
      spentMicros: base,
      storedCurrency: row.currency,
      ...(admission === "conflict" ? { requestIdConflict: true } : {}),
    };
  } catch {
    // A missing table or a D1 error is "unknown", never "nothing spent".
    return { available: false };
  }
}

/**
 * Admit the spend atomically. The ceiling check and the increment are one
 * UPDATE, so two concurrent calls cannot both fit under the same headroom.
 */
async function claimBudget(db: D1Database, claim: BudgetClaim): Promise<boolean> {
  const now = Math.floor(Date.now() / 1000);
  try {
    if ((await readAdmission(db, claim)) === "same") return true; // already counted
    if ((await readAdmission(db, claim)) !== "none" && claim.idempotency !== undefined) return false;
    await db
      .prepare(
        "INSERT OR IGNORE INTO budget_ledger (budget_key, currency, spent_micros, admissions, updated_at) " +
          "VALUES (?, ?, 0, 0, ?)",
      )
      .bind(claim.key, claim.currency, now)
      .run();
    const outcome = await db
      .prepare(
        "UPDATE budget_ledger SET spent_micros = spent_micros + ?, admissions = admissions + 1, updated_at = ? " +
          "WHERE budget_key = ? AND currency = ? AND spent_micros + ? <= ?",
      )
      .bind(claim.amountMicros, now, claim.key, claim.currency, claim.amountMicros, claim.ceilingMicros)
      .run();
    if (Number(outcome.meta?.changes ?? 0) !== 1) return false;
    if (claim.idempotency !== undefined) {
      // Count first, record second: a crash in between over-counts a retry
      // (fails closed) and never lets it through uncounted.
      const recorded = await db
        .prepare(
          "INSERT OR IGNORE INTO budget_admissions (budget_key, request_key, action_hash, amount_micros, created_at) " +
            "VALUES (?, ?, ?, ?, ?)",
        )
        .bind(claim.key, claim.idempotency.requestKey, claim.idempotency.actionHash, claim.amountMicros, now)
        .run();
      if (Number(recorded.meta?.changes ?? 0) !== 1) {
        // A concurrent call with the same request id was admitted first.
        await releaseBudget(db, claim);
        return (await readAdmission(db, claim)) === "same";
      }
    }
    return true;
  } catch {
    return false;
  }
}

/** Undo a claim when a later step (single-use) refuses the same call. */
async function releaseBudget(db: D1Database, claim: BudgetClaim): Promise<void> {
  const now = Math.floor(Date.now() / 1000);
  await db
    .prepare(
      "UPDATE budget_ledger SET spent_micros = spent_micros - ?, admissions = admissions - 1, updated_at = ? " +
        "WHERE budget_key = ? AND spent_micros >= ? AND admissions >= 1",
    )
    .bind(claim.amountMicros, now, claim.key, claim.amountMicros)
    .run();
}

/**
 * Run the kernel with grant lifecycle state resolved. A single-use grant that
 * is ALLOWed is consumed atomically. If a concurrent request consumed it
 * first, the kernel is re-run with the grant marked used, so the loser gets a
 * BLOCK with GRANT_ALREADY_USED rather than a second ALLOW.
 *
 * A budgeted call is checked against the cumulative ledger before the kernel
 * decides, and its amount is claimed atomically after an ALLOW. A losing race
 * re-runs the kernel against the fresh ledger, so it gets BLOCK with
 * BUDGET_CEILING_EXCEEDED rather than a second ALLOW.
 */
export async function verifyWithGrantLifecycle(
  request: VerificationRequest,
  verifyOptions: VerificationOptions,
  options: TransportOptions,
  lifecycle: GrantLifecycleOptions,
): Promise<VerificationResponse> {
  const result = await decideWithGrantLifecycle(request, verifyOptions, options, lifecycle);
  if (lifecycle.enforce) await recordActivity(options, result);
  return result;
}

async function decideWithGrantLifecycle(
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
  const budgetClaim = await readBudgetClaim(request, budgetIdempotencyOn(options));
  const usageClaim = await readUsageClaim(request, now);
  const [isRevoked, isUsed, budgetState, usageState] = await Promise.all([
    options.db === undefined
      ? Promise.resolve(memHas(memoryRevoked, hints.jti, now))
      : dbHas(options.db, "revoked_grants", hints.jti, now),
    hints.singleUse && options.db !== undefined
      ? dbHas(options.db, "consumed_grants", hints.jti, now)
      : Promise.resolve(false),
    budgetClaim !== null && options.db !== undefined
      ? readBudgetState(options.db, budgetClaim)
      : Promise.resolve<BudgetState | undefined>(undefined),
    usageClaim !== null && options.db !== undefined
      ? readUsageState(options.db, usageClaim)
      : Promise.resolve<UsageState | undefined>(undefined),
  ]);
  if (isRevoked) revoked.add(hints.jti);
  if (isUsed) used.add(hints.jti);

  const withState = (
    usedIds: ReadonlySet<string>,
    budget: BudgetState | undefined,
    usage: UsageState | undefined,
  ): VerificationOptions => ({
    ...verifyOptions,
    revokedGrantIds: revoked,
    usedGrantIds: usedIds,
    ...(budget === undefined ? {} : { budget }),
    ...(usage === undefined ? {} : { usage }),
    // Enforcement without a durable store fails single-use grants closed.
    // Evaluation-only paths do not consume, so they keep their old semantics.
    ...(lifecycle.enforce ? { singleUseStateDurable: options.db !== undefined } : {}),
  });
  const result = await verifyAction(request, withState(used, budgetState, usageState));

  const signedAllow =
    lifecycle.enforce &&
    result.decision === "ALLOW" &&
    result.receipt.authority_provenance === "principal_signed" &&
    result.receipt.grant?.jti === hints.jti;
  if (!signedAllow) return result;

  const db = options.db;
  let claimedBudget = false;
  if (budgetClaim !== null && db !== undefined) {
    if (await claimBudget(db, budgetClaim)) {
      claimedBudget = true;
    } else {
      // Lost a race (or the ledger failed). Re-read and decide again; if the
      // ledger still says it fits, force a refusal rather than an ALLOW.
      const fresh = await readBudgetState(db, budgetClaim);
      const forced: BudgetState = fresh.available
        ? {
            ...fresh,
            spentMicros: Math.max(
              fresh.spentMicros,
              budgetClaim.ceilingMicros - budgetClaim.amountMicros + 1,
            ),
          }
        : fresh;
      return verifyAction(request, withState(used, forced, usageState));
    }
  }

  let claimedUsage = false;
  if (usageClaim !== null && db !== undefined) {
    if (await claimUsage(db, usageClaim)) {
      claimedUsage = true;
    } else {
      // Lost a race (or the ledger failed). Re-read and decide again; if the
      // ledger still says the call fits, force a refusal rather than an ALLOW.
      const fresh = await readUsageState(db, usageClaim);
      const forced: UsageState = fresh.available
        ? {
            ...fresh,
            calls:
              usageClaim.maxCalls === null
                ? fresh.calls
                : Math.max(fresh.calls, usageClaim.maxCalls),
            spentMicros:
              usageClaim.ceilingMicros === null
                ? fresh.spentMicros
                : Math.max(
                    fresh.spentMicros,
                    usageClaim.ceilingMicros - usageClaim.amountMicros + 1,
                  ),
          }
        : fresh;
      if (claimedBudget && budgetClaim !== null) {
        await releaseBudget(db, budgetClaim);
      }
      return verifyAction(request, withState(used, budgetState, forced));
    }
  }

  if (!hints.singleUse) return result;
  if (await claimConsumption(options, hints)) {
    return result;
  }
  if (claimedBudget && db !== undefined && budgetClaim !== null) {
    await releaseBudget(db, budgetClaim);
  }
  if (claimedUsage && db !== undefined && usageClaim !== null) {
    await releaseUsage(db, usageClaim);
  }
  return verifyAction(
    request,
    withState(new Set([...used, hints.jti]), budgetState, usageState),
  );
}

/** Test hook: clear per-isolate fallback state. */
export function resetGrantLifecycleMemory(): void {
  memoryRevoked.clear();
}
