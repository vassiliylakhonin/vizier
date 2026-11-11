import { sha256 } from "./receipts";
import type { VerificationRequest } from "./schemas";

/**
 * Cumulative budget ceiling.
 *
 * `max_amount` bounds one call. A budget bounds the running total of every
 * ALLOWed call that spends under one principal-signed budget id. Amounts are
 * held as integer micro-units so that adding them is exact.
 *
 * Rounding always favours the principal: a spend rounds up, a ceiling rounds
 * down. The ledger records what was admitted at ALLOW, not what the executor
 * finally settled.
 */
export const MICROS_PER_UNIT = 1_000_000;

/** Largest ceiling, in whole currency units, that stays an exact integer. */
export const MAX_BUDGET_CEILING_UNITS = 1_000_000_000;

export type BudgetPricing =
  | { readonly priced: true; readonly amountMicros: number }
  | { readonly priced: false; readonly reason: "amount_missing" | "amount_invalid" | "currency_mismatch" };

/** Round a spend up to whole micro-units. Returns null when it is not a safe integer amount. */
export function amountToMicrosCeil(amount: number): number | null {
  if (!Number.isFinite(amount) || amount < 0) return null;
  const micros = Math.ceil(Number((amount * MICROS_PER_UNIT).toPrecision(15)));
  return Number.isSafeInteger(micros) ? micros : null;
}

/** Round a ceiling down to whole micro-units. */
export function ceilingToMicrosFloor(ceiling: number): number {
  return Math.floor(Number((ceiling * MICROS_PER_UNIT).toPrecision(15)));
}

/**
 * Price a proposed call. A call whose cost cannot be read exactly is
 * `priced: false`. It is never treated as costing zero.
 */
export function priceAction(
  request: VerificationRequest,
  currency: string,
): BudgetPricing {
  const { amount, currency: provided } = request.action.parameters;
  if (amount === undefined || amount === null) {
    return { priced: false, reason: "amount_missing" };
  }
  if (typeof amount !== "number") {
    return { priced: false, reason: "amount_invalid" };
  }
  const micros = amountToMicrosCeil(amount);
  if (micros === null) return { priced: false, reason: "amount_invalid" };
  if (provided !== currency) return { priced: false, reason: "currency_mismatch" };
  return { priced: true, amountMicros: micros };
}

/** Ledger key: no readable principal or budget id is stored. */
export async function budgetKey(principalId: string, budgetId: string): Promise<string> {
  return sha256(`${principalId}\n${budgetId}`);
}

/** What the transport read from the ledger before the kernel runs. */
export type BudgetState =
  | { readonly available: true; readonly spentMicros: number; readonly storedCurrency: string | null }
  | { readonly available: false };
