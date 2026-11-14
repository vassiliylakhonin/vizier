import { sha256 } from "./receipts";

/**
 * Per-principal aggregate bounds over a fixed time window (R4, first step).
 *
 * `max_amount` bounds one call. A budget bounds cumulative spend with no time
 * bound. Usage bounds close the gap between them: at most this many calls
 * and/or this much cumulative amount per principal per window. Windows are
 * fixed tumbling windows aligned to the Unix epoch, not sliding: counters
 * reset when the window rolls over.
 *
 * This bounds the number and total admitted price of calls. It is not
 * information-flow tracking: it does not measure what a call read, returned
 * or caused, and it does not relate use back to an originating task scope.
 */
export const MAX_USAGE_WINDOW_SECONDS = 366 * 24 * 60 * 60;

/** What the transport read from the ledger before the kernel runs. */
export type UsageState =
  | {
      readonly available: true;
      readonly calls: number;
      readonly spentMicros: number;
      readonly storedCurrency: string | null;
    }
  | { readonly available: false };

/** Ledger key: no readable principal or usage id is stored. */
export async function usageKey(
  principalId: string,
  usageId: string,
): Promise<string> {
  return sha256(`${principalId}\n${usageId}`);
}

/** Fixed tumbling window aligned to the Unix epoch. */
export function usageWindowStart(
  nowSeconds: number,
  windowSeconds: number,
): number {
  return Math.floor(nowSeconds / windowSeconds) * windowSeconds;
}
