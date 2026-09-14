import type { KVNamespace } from "@cloudflare/workers-types";
import { canonicalize, sha256 } from "./receipts";
import type { VerificationRequest } from "./schemas";

export const DEFAULT_MAX_REPEATED_CALLS = 5;
export const DEFAULT_TIME_WINDOW_SECONDS = 30;
export const DEFAULT_COOL_OFF_SECONDS = 60;
export const DEFAULT_MAX_SESSION_ACTIONS = 100;

export interface EdgeCircuitBreakerResult {
  readonly tripped: boolean;
  readonly reasonCode?: "CIRCUIT_TRIPPED:LOOP_DETECTED" | "CIRCUIT_TRIPPED:BUDGET_EXCEEDED";
  readonly message?: string;
  readonly details?: Readonly<Record<string, unknown>>;
}

export interface EdgeCircuitBreakerOptions {
  readonly now?: Date;
}

export async function evaluateEdgeCircuitBreaker(
  kv: KVNamespace,
  request: VerificationRequest,
  options: EdgeCircuitBreakerOptions = {},
): Promise<EdgeCircuitBreakerResult> {
  const nowMs = (options.now ?? new Date()).getTime();
  const sessionId = request.context.session_id ?? request.agent.id;

  const maxRepeats =
    request.authority.constraints.max_repeated_calls ?? DEFAULT_MAX_REPEATED_CALLS;
  const windowSeconds =
    request.authority.constraints.time_window_seconds ?? DEFAULT_TIME_WINDOW_SECONDS;
  const coolOffSeconds =
    request.authority.constraints.cool_off_seconds ?? DEFAULT_COOL_OFF_SECONDS;
  const maxSessionActions =
    request.authority.constraints.max_session_actions ?? DEFAULT_MAX_SESSION_ACTIONS;

  const trippedKey = `cb:tripped:${sessionId}`;
  const epochKey = `cb:epoch:${sessionId}`;

  try {
    // 1. Check if session is currently tripped
    const trippedRaw = await kv.get(trippedKey);
    if (trippedRaw !== null) {
      const trippedData = JSON.parse(trippedRaw) as {
        code: "CIRCUIT_TRIPPED:LOOP_DETECTED" | "CIRCUIT_TRIPPED:BUDGET_EXCEEDED";
        message: string;
        trippedAt: number;
      };
      const elapsedSec = (nowMs - trippedData.trippedAt) / 1000;
      if (elapsedSec < coolOffSeconds) {
        const remaining = Math.max(1, Math.ceil(coolOffSeconds - elapsedSec));
        return {
          tripped: true,
          reasonCode: trippedData.code,
          message: `Circuit breaker active for session '${sessionId}'. Cool-off remaining: ${remaining}s. (${trippedData.message})`,
          details: {
            session_id: sessionId,
            cool_off_remaining_s: remaining,
            reason: trippedData.code,
          },
        };
      }
    }

    // 2. Fetch session epoch (version)
    const epochRaw = await kv.get(epochKey);
    const epoch = epochRaw ?? "0";
    const budgetKey = `cb:budget:${sessionId}:${epoch}`;

    // 3. Check session budget
    const budgetRaw = await kv.get(budgetKey);
    const currentBudget = budgetRaw ? parseInt(budgetRaw, 10) : 0;
    if (currentBudget >= maxSessionActions) {
      const message = `Session action budget of ${maxSessionActions} exceeded for session '${sessionId}'.`;
      await kv.put(
        trippedKey,
        JSON.stringify({
          code: "CIRCUIT_TRIPPED:BUDGET_EXCEEDED",
          message,
          trippedAt: nowMs,
        }),
        { expirationTtl: Math.max(60, Math.ceil(coolOffSeconds)) },
      );
      return {
        tripped: true,
        reasonCode: "CIRCUIT_TRIPPED:BUDGET_EXCEEDED",
        message,
        details: {
          session_id: sessionId,
          total_actions: currentBudget,
          max_session_actions: maxSessionActions,
        },
      };
    }

    // 4. Sliding-window loop detection for identical tool parameters
    const paramHash = await sha256(canonicalize(request.action.parameters));
    const signature = `${request.action.type}:${request.action.target}:${paramHash}`;
    const signatureHash = await sha256(signature);
    const loopKey = `cb:loop:${sessionId}:${epoch}:${signatureHash}`;

    const historyRaw = await kv.get(loopKey);
    const cutoffMs = nowMs - windowSeconds * 1000;
    const timestamps: number[] = historyRaw
      ? (JSON.parse(historyRaw) as number[]).filter((ts) => ts >= cutoffMs)
      : [];

    if (timestamps.length >= maxRepeats) {
      const message = `Potential infinite tool-calling loop detected: action '${request.action.type}' called ${timestamps.length + 1} times with identical parameters within ${windowSeconds}s.`;
      await kv.put(
        trippedKey,
        JSON.stringify({
          code: "CIRCUIT_TRIPPED:LOOP_DETECTED",
          message,
          trippedAt: nowMs,
        }),
        { expirationTtl: Math.max(60, Math.ceil(coolOffSeconds)) },
      );
      return {
        tripped: true,
        reasonCode: "CIRCUIT_TRIPPED:LOOP_DETECTED",
        message,
        details: {
          session_id: sessionId,
          action_type: request.action.type,
          target: request.action.target,
          repeats: timestamps.length + 1,
          window_seconds: windowSeconds,
        },
      };
    }

    // 5. Update history and budget in KV
    timestamps.push(nowMs);
    const loopTtl = Math.max(60, Math.ceil(windowSeconds * 2));
    const budgetTtl = Math.max(3600, Math.ceil(coolOffSeconds * 2));

    await Promise.all([
      kv.put(loopKey, JSON.stringify(timestamps), { expirationTtl: loopTtl }),
      kv.put(budgetKey, String(currentBudget + 1), { expirationTtl: budgetTtl }),
    ]);

    return { tripped: false };
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : "Unknown KV error";
    console.error(
      JSON.stringify({
        event: "vizier.circuit_breaker.error",
        session_id: sessionId,
        error: errorMsg,
      }),
    );
    // Fail-closed to preserve SECURITY.md invariant 1: if security evaluation errors, block execution
    return {
      tripped: true,
      reasonCode: "CIRCUIT_TRIPPED:LOOP_DETECTED",
      message: `Circuit breaker storage error: ${errorMsg}. Action blocked.`,
      details: {
        session_id: sessionId,
        error: errorMsg,
      },
    };
  }
}

export async function resetEdgeCircuitBreaker(
  kv: KVNamespace,
  sessionId: string,
): Promise<void> {
  await Promise.all([
    kv.delete(`cb:tripped:${sessionId}`),
    kv.put(`cb:epoch:${sessionId}`, String(Date.now()), { expirationTtl: 86400 }),
  ]);
}
