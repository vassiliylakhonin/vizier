import { VizierError } from "./index.js";
import type {
  JsonValue,
  VerificationRequest,
  VerificationResponse,
  VerifyOptions,
  Vizier,
} from "./index.js";

/** The payment the executor will make. The guard evaluates exactly these values. */
export interface PaymentCall {
  /** Payee or destination, as the executor receives it. */
  target: string;
  /** Amount in whole currency units, as the executor receives it. */
  amount: number;
  currency: string;
  /**
   * Idempotency key for this payment. Reuse the same value when retrying the
   * same payment. With `VIZIER_BUDGET_IDEMPOTENCY=request_id` on the server,
   * a repeated key is counted against the budget once. Defaults to a fresh
   * random id, which makes every call count.
   */
  requestId?: string;
  /** Extra parameters recorded on the evaluated action (not used for pricing). */
  extra?: Record<string, JsonValue>;
}

export interface PaymentExecutor<R> {
  pay(call: PaymentCall): R | Promise<R>;
}

export interface PaymentGuardOptions {
  agentId: string;
  principalId: string;
  agentOwner?: string | null;
  /** Compact JWS grant signed by the principal. */
  grant: string;
  authority: VerificationRequest["authority"];
  /** Action type to evaluate; defaults to "payment". */
  actionType?: string;
  /** Declared per integration, default false (irreversible). */
  isReversible?: boolean;
  authorizeOptions?: VerifyOptions;
  onAuthorized?: (response: VerificationResponse) => void;
}

/**
 * Opt-in typed adapter for payments. The amount and currency Vizier prices
 * against a budget ceiling are taken from the same call that reaches the
 * executor, so a call site cannot ask about one amount and pay another.
 *
 * Limits, stated plainly: the Vizier server does not verify the price. It
 * trusts the amount this integration reports, and it counts admitted amounts,
 * not settled money. The guard only enforces anything if the agent has no
 * other path to the payment executor. Callers that do not use it are unchanged.
 */
export function guardPayment<R>(
  client: Vizier,
  options: PaymentGuardOptions,
  executor: PaymentExecutor<R>,
): PaymentExecutor<Promise<R>> {
  return {
    async pay(call: PaymentCall): Promise<R> {
      if (typeof call.target !== "string" || call.target.length === 0) {
        throw new VizierError("A non-empty payment target is required.", 0, "INVALID_REQUEST");
      }
      if (typeof call.amount !== "number" || !Number.isFinite(call.amount) || call.amount < 0) {
        throw new VizierError("A finite non-negative amount is required.", 0, "INVALID_REQUEST");
      }
      if (typeof call.currency !== "string" || call.currency.length === 0) {
        throw new VizierError("A currency is required.", 0, "INVALID_REQUEST");
      }
      const request: VerificationRequest = {
        agent: { id: options.agentId, owner: options.agentOwner ?? options.principalId },
        principal: { id: options.principalId },
        action: {
          type: options.actionType ?? "payment",
          target: call.target,
          parameters: { ...call.extra, amount: call.amount, currency: call.currency },
          is_reversible: options.isReversible ?? false,
        },
        authority: options.authority,
        context: {
          request_id: call.requestId ?? crypto.randomUUID(),
          timestamp: null,
          source: "rest",
        },
        grant: options.grant,
      };
      const established = await client.authorize(request, options.authorizeOptions ?? {});
      options.onAuthorized?.(established);
      return executor.pay(call);
    },
  };
}
