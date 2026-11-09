import { VizierError } from "./index.js";
import type {
  JsonValue,
  VerificationRequest,
  VerificationResponse,
  VerifyOptions,
  Vizier,
} from "./index.js";

/**
 * Executor being protected: a function that bans one account. The adapter
 * calls it only after Vizier establishes an ALLOW for the exact same
 * arguments.
 */
export interface BanExecutor<A extends unknown[], R> {
  ban(target: string, ...args: A): R | Promise<R>;
}

/**
 * Configuration of the opt-in typed ban-account guard. Everything the guard
 * cannot derive from the actual executor call is pinned here once per
 * integration, not per call: the agent, the principal, the signed grant, the
 * authority the grant must match, the action type and the declared
 * reversibility of a ban.
 */
export interface BanAccountGuardOptions<A extends unknown[] = unknown[]> {
  /** Agent that executes the bans; must be the grant's subject. */
  agentId: string;
  /** Principal that signed the grant; must be the grant's issuer. */
  principalId: string;
  /** Owner of the agent; defaults to the principal. */
  agentOwner?: string | null;
  /** Compact JWS grant signed by the principal. */
  grant: string;
  /**
   * Authority the caller claims; Vizier BLOCKs it with
   * GRANT_AUTHORITY_MISMATCH unless it matches the signed grant exactly.
   */
  authority: VerificationRequest["authority"];
  /** Action type to evaluate; defaults to "ban_account". */
  actionType?: string;
  /**
   * Declared reversibility of a ban. Defaults to false (irreversible), so a
   * policy with require_review_for_irreversible still forces review. Pinned
   * per integration; a caller cannot mark one call reversible on its own.
   */
  isReversible?: boolean;
  /** Static parameters recorded on every evaluated action (e.g. a reason). */
  baseParameters?: Record<string, JsonValue>;
  /**
   * Fold the actual executor call arguments into the evaluated action
   * parameters, so what Vizier checks is what will run. Overrides
   * baseParameters.
   */
  deriveParameters?: (target: string, ...args: A) => Record<string, JsonValue>;
  /** Forwarded to authorize(), e.g. { requireReceiptJws: true }. */
  authorizeOptions?: VerifyOptions;
  /** Called with the established authorization receipt before execution. */
  onAuthorized?: (response: VerificationResponse) => void;
}

/**
 * Opt-in typed adapter for one workflow: account bans. It wraps an executor
 * so that the action Vizier evaluates is built from the arguments of the
 * actual executor call, not from a separately assembled request: the target,
 * reversibility and parameters the guard checks are the ones that will run,
 * and the executor is invoked only after authorize() establishes an ALLOW.
 * A refusal (BLOCK/REVIEW, grant mismatch, missing credential) propagates as
 * a VizierError and the executor is never called.
 *
 * What this closes: a call site cannot ask Vizier about one account and then
 * ban another, or mark a ban reversible per call. What it does not prove: the
 * guard is only an enforcement point when the agent has no other path to the
 * executor; host isolation stays an operator responsibility. Defaults and
 * legacy behavior are unchanged for callers that do not opt in.
 */
export function guardBanAccount<A extends unknown[], R>(
  client: Vizier,
  options: BanAccountGuardOptions<A>,
  executor: BanExecutor<A, R>,
): BanExecutor<A, Promise<R>> {
  const actionType = options.actionType ?? "ban_account";
  const isReversible = options.isReversible ?? false;
  return {
    async ban(target: string, ...args: A): Promise<R> {
      if (typeof target !== "string" || target.length === 0) {
        throw new VizierError("A non-empty ban target is required.", 0, "INVALID_REQUEST");
      }
      const parameters = options.deriveParameters
        ? options.deriveParameters(target, ...args)
        : { ...options.baseParameters };
      const request: VerificationRequest = {
        agent: {
          id: options.agentId,
          owner: options.agentOwner ?? options.principalId,
        },
        principal: { id: options.principalId },
        action: {
          type: actionType,
          target,
          parameters,
          is_reversible: isReversible,
        },
        authority: options.authority,
        context: {
          request_id: crypto.randomUUID(),
          timestamp: null,
          source: "rest",
        },
        grant: options.grant,
      };
      const established = await client.authorize(request, options.authorizeOptions ?? {});
      options.onAuthorized?.(established);
      return executor.ban(target, ...args);
    },
  };
}
