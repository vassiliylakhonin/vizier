import { ceilingToMicrosFloor, priceAction, type BudgetState } from "./budget";
import type { UsageState } from "./usage";
import type { EdgeCircuitBreakerResult } from "./circuit-breaker";
import type { DlpEvaluationResult } from "./dlp";
import type { NumericConsistencyEvaluationResult } from "./numeric-consistency";
import type { GrantVerification } from "./grants";
import type { PolicyResult } from "./types";
import type { QuorumEvaluationResult } from "./quorum";
import type { SanctionsEvaluationResult } from "./sanctions";
import type { VerificationRequest } from "./schemas";

export const DEFAULT_SENSITIVE_ACTIONS = Object.freeze([
  "transfer_funds",
  "delete_data",
  "deploy_worker",
  "execute_code",
  "send_external_message",
  "modify_permissions",
  "sign_contract",
] as const);

export type PolicyEvaluator = (request: VerificationRequest) => PolicyResult | readonly PolicyResult[];

export interface PolicyOptions {
  readonly sensitiveActions?: readonly string[];
  readonly trustedAuthority?: boolean;
  readonly signedGrantMode?: "optional" | "required" | "invalid";
  readonly customPolicies?: readonly PolicyEvaluator[];
  /**
   * Outcome of verifying a principal-signed delegation grant, when the request
   * carried one. Verification is async and happens before policy evaluation so
   * that this function stays synchronous and deterministic.
   */
  readonly grantVerification?: GrantVerification;
  readonly circuitBreaker?: EdgeCircuitBreakerResult;
  readonly sanctions?: SanctionsEvaluationResult;
  readonly dlp?: DlpEvaluationResult;
  readonly numericConsistency?: NumericConsistencyEvaluationResult;
  readonly quorum?: QuorumEvaluationResult;
  /**
   * Cumulative budget ledger state, read by the transport before the call.
   * Absent means no durable ledger is bound: a budgeted request fails closed.
   */
  readonly budget?: BudgetState;
  /**
   * Per-window usage ledger state, read by the transport before the call.
   * Absent means no durable ledger is bound: a usage-bounded request fails
   * closed.
   */
  readonly usage?: UsageState;
}

function result(
  ruleId: string,
  status: PolicyResult["result"],
  reasonCode: string | null,
  details: Readonly<Record<string, unknown>> = {},
): PolicyResult {
  return Object.freeze({
    rule_id: ruleId,
    result: status,
    reason_code: reasonCode,
    details: Object.freeze({ ...details }),
  });
}

function evaluatePrincipal(
  request: VerificationRequest,
  grant: GrantVerification | undefined,
  trustedAuthority: boolean,
): PolicyResult {
  if (request.principal === null) {
    return result("principal.verified", "REVIEW", "PRINCIPAL_UNVERIFIED");
  }
  // A verified grant makes this cryptographic rather than a matter of the
  // caller having typed a principal id into the request.
  return grant?.ok === true
    ? result("principal.verified", "PASS", null, {
        verified_by: "delegation_grant",
        key_id: grant.grant.key_id,
      })
    : trustedAuthority
      ? result("principal.verified", "PASS", null, {verification_status:"integration_asserted", signature_verified:false})
      : result("principal.verified", "REVIEW", "PRINCIPAL_UNVERIFIED", {verification_status:"caller_asserted", signature_verified:false});
}

/**
 * Evaluate a principal-signed delegation grant, when one was supplied.
 *
 * Presenting a grant is an instruction to verify it. A grant that does not
 * verify therefore fails the request outright rather than degrading to the
 * caller-asserted path — otherwise a forged grant would be strictly better for
 * an attacker than sending none at all.
 */
function evaluateDelegationGrant(grant: GrantVerification): PolicyResult {
  return grant.ok
    ? result("authority.grant.verified", "PASS", null, {
        jti: grant.grant.jti,
        issuer: grant.grant.issuer,
        subject: grant.grant.subject,
        key_id: grant.grant.key_id,
        expires_at: grant.grant.expires_at,
      })
    : result("authority.grant.verified", "FAIL", grant.code, grant.details);
}

function evaluateAuthorityProvenance(trustedAuthority: boolean): PolicyResult {
  return trustedAuthority
    ? result("integration.authority.trusted", "PASS", null)
    : result(
        "integration.authority.trusted",
        "REVIEW",
        "AUTHORITY_SOURCE_UNTRUSTED",
        { enforcement_mode: "evaluation" },
      );
}

function evaluateDelegatedAction(request: VerificationRequest): PolicyResult {
  const isDelegated = request.authority.allowed_actions.includes(request.action.type);
  return isDelegated
    ? result("authority.action.allowed", "PASS", null)
    : result("authority.action.allowed", "FAIL", "ACTION_NOT_DELEGATED", {
        action_type: request.action.type,
      });
}

function evaluateAmount(request: VerificationRequest): PolicyResult {
  const { max_amount: maximum, currency: delegatedCurrency } =
    request.authority.constraints;

  if (maximum === undefined) {
    return result("authority.amount.within_limit", "PASS", null, {
      applicable: false,
    });
  }

  const amount = request.action.parameters.amount;
  const currency = request.action.parameters.currency;
  if (typeof amount !== "number" || !Number.isFinite(amount) || amount < 0) {
    return result(
      "authority.amount.within_limit",
      "REVIEW",
      "AMOUNT_UNVERIFIED",
      { max_amount: maximum },
    );
  }

  if (delegatedCurrency !== undefined && currency !== delegatedCurrency) {
    return result(
      "authority.amount.within_limit",
      "REVIEW",
      "CURRENCY_UNVERIFIED",
      {
        expected_currency: delegatedCurrency,
        provided_currency: typeof currency === "string" ? currency : null,
      },
    );
  }

  return amount <= maximum
    ? result("authority.amount.within_limit", "PASS", null, {
        amount,
        max_amount: maximum,
      })
    : result(
        "authority.amount.within_limit",
        "FAIL",
        "AUTHORITY_LIMIT_EXCEEDED",
        { amount, max_amount: maximum },
      );
}

function evaluateTarget(request: VerificationRequest): PolicyResult {
  const { allowed_targets: allowed, blocked_targets: blocked } =
    request.authority.constraints;
  const { target } = request.action;

  if (blocked?.includes(target)) {
    return result("authority.target.allowed", "FAIL", "TARGET_BLOCKED", {
      target,
    });
  }

  if (allowed !== undefined && !allowed.includes(target)) {
    return result("authority.target.allowed", "FAIL", "TARGET_NOT_ALLOWED", {
      target,
    });
  }

  return result("authority.target.allowed", "PASS", null);
}

function evaluateSensitiveAction(
  request: VerificationRequest,
  sensitiveActions: readonly string[],
): PolicyResult {
  const { type } = request.action;
  if (!sensitiveActions.includes(type)) {
    return result("action.sensitive.explicitly_allowed", "PASS", null, {
      applicable: false,
    });
  }

  const isExplicitlyAllowed =
    request.authority.constraints.allowed_sensitive_actions?.includes(type) ?? false;
  return isExplicitlyAllowed
    ? result("action.sensitive.explicitly_allowed", "PASS", null)
    : result(
        "action.sensitive.explicitly_allowed",
        "REVIEW",
        "SENSITIVE_ACTION_REVIEW",
        { action_type: type },
      );
}

function evaluateBudget(
  request: VerificationRequest,
  grant: GrantVerification | undefined,
  state: BudgetState | undefined,
): PolicyResult | null {
  const budget = request.authority.constraints.budget;
  if (budget === undefined) return null;
  const rule = "authority.budget.ceiling";
  if (!budget.actions.includes(request.action.type)) {
    return result(rule, "PASS", null, { applicable: false });
  }
  // The ledger key comes from the principal and the budget id. Unsigned
  // authority could name a fresh id on every call and never reach a ceiling.
  if (grant?.ok !== true) {
    return result(rule, "FAIL", "BUDGET_REQUIRES_GRANT");
  }
  const pricing = priceAction(request, budget.currency);
  if (!pricing.priced) {
    // Unknown cost is not zero cost. The call is refused and the ledger is
    // untouched, so it is also not counted: coverage of the total is partial.
    return result(rule, "FAIL", "BUDGET_UNPRICED", {
      unpriced: true,
      coverage: "partial",
      reason: pricing.reason,
      budget_currency: budget.currency,
    });
  }
  if (state === undefined || !state.available) {
    return result(rule, "FAIL", "BUDGET_STATE_UNAVAILABLE");
  }
  if (state.storedCurrency !== null && state.storedCurrency !== budget.currency) {
    return result(rule, "FAIL", "BUDGET_CURRENCY_CONFLICT", {
      budget_currency: budget.currency,
      ledger_currency: state.storedCurrency,
    });
  }
  if (state.requestIdConflict === true) {
    return result(rule, "FAIL", "BUDGET_REQUEST_ID_CONFLICT");
  }
  const ceilingMicros = ceilingToMicrosFloor(budget.ceiling);
  const details = {
    budget_currency: budget.currency,
    ceiling_micros: ceilingMicros,
    spent_micros: state.spentMicros,
    requested_micros: pricing.amountMicros,
  };
  return state.spentMicros + pricing.amountMicros <= ceilingMicros
    ? result(rule, "PASS", null, details)
    : result(rule, "FAIL", "BUDGET_CEILING_EXCEEDED", details);
}

function evaluateUsage(
  request: VerificationRequest,
  grant: GrantVerification | undefined,
  state: UsageState | undefined,
): PolicyResult | null {
  const usage = request.authority.constraints.usage;
  if (usage === undefined) return null;
  const rule = "authority.usage.window";
  // The ledger key comes from the principal and the usage id. Unsigned
  // authority could name a fresh id on every call and never reach a bound.
  if (grant?.ok !== true) {
    return result(rule, "FAIL", "USAGE_REQUIRES_GRANT");
  }
  // Unknown cost is checked before the ledger, so an unpriced call reports
  // USAGE_UNPRICED rather than a misleading ledger failure.
  let amountMicros = 0;
  if (usage.max_amount !== undefined) {
    // The schema requires currency when max_amount is set.
    const pricing = priceAction(request, usage.currency ?? "");
    if (!pricing.priced) {
      return result(rule, "FAIL", "USAGE_UNPRICED", {
        unpriced: true,
        coverage: "partial",
        reason: pricing.reason,
        usage_currency: usage.currency,
      });
    }
    amountMicros = pricing.amountMicros;
  }
  if (state === undefined || !state.available) {
    return result(rule, "FAIL", "USAGE_STATE_UNAVAILABLE");
  }
  const details: Record<string, unknown> = {
    window_seconds: usage.window_seconds,
    calls_in_window: state.calls,
  };
  if (usage.max_calls !== undefined && state.calls >= usage.max_calls) {
    return result(rule, "FAIL", "USAGE_CALL_LIMIT_EXCEEDED", {
      ...details,
      max_calls: usage.max_calls,
    });
  }
  if (usage.max_amount !== undefined) {
    if (state.storedCurrency !== null && state.storedCurrency !== usage.currency) {
      return result(rule, "FAIL", "USAGE_CURRENCY_CONFLICT", {
        ...details,
        usage_currency: usage.currency,
        ledger_currency: state.storedCurrency,
      });
    }
    const ceilingMicros = ceilingToMicrosFloor(usage.max_amount);
    if (state.spentMicros + amountMicros > ceilingMicros) {
      return result(rule, "FAIL", "USAGE_AMOUNT_LIMIT_EXCEEDED", {
        ...details,
        usage_currency: usage.currency,
        window_limit_micros: ceilingMicros,
        spent_micros: state.spentMicros,
        requested_micros: amountMicros,
      });
    }
    details.window_limit_micros = ceilingMicros;
    details.spent_micros = state.spentMicros;
  }
  if (usage.max_calls !== undefined) details.max_calls = usage.max_calls;
  return result(rule, "PASS", null, details);
}

export function evaluateReversibility(request: VerificationRequest): PolicyResult {
  const requiresReversible = request.authority.constraints.require_review_for_irreversible ?? false;
  if (!requiresReversible) {
    return result("action.reversibility.not_required", "PASS", null);
  }
  return request.action.is_reversible === true
    ? result("action.reversibility.provided", "PASS", null)
    : result("action.reversibility.provided", "REVIEW", "IRREVERSIBLE_ACTION_REVIEW", {
        action_type: request.action.type,
      });
}

export function evaluatePolicies(
  request: VerificationRequest,
  options: PolicyOptions = {},
): readonly PolicyResult[] {
  const sensitiveActions = options.sensitiveActions ?? DEFAULT_SENSITIVE_ACTIONS;
  const { grantVerification } = options;
  const results: PolicyResult[] = [
    evaluateAuthorityProvenance(options.trustedAuthority ?? true),
    evaluatePrincipal(request, grantVerification, options.trustedAuthority ?? true),
    evaluateDelegatedAction(request),
    evaluateAmount(request),
    evaluateTarget(request),
    evaluateSensitiveAction(request, sensitiveActions),
    evaluateReversibility(request),
  ];

  const budgetResult = evaluateBudget(request, grantVerification, options.budget);
  if (budgetResult !== null) results.push(budgetResult);

  const usageResult = evaluateUsage(request, grantVerification, options.usage);
  if (usageResult !== null) results.push(usageResult);

  if (options.signedGrantMode === "invalid") {
    results.push(result("authority.grant.required", "FAIL", "GRANT_POLICY_MISCONFIGURED"));
  } else if (options.signedGrantMode === "required") {
    results.push(result("authority.grant.required", grantVerification?.ok === true ? "PASS" : "FAIL",
      grantVerification?.ok === true ? null : "GRANT_REQUIRED"));
  }

  if (grantVerification !== undefined) {
    results.push(evaluateDelegationGrant(grantVerification));
  }

  if (options.circuitBreaker !== undefined) {
    if (options.circuitBreaker.tripped) {
      results.push(
        result(
          "agent.circuit_breaker",
          "FAIL",
          options.circuitBreaker.reasonCode ?? "CIRCUIT_TRIPPED:LOOP_DETECTED",
          options.circuitBreaker.details ?? {},
        ),
      );
    } else {
      results.push(result("agent.circuit_breaker", "PASS", null));
    }
  }

  if (options.sanctions !== undefined) {
    if (!options.sanctions.clean && options.sanctions.match) {
      const is50Rule = options.sanctions.rule50_result !== undefined;
      const policyId = is50Rule ? "compliance.sanctions_50_rule" : "compliance.sanctions";
      const reasonCode =
        options.sanctions.rule50_result?.reason_codes[0] ??
        (options.sanctions.match.list === "SANCTIONS_50_RULE_VIOLATION"
          ? "SANCTIONS_50_RULE_VIOLATION"
          : "SANCTIONED_ENTITY_MATCH");

      results.push(
        result(
          policyId,
          "FAIL",
          reasonCode,
          {
            matched_value: options.sanctions.match.matched_value,
            entity_name: options.sanctions.match.entity_name,
            list: options.sanctions.match.list,
            candidate_type: options.sanctions.match.candidate_type,
            source: options.sanctions.match.source,
            ...(options.sanctions.match.details ?? {}),
            ...(options.sanctions.rule50_result
              ? {
                  aggregate_blocked_percentage: options.sanctions.rule50_result.aggregate_blocked_percentage,
                  threshold_percentage: options.sanctions.rule50_result.threshold_percentage,
                  blocked_shareholders: options.sanctions.rule50_result.blocked_shareholders,
                  explanation: options.sanctions.rule50_result.explanation,
                }
              : {}),
          },
        ),
      );
    } else {
      results.push(result("compliance.sanctions", "PASS", null));
    }
  }

  if (options.dlp !== undefined) {
    if (!options.dlp.clean && options.dlp.findings.length > 0) {
      results.push(
        result(
          "security.dlp",
          "FAIL",
          "SECRET_LEAK_PREVENTED",
          {
            findings: options.dlp.findings,
            total_leaks_prevented: options.dlp.total_leaks_prevented,
          },
        ),
      );
    } else {
      results.push(result("security.dlp", "PASS", null));
    }
  }

  if (options.numericConsistency !== undefined) {
    // Numeric inconsistency is a quality signal that needs human judgment:
    // it routes to REVIEW and never blocks on its own.
    if (
      !options.numericConsistency.consistent &&
      options.numericConsistency.findings.length > 0
    ) {
      results.push(
        result("quality.numeric_consistency", "REVIEW", "NUMERIC_INCONSISTENCY", {
          findings: options.numericConsistency.findings,
        }),
      );
    } else {
      results.push(result("quality.numeric_consistency", "PASS", null));
    }
  }

  if (options.quorum !== undefined && options.quorum.required) {
    if (!options.quorum.satisfied) {
      results.push(
        result(
          "governance.quorum",
          "FAIL",
          options.quorum.reasonCode ?? "QUORUM_NOT_MET",
          options.quorum.details,
        ),
      );
    } else {
      results.push(
        result("governance.quorum", "PASS", null, options.quorum.details),
      );
    }
  }

  if (options.customPolicies) {
    for (const evaluator of options.customPolicies) {
      const result = evaluator(request);
      if (Array.isArray(result)) {
        results.push(...(result as readonly PolicyResult[]));
      } else {
        results.push(result as PolicyResult);
      }
    }
  }

  return Object.freeze(results);
}
