import type { EdgeCircuitBreakerResult } from "./circuit-breaker";
import type { DlpEvaluationResult } from "./dlp";
import type { GrantVerification } from "./grants";
import type { PolicyResult } from "./types";
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
    : result("principal.verified", "PASS", null);
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
    evaluatePrincipal(request, grantVerification),
    evaluateDelegatedAction(request),
    evaluateAmount(request),
    evaluateTarget(request),
    evaluateSensitiveAction(request, sensitiveActions),
    evaluateReversibility(request),
  ];

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
      results.push(
        result(
          "compliance.sanctions",
          "FAIL",
          "SANCTIONED_ENTITY_MATCH",
          {
            matched_value: options.sanctions.match.matched_value,
            entity_name: options.sanctions.match.entity_name,
            list: options.sanctions.match.list,
            candidate_type: options.sanctions.match.candidate_type,
            source: options.sanctions.match.source,
            ...(options.sanctions.match.details ?? {}),
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
