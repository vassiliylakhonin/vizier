import type { PolicyResult } from "./types";
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

function evaluatePrincipal(request: VerificationRequest): PolicyResult {
  return request.principal === null
    ? result("principal.verified", "REVIEW", "PRINCIPAL_UNVERIFIED")
    : result("principal.verified", "PASS", null);
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
  const results: PolicyResult[] = [
    evaluateAuthorityProvenance(options.trustedAuthority ?? true),
    evaluatePrincipal(request),
    evaluateDelegatedAction(request),
    evaluateAmount(request),
    evaluateTarget(request),
    evaluateSensitiveAction(request, sensitiveActions),
    evaluateReversibility(request),
  ];

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
