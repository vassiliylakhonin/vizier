import { aggregateDecision } from "../core/decision";
import { evaluatePolicies, type PolicyOptions } from "../core/policies";
import { canonicalize, sha256 } from "../core/receipts";
import { calculateRiskScore } from "../core/risk";
import type { VerificationRequest } from "../core/schemas";
import type { Decision, PolicyResult } from "../core/types";
import { signCompactJws, verifyCompactJws } from "../crypto/jws";
import type {
  ActionCovenant,
  ActionCovenantActivationRequest,
  ActionCovenantAuthorizationRequest,
  ActionCovenantDraft,
  AuthorizationReceiptPayload,
  OutcomeReceiptPayload,
  OutcomeRecordingRequest,
  SignedAuthorizationReceipt,
  SignedOutcomeReceipt,
} from "./schemas";
import type { ActionCovenantAuthorizationResponse } from "./types";

const AUTHORIZATION_RECEIPT_TYPE = "VIZIER-ACTION-AUTHORIZATION+JWS";
const OUTCOME_RECEIPT_TYPE = "VIZIER-OUTCOME-RECEIPT+JWS";
const DEFAULT_AUTHORIZATION_TTL_SECONDS = 300;
const DEFAULT_CLOCK_SKEW_MS = 300_000;

export class ActionCovenantError extends Error {
  constructor(
    readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = "ActionCovenantError";
  }
}

interface IdentityOptions {
  readonly now?: () => Date;
  readonly createId?: () => string;
}

export interface ActivationOptions extends IdentityOptions {
  readonly maxClockSkewMs?: number;
}

export interface AuthorizationOptions extends IdentityOptions, PolicyOptions {
  readonly signingKey: string;
  readonly issuer: string;
  readonly authorizationTtlSeconds?: number;
}

export interface OutcomeOptions extends IdentityOptions {
  readonly signingKey: string;
  readonly issuer: string;
  readonly maxClockSkewMs?: number;
}

function policyResult(
  ruleId: string,
  result: PolicyResult["result"],
  reasonCode: string | null,
  details: Readonly<Record<string, unknown>> = {},
): PolicyResult {
  return Object.freeze({
    rule_id: ruleId,
    result,
    reason_code: reasonCode,
    details: Object.freeze({ ...details }),
  });
}

function covenantHashInput(covenant: Omit<ActionCovenant, "covenant_hash">): string {
  return canonicalize(covenant);
}

export async function hashActionCovenantDraft(
  draft: ActionCovenantDraft,
): Promise<string> {
  return sha256(canonicalize(draft));
}

async function hashActionCovenant(covenant: ActionCovenant): Promise<string> {
  return sha256(
    covenantHashInput({
      id: covenant.id,
      version: covenant.version,
      status: covenant.status,
      activated_at: covenant.activated_at,
      draft: covenant.draft,
      acceptance: covenant.acceptance,
    }),
  );
}

export async function activateActionCovenant(
  request: ActionCovenantActivationRequest,
  options: ActivationOptions = {},
): Promise<ActionCovenant> {
  const now = (options.now ?? (() => new Date()))();
  const maxClockSkewMs = options.maxClockSkewMs ?? DEFAULT_CLOCK_SKEW_MS;
  if (request.acceptance.accepted_by.id !== request.draft.principal.id) {
    throw new ActionCovenantError(
      "ACCEPTANCE_PRINCIPAL_MISMATCH",
      "Only the covenant principal can accept the draft.",
    );
  }
  const draftHash = await hashActionCovenantDraft(request.draft);
  if (request.acceptance.draft_hash !== draftHash) {
    throw new ActionCovenantError(
      "DRAFT_HASH_MISMATCH",
      "The acceptance is not bound to this draft.",
    );
  }
  const acceptedAt = Date.parse(request.acceptance.accepted_at);
  if (acceptedAt > now.getTime() + maxClockSkewMs) {
    throw new ActionCovenantError(
      "ACCEPTANCE_TIME_INVALID",
      "The acceptance timestamp is too far in the future.",
    );
  }
  if (acceptedAt < Date.parse(request.draft.drafted_at)) {
    throw new ActionCovenantError(
      "ACCEPTANCE_TIME_INVALID",
      "The acceptance cannot predate the draft.",
    );
  }
  if (Date.parse(request.draft.expires_at) <= now.getTime()) {
    throw new ActionCovenantError(
      "DRAFT_EXPIRED",
      "An expired draft cannot be activated.",
    );
  }

  const createId = options.createId ?? (() => `acv_${crypto.randomUUID()}`);
  const unsignedCovenant = {
    id: createId(),
    version: 1 as const,
    status: "ACTIVE" as const,
    activated_at: now.toISOString(),
    draft: request.draft,
    acceptance: request.acceptance,
  };
  return Object.freeze({
    ...unsignedCovenant,
    covenant_hash: await sha256(covenantHashInput(unsignedCovenant)),
  });
}

function evaluateCovenantIntegrity(
  isValid: boolean,
): PolicyResult {
  return isValid
    ? policyResult("covenant.integrity.valid", "PASS", null)
    : policyResult(
        "covenant.integrity.valid",
        "FAIL",
        "COVENANT_INTEGRITY_INVALID",
      );
}

function evaluateCovenantExpiry(
  covenant: ActionCovenant,
  now: Date,
): PolicyResult {
  return Date.parse(covenant.draft.expires_at) > now.getTime()
    ? policyResult("covenant.time.active", "PASS", null)
    : policyResult("covenant.time.active", "FAIL", "COVENANT_EXPIRED", {
        expires_at: covenant.draft.expires_at,
      });
}

async function evaluateExactAction(
  request: ActionCovenantAuthorizationRequest,
): Promise<PolicyResult> {
  const [expected, actual] = await Promise.all([
    sha256(canonicalize(request.covenant.draft.action)),
    sha256(canonicalize(request.action)),
  ]);
  return expected === actual
    ? policyResult("covenant.action.exact", "PASS", null)
    : policyResult(
        "covenant.action.exact",
        "FAIL",
        "ACTION_COVENANT_MISMATCH",
        { expected_action_hash: expected, actual_action_hash: actual },
      );
}

function evaluateEvidence(
  request: ActionCovenantAuthorizationRequest,
  now: Date,
): readonly PolicyResult[] {
  if (request.covenant.draft.evidence_requirements.length === 0) {
    return [policyResult("covenant.evidence.current", "PASS", null)];
  }
  return request.covenant.draft.evidence_requirements.map((requirement) => {
    const observation = request.evidence.find(
      (candidate) => candidate.requirement_id === requirement.id,
    );
    const ruleId = `covenant.evidence.${requirement.id}.current`;
    if (observation === undefined) {
      return policyResult(ruleId, "REVIEW", "EVIDENCE_MISSING", {
        requirement_id: requirement.id,
      });
    }
    if (observation.evidence_type !== requirement.evidence_type) {
      return policyResult(ruleId, "REVIEW", "EVIDENCE_TYPE_MISMATCH", {
        requirement_id: requirement.id,
        expected_type: requirement.evidence_type,
        observed_type: observation.evidence_type,
      });
    }
    const observedAt = Date.parse(observation.observed_at);
    if (observedAt > now.getTime()) {
      return policyResult(ruleId, "REVIEW", "EVIDENCE_FROM_FUTURE", {
        requirement_id: requirement.id,
      });
    }
    const ageSeconds = (now.getTime() - observedAt) / 1_000;
    if (ageSeconds > requirement.max_age_seconds) {
      return policyResult(ruleId, "REVIEW", "EVIDENCE_STALE", {
        requirement_id: requirement.id,
        age_seconds: ageSeconds,
        max_age_seconds: requirement.max_age_seconds,
      });
    }
    return policyResult(ruleId, "PASS", null, {
      requirement_id: requirement.id,
      evidence_hash: observation.content_hash,
    });
  });
}

function signalMatches(
  signal: ActionCovenantAuthorizationRequest["signals"][number],
  rule: ActionCovenant["draft"]["invalidation_rules"][number],
): boolean {
  return (
    signal.signal_type === rule.signal_type &&
    Object.entries(rule.match).every(
      ([key, expected]) => signal.attributes[key] === expected,
    )
  );
}

function evaluateInvalidation(
  request: ActionCovenantAuthorizationRequest,
): readonly PolicyResult[] {
  if (request.covenant.draft.invalidation_rules.length === 0) {
    return [policyResult("covenant.invalidation.clear", "PASS", null)];
  }
  return request.covenant.draft.invalidation_rules.map((rule) => {
    const invalidatingSignal = request.signals.find((signal) =>
      signalMatches(signal, rule),
    );
    const ruleId = `covenant.invalidation.${rule.id}.clear`;
    return invalidatingSignal === undefined
      ? policyResult(ruleId, "PASS", null)
      : policyResult(ruleId, "FAIL", "COVENANT_INVALIDATED", {
          invalidation_rule_id: rule.id,
          signal_type: invalidatingSignal.signal_type,
          signal_source: invalidatingSignal.source,
        });
  });
}

const EXPLANATIONS: Readonly<Record<Decision, string>> = Object.freeze({
  ALLOW: "The exact action satisfies the active covenant, supplied authority, evidence, and invalidation checks.",
  REVIEW: "The action requires review because covenant evidence or authority could not be resolved automatically.",
  BLOCK: "The action violates or no longer satisfies the accepted covenant.",
});

export async function authorizeActionCovenant(
  request: ActionCovenantAuthorizationRequest,
  options: AuthorizationOptions,
): Promise<ActionCovenantAuthorizationResponse> {
  const now = (options.now ?? (() => new Date()))();
  const covenantHash = await hashActionCovenant(request.covenant);
  const verificationRequest: VerificationRequest = {
    agent: request.covenant.draft.agent,
    principal: request.covenant.draft.principal,
    action: request.action,
    authority: request.covenant.draft.authority,
    context: request.context,
  };
  const policyResults = Object.freeze([
    evaluateCovenantIntegrity(
      covenantHash === request.covenant.covenant_hash,
    ),
    policyResult("covenant.status.active", "PASS", null),
    evaluateCovenantExpiry(request.covenant, now),
    await evaluateExactAction(request),
    ...evaluateEvidence(request, now),
    ...evaluateInvalidation(request),
    ...evaluatePolicies(verificationRequest, {
      sensitiveActions: options.sensitiveActions,
      trustedAuthority: options.trustedAuthority ?? false,
    }),
  ]);
  const decision = aggregateDecision(policyResults);
  const riskScore = calculateRiskScore(policyResults);
  const reasonCodes = Object.freeze(
    policyResults.flatMap((result) =>
      result.reason_code === null ? [] : [result.reason_code],
    ),
  );
  const createId = options.createId ?? (() => `azr_${crypto.randomUUID()}`);
  const authorizationTtlSeconds =
    options.authorizationTtlSeconds ?? DEFAULT_AUTHORIZATION_TTL_SECONDS;
  const expiresAt = new Date(
    Math.min(
      Date.parse(request.covenant.draft.expires_at),
      now.getTime() + authorizationTtlSeconds * 1_000,
    ),
  );
  const payload: AuthorizationReceiptPayload = {
    type: "ACTION_AUTHORIZATION",
    version: 1,
    id: createId(),
    issuer: options.issuer,
    issued_at: now.toISOString(),
    expires_at: expiresAt.toISOString(),
    covenant_id: request.covenant.id,
    covenant_hash: request.covenant.covenant_hash,
    request_hash: await sha256(canonicalize(request)),
    action_hash: await sha256(canonicalize(request.action)),
    evidence_hash: await sha256(canonicalize(request.evidence)),
    signals_hash: await sha256(canonicalize(request.signals)),
    decision,
    risk_score: riskScore,
    policy_rule_ids: policyResults.map((result) => result.rule_id),
    reason_codes: [...reasonCodes],
  };
  const token = await signCompactJws(
    payload,
    options.signingKey,
    AUTHORIZATION_RECEIPT_TYPE,
  );
  return Object.freeze({
    decision,
    risk_score: riskScore,
    reason_codes: reasonCodes,
    explanation: EXPLANATIONS[decision],
    policy_results: policyResults,
    authorization_receipt: Object.freeze({ payload, token }),
  });
}

async function verifyAuthorizationReceiptSignature(
  receipt: SignedAuthorizationReceipt,
  signingKey: string,
): Promise<boolean> {
  return verifyCompactJws(
    receipt.token,
    receipt.payload,
    signingKey,
    AUTHORIZATION_RECEIPT_TYPE,
  );
}

function forbiddenOutcomeViolations(
  request: OutcomeRecordingRequest,
): readonly string[] {
  return request.covenant.draft.forbidden_outcomes.flatMap((rule) => {
    const matched = request.outcome.effects.some(
      (effect) =>
        effect.type === rule.effect_type &&
        (rule.target === undefined || effect.target === rule.target),
    );
    return matched ? [`FORBIDDEN_OUTCOME:${rule.id}`] : [];
  });
}

export async function recordActionOutcome(
  request: OutcomeRecordingRequest,
  options: OutcomeOptions,
): Promise<SignedOutcomeReceipt> {
  const now = (options.now ?? (() => new Date()))();
  const receipt = request.authorization_receipt;
  if (!(await verifyAuthorizationReceiptSignature(receipt, options.signingKey))) {
    throw new ActionCovenantError(
      "AUTHORIZATION_RECEIPT_INVALID",
      "The authorization receipt signature or payload is invalid.",
    );
  }
  if (receipt.payload.issuer !== options.issuer) {
    throw new ActionCovenantError(
      "AUTHORIZATION_ISSUER_MISMATCH",
      "The authorization receipt was issued by another Vizier instance.",
    );
  }
  if (receipt.payload.decision !== "ALLOW") {
    throw new ActionCovenantError(
      "ACTION_NOT_AUTHORIZED",
      "An outcome can only be recorded for an ALLOW authorization.",
    );
  }
  const covenantHash = await hashActionCovenant(request.covenant);
  if (
    covenantHash !== request.covenant.covenant_hash ||
    receipt.payload.covenant_hash !== request.covenant.covenant_hash ||
    receipt.payload.covenant_id !== request.covenant.id
  ) {
    throw new ActionCovenantError(
      "COVENANT_RECEIPT_MISMATCH",
      "The outcome covenant does not match the authorization receipt.",
    );
  }
  const startedAt = Date.parse(request.outcome.started_at);
  const maxClockSkewMs = options.maxClockSkewMs ?? DEFAULT_CLOCK_SKEW_MS;
  if (startedAt < Date.parse(receipt.payload.issued_at) - maxClockSkewMs) {
    throw new ActionCovenantError(
      "OUTCOME_TIME_INVALID",
      "The action started before authorization was issued.",
    );
  }
  if (startedAt > Date.parse(receipt.payload.expires_at)) {
    throw new ActionCovenantError(
      "AUTHORIZATION_EXPIRED_BEFORE_EXECUTION",
      "The action started after authorization expired.",
    );
  }
  if (Date.parse(request.outcome.finished_at) > now.getTime() + maxClockSkewMs) {
    throw new ActionCovenantError(
      "OUTCOME_TIME_INVALID",
      "The outcome timestamp is too far in the future.",
    );
  }

  const violationCodes = forbiddenOutcomeViolations(request);
  const createId = options.createId ?? (() => `out_${crypto.randomUUID()}`);
  const payload: OutcomeReceiptPayload = {
    type: "OUTCOME_RECEIPT",
    version: 1,
    id: createId(),
    issuer: options.issuer,
    issued_at: now.toISOString(),
    authorization_receipt_id: receipt.payload.id,
    authorization_token_hash: await sha256(receipt.token),
    covenant_id: request.covenant.id,
    covenant_hash: request.covenant.covenant_hash,
    outcome_hash: await sha256(canonicalize(request.outcome)),
    compliance: violationCodes.length === 0 ? "COMPLIANT" : "VIOLATION",
    violation_codes: [...violationCodes],
  };
  return Object.freeze({
    payload,
    token: await signCompactJws(
      payload,
      options.signingKey,
      OUTCOME_RECEIPT_TYPE,
    ),
  });
}
