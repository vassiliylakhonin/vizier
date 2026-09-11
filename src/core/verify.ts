import { aggregateDecision } from "./decision";
import {
  verifyDelegationGrant,
  type GrantVerification,
  type PrincipalKeyRegistry,
} from "./grants";
import { evaluatePolicies, type PolicyOptions } from "./policies";
import { evaluateQuorum } from "./quorum";
import { createReceipt, type ReceiptOptions } from "./receipts";
import { calculateRiskScore } from "./risk";
import type { VerificationRequest } from "./schemas";
import type { AuthorityProvenance, Decision, VerificationResponse } from "./types";

const EMPTY_REGISTRY: PrincipalKeyRegistry = new Map();

export interface VerificationOptions extends PolicyOptions, ReceiptOptions {
  /**
   * Public keys, by principal id, that delegation grants may be signed with.
   * Registered out of band by an operator; never fetched at decision time.
   * A request carrying a grant while this is empty is refused, not downgraded.
   */
  readonly principalKeys?: PrincipalKeyRegistry;
  /** Expected `aud` when a grant names one. */
  readonly audience?: string;
}

const EXPLANATIONS: Readonly<Record<Decision, string>> = Object.freeze({
  ALLOW: "The proposed action is within the supplied delegated authority and constraints.",
  REVIEW: "The proposed action requires human review because authority or risk could not be resolved automatically.",
  BLOCK: "The proposed action violates the supplied delegated authority or constraints.",
});

const SIGNED_EXPLANATIONS: Readonly<Record<Decision, string>> = Object.freeze({
  ALLOW: "The proposed action is within authority the principal signed for this agent.",
  REVIEW: "The principal's delegation verified, but the proposed action still requires human review.",
  BLOCK: "The proposed action violates authority the principal signed for this agent.",
});

function explain(decision: Decision, provenance: AuthorityProvenance): string {
  return provenance === "principal_signed"
    ? SIGNED_EXPLANATIONS[decision]
    : EXPLANATIONS[decision];
}

function resolveProvenance(
  grantVerification: GrantVerification | undefined,
  trustedAuthority: boolean,
): AuthorityProvenance {
  if (grantVerification?.ok === true) {
    return "principal_signed";
  }
  return trustedAuthority ? "trusted_integration" : "unverified";
}

export async function verifyAction(
  request: VerificationRequest,
  options: VerificationOptions = {},
): Promise<VerificationResponse> {
  const grantVerification =
    request.grant === undefined
      ? undefined
      : await verifyDelegationGrant({
          token: request.grant,
          registry: options.principalKeys ?? EMPTY_REGISTRY,
          principalId: request.principal?.id ?? null,
          agentId: request.agent.id,
          authority: request.authority,
          ...(options.audience === undefined ? {} : { audience: options.audience }),
          ...(options.now === undefined ? {} : { now: options.now() }),
        });

  const quorum =
    options.quorum !== undefined
      ? options.quorum
      : request.authority.constraints.quorum !== undefined
        ? await evaluateQuorum(request, undefined, options.now)
        : undefined;

  const policyResults = evaluatePolicies(request, {
    ...options,
    ...(grantVerification === undefined ? {} : { grantVerification }),
    ...(quorum === undefined ? {} : { quorum }),
  });
  const decision = aggregateDecision(policyResults);
  const riskScore = calculateRiskScore(policyResults);
  const reasonCodes = Object.freeze(
    policyResults.flatMap((item) =>
      item.reason_code === null ? [] : [item.reason_code],
    ),
  );
  const authorityProvenance = resolveProvenance(
    grantVerification,
    options.trustedAuthority ?? true,
  );
  const receipt = await createReceipt(
    request,
    decision,
    riskScore,
    policyResults,
    {
      authorityProvenance,
      ...(grantVerification?.ok === true
        ? {
            grant: {
              jti: grantVerification.grant.jti,
              issuer: grantVerification.grant.issuer,
              subject: grantVerification.grant.subject,
              key_id: grantVerification.grant.key_id,
              expires_at: grantVerification.grant.expires_at,
            },
          }
        : {}),
    },
    options,
  );

  return Object.freeze({
    decision,
    risk_score: riskScore,
    reason_codes: reasonCodes,
    explanation: explain(decision, authorityProvenance),
    policy_results: policyResults,
    receipt,
  });
}
