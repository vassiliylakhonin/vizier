// Deterministic explanations for Vizier deny/review reason codes.
// A static lookup over codes the system already emits. No model, no network,
// no re-evaluation: it cannot say whether a changed grant WILL be allowed, only
// which setting the code points at.

export type FixOwner = "owner" | "operator" | "agent";

interface CatalogEntry {
  readonly meaning: string;
  readonly fix: readonly string[];
  readonly owner: FixOwner;
}

const E = (owner: FixOwner, meaning: string, ...fix: string[]): CatalogEntry => ({ owner, meaning, fix });

const CATALOG: Readonly<Record<string, CatalogEntry>> = Object.freeze({
  GRANT_REQUIRED: E("owner", "This deployment requires a valid principal-signed grant and none verified.",
    "Have the principal sign a delegation grant for this agent and attach it to the request.",
    "Caller-declared limits and API keys do not replace the grant."),
  GRANT_POLICY_MISCONFIGURED: E("operator", "The signed-grant policy setting is invalid, so the request is refused.",
    "Fix the operator's signed-grant mode setting to a supported value (see docs/DELEGATION_GRANTS.md)."),
  GRANT_MALFORMED: E("owner", "The grant could not be parsed as a Vizier delegation grant (compact JWS, ES256, typ vizier-delegation+jws, kid, valid claims).",
    "Re-issue the grant with the grant tooling. Check the `reason` field in the details if present."),
  GRANT_PRINCIPAL_UNKNOWN: E("operator", "The grant issuer is not a registered principal.",
    "Register the principal's public key with the operator, or use a grant from a registered principal."),
  GRANT_KEY_UNKNOWN: E("operator", "The key id (kid) in the grant is not registered for this principal.",
    "Register that public key for the principal, or re-sign with a registered key."),
  GRANT_SIGNATURE_INVALID: E("owner", "The grant signature does not verify against the registered key.",
    "Re-issue the grant with the correct private key. A grant edited after signing will always fail."),
  GRANT_NOT_YET_VALID: E("owner", "The grant's not-before time is in the future.",
    "Wait until it is valid, or re-issue with an earlier start. Check clock skew if the time looks right."),
  GRANT_EXPIRED: E("owner", "The grant has expired.", "Issue a new grant with a new expiry."),
  GRANT_EXPIRED_BEFORE_EXECUTION: E("owner", "The grant expired between the decision and execution.",
    "Issue a grant with enough lifetime to cover execution, then decide again."),
  GRANT_REVOKED: E("owner", "The grant's id (jti) was revoked.",
    "Issue a new grant with a new jti if the authority should still exist. Revocation is deliberate; confirm before replacing."),
  GRANT_ALREADY_USED: E("owner", "A single-use grant was already consumed.",
    "Issue a new single-use grant for the new action."),
  GRANT_SINGLE_USE_STATE_UNAVAILABLE: E("operator", "Single-use state could not be checked, so the request fails closed.",
    "Bind the durable store the deployment uses for single-use tracking, or use a multi-use grant."),
  GRANT_STORE_UNAVAILABLE: E("operator", "The grant store could not be reached.", "Restore the store binding, then retry."),
  GRANT_LIFETIME_EXCESSIVE: E("owner", "The grant lifetime (exp - iat) is longer than the maximum allowed (365 days).",
    "Re-issue with a shorter lifetime."),
  GRANT_ISSUER_MISMATCH: E("owner", "The grant issuer differs from the principal on the request.",
    "Send the request with the principal that signed the grant, or use a grant signed by the stated principal."),
  GRANT_SUBJECT_MISMATCH: E("owner", "The grant was issued to a different agent than the one making the request.",
    "Issue a grant whose subject is this agent id, or call with the agent id the grant names."),
  GRANT_AUDIENCE_MISMATCH: E("owner", "The grant names an audience that differs from this deployment's.",
    "Issue the grant with this deployment's audience."),
  GRANT_AUTHORITY_MISMATCH: E("owner", "The authority on the request differs from the authority the grant signed.",
    "Send the request with the authority exactly as signed, or sign a new grant with the changed authority. The agent must not widen it itself."),
  ACTION_NOT_DELEGATED: E("owner", "The action type is not in the authority's allowed_actions.",
    "If the owner wants this action allowed, add its type to allowed_actions in a new grant. Otherwise the block is correct."),
  TARGET_BLOCKED: E("owner", "The target is in blocked_targets.",
    "Remove it from blocked_targets only if the owner intends to allow it; otherwise choose another target."),
  TARGET_NOT_ALLOWED: E("owner", "allowed_targets is set and does not include this target.",
    "Add the target to allowed_targets in a new grant if intended, or use a listed target."),
  AUTHORITY_LIMIT_EXCEEDED: E("owner", "The action amount is above max_amount.",
    "Lower the amount, or have the owner sign a higher max_amount."),
  AMOUNT_UNVERIFIED: E("agent", "max_amount is set but the action has no usable numeric `amount` parameter.",
    "Send a finite, non-negative number in action.parameters.amount."),
  CURRENCY_UNVERIFIED: E("agent", "The action currency is missing or differs from the authority's currency.",
    "Send action.parameters.currency matching the authority currency."),
  SENSITIVE_ACTION_REVIEW: E("owner", "This action type is treated as sensitive and was not explicitly allowed.",
    "Add the type to allowed_sensitive_actions in a new grant if intended, or send it to human review."),
  IRREVERSIBLE_ACTION_REVIEW: E("agent", "The action is irreversible or has no reversibility information, so it needs human review.",
    "Provide reversibility information if the action is reversible; otherwise route it to a human."),
  PRINCIPAL_UNVERIFIED: E("owner", "The principal is only asserted by the caller, not verified by a signed grant.",
    "Attach a principal-signed grant."),
  AUTHORITY_SOURCE_UNTRUSTED: E("operator", "The authority came from an unauthenticated caller (evaluation mode).",
    "Call through the authenticated integration path if this should be enforced."),
  BUDGET_REQUIRES_GRANT: E("owner", "A budget was set without a verified grant, so spend cannot be tracked reliably.",
    "Put the budget inside a principal-signed grant."),
  BUDGET_UNPRICED: E("agent", "The cost of the action could not be determined, and unknown cost is not treated as zero.",
    "Send a numeric amount and a currency that matches the budget currency. Check `reason` in the details."),
  BUDGET_STATE_UNAVAILABLE: E("operator", "The budget ledger could not be read.", "Restore the ledger store binding, then retry."),
  BUDGET_CURRENCY_CONFLICT: E("owner", "The budget currency differs from the currency already recorded for this budget id.",
    "Use the original currency, or start a new budget id."),
  BUDGET_REQUEST_ID_CONFLICT: E("agent", "The same request_id was used earlier with a different request body.",
    "Use a new request_id for a different action; resend the identical body only to repeat a decision."),
  BUDGET_CEILING_EXCEEDED: E("owner", "Spent plus this amount is above the budget ceiling. Only admitted amounts are counted, not settled ones.",
    "Reduce the amount, or have the owner sign a higher ceiling or a new budget id."),
  USAGE_REQUIRES_GRANT: E("owner", "Per-window usage bounds were set without a verified grant, so use cannot be counted reliably.",
    "Put the usage bounds inside a principal-signed grant."),
  USAGE_UNPRICED: E("agent", "The cost of the action could not be determined, and unknown cost is not treated as zero.",
    "Send a numeric amount and a currency that matches the usage currency. Check `reason` in the details."),
  USAGE_STATE_UNAVAILABLE: E("operator", "The usage ledger could not be read.", "Restore the ledger store binding, then retry."),
  USAGE_CALL_LIMIT_EXCEEDED: E("owner", "This principal already used the allowed number of calls in the current window.",
    "Wait for the window to roll over, or have the owner sign a higher max_calls or a new usage id."),
  USAGE_AMOUNT_LIMIT_EXCEEDED: E("owner", "Spent plus this amount is above the per-window usage limit. Only admitted amounts are counted, not settled ones.",
    "Wait for the window to roll over, reduce the amount, or have the owner sign a higher limit or a new usage id."),
  USAGE_CURRENCY_CONFLICT: E("owner", "The usage currency differs from the currency already recorded for this usage id in this window.",
    "Use the original currency, or start a new usage id."),
  "CIRCUIT_TRIPPED:LOOP_DETECTED": E("agent", "The same call repeated enough to trip the loop breaker.",
    "Stop repeating it. Look at the last result, change the plan, or ask the owner."),
  "CIRCUIT_TRIPPED:BUDGET_EXCEEDED": E("operator", "The call-count budget for this agent was used up.",
    "Wait for the window to reset, or ask the operator to raise the call budget."),
  CIRCUIT_TRIPPED: E("agent", "A circuit breaker tripped for this agent.", "Inspect the details, then change the plan or ask the owner."),
  QUOTA_EXCEEDED: E("operator", "A usage quota was exceeded.", "Wait for the quota window, or ask the operator to raise it."),
  SECRET_LEAK_PREVENTED: E("agent", "A secret-like value was found in the action parameters.",
    "Remove the secret from the parameters; pass credentials through the executor, not the agent."),
  NUMERIC_INCONSISTENCY: E("agent", "The same metric differs between parts of the supplied text. This is a heuristic check, not a fact-check.",
    "Reconcile the figures in the source, or have a human confirm which is right."),
  QUORUM_REQUIRED: E("owner", "The authority requires approvals from several approvers.", "Collect the required approvals."),
  QUORUM_NOT_MET: E("owner", "Not enough valid approvals yet.", "Collect the remaining approvals."),
  QUORUM_REJECTED: E("owner", "An approver rejected the proposal.", "Do not proceed unless the owner starts a new proposal."),
  QUORUM_ACTION_MISMATCH: E("agent", "The approvals were for a different action than the one proposed.",
    "Propose the action that was approved, or get approvals for this one."),
  QUORUM_APPROVAL_FAILED: E("owner", "An approval could not be recorded or verified.", "Have the approver submit it again."),
  UNAUTHORIZED_APPROVER: E("owner", "The approver is not in the list of allowed approvers.", "Use an allowed approver, or add the approver in a new grant."),
  SELF_APPROVAL_DISALLOWED: E("owner", "The requester cannot approve its own proposal.", "Have a different approver approve."),
  PROPOSAL_NOT_FOUND: E("agent", "No proposal with that id exists.", "Check the proposal id, or create a new proposal."),
  PROPOSAL_EXPIRED: E("agent", "The proposal expired.", "Create a new proposal."),
  PROPOSAL_ALREADY_CONSUMED: E("agent", "The proposal was already used.", "Create a new proposal."),
  CUSTOM_CONSTRAINT_BLOCKED: E("owner", "A custom constraint in the authority blocked the action.", "Read the constraint in the grant. Change it only if the owner intends to."),
  CUSTOM_DENYLIST: E("operator", "The action matched an operator denylist entry.", "Ask the operator whether the entry is intended."),
  SANCTIONED_ENTITY_MATCH: E("owner", "A name or address matched a sanctions list entry. A match is not proof; false positives happen.",
    "Send it to a human compliance review. Do not retry with altered names."),
  SANCTIONS_ADDRESS_MATCH: E("owner", "An address matched a sanctions list entry.", "Send it to a human compliance review."),
  SANCTIONS_50_RULE_VIOLATION: E("owner", "An ownership check pointed to a possible 50 percent rule match.", "Send it to a human compliance review."),
  OFAC_50_PERCENT_DEEMED: E("owner", "An ownership check pointed to a possible 50 percent rule match.", "Send it to a human compliance review."),
  SANCTIONS_LOOKUP_ERROR: E("operator", "The sanctions lookup failed, so the request fails closed.", "Restore the lookup, then retry."),
  SANCTIONS_DATA_UNAVAILABLE: E("operator", "Sanctions data was unavailable.", "Restore the data source, then retry."),
  STREAMING_UNINSPECTED_OUTPUT: E("operator", "Streaming output could not be inspected.", "Use a non-streaming call or enable inspection."),
  RECEIPT_SIGNATURE_REQUIRED: E("operator", "The caller requires a signed receipt and none was returned.", "Enable receipt signing on the deployment."),
  RECEIPT_SIGNATURE_INVALID: E("operator", "The receipt signature did not verify.", "Check the JWKS and the key in use. Do not execute."),
  SIGNED_GRANT_RECEIPT_REQUIRED: E("operator", "The proxy requires a decision backed by a signed grant.", "Supply a grant file in required grant mode."),
  TOOL_NOT_ALLOWED: E("operator", "The tool is not in the proxy's allowed tool list.", "Add the tool to the operator's allowed tools only if intended."),
  ARGUMENT_REQUIRED: E("agent", "A guarded argument is missing or not a string.", "Send the configured argument as a string."),
  ARGUMENT_INVALID: E("agent", "A guarded argument is ambiguous or malformed.", "Use one plain encoding, no control characters, no credentials in URLs."),
  URL_ORIGIN_NOT_ALLOWED: E("operator", "The URL origin is not in the operator's allowed origins.", "Use an approved origin, or ask the operator to add it."),
  PATH_OUTSIDE_ROOT: E("operator", "The path resolves outside the allowed root.", "Use a path inside the root, or ask the operator to change the root."),
  PATH_STATE_UNAVAILABLE: E("operator", "The filesystem state needed to check the path was unavailable.", "Use an existing workspace parent; the operator fixes unavailable state."),
  TAINT_PRIVATE_TO_EXTERNAL: E("owner", "This session read a labelled private source, so external sinks are blocked.", "Start a new session, or ask the owner."),
  VIZIER_DENIED: E("agent", "Vizier denied the call.", "Run `vizier explain` on the Vizier response to see the specific reason codes."),
  VIZIER_UNAVAILABLE: E("operator", "Vizier could not be reached, so the call was refused.", "Restore connectivity, then retry."),
  UPSTREAM_FAILED: E("operator", "The upstream server failed.", "Check the upstream server."),
  INVALID_CONFIGURATION: E("operator", "The proxy configuration is invalid.", "Fix the configuration file or flags."),
});

export interface ExplainFinding {
  readonly code: string;
  readonly rule_id: string | null;
  readonly status: string | null;
  readonly meaning: string;
  readonly who_can_fix: FixOwner;
  readonly what_to_change: readonly string[];
  readonly details: Readonly<Record<string, string | number | boolean | null>>;
}

export interface ExplainReport {
  readonly evaluation_only: true;
  readonly decision: string | null;
  readonly findings: readonly ExplainFinding[];
  readonly unknown_codes: readonly string[];
  readonly note: string;
}

const NOTE =
  "Static lookup from reason codes. It does not re-run the decision and cannot promise that a change will lead to ALLOW. " +
  "Only the owner or operator should change grants or policy; an agent must not widen its own authority.";

function lookup(code: string): CatalogEntry | undefined {
  return CATALOG[code] ?? CATALOG[code.split(":")[0] ?? ""];
}

function scalars(value: unknown): Record<string, string | number | boolean | null> {
  const out: Record<string, string | number | boolean | null> = {};
  if (typeof value !== "object" || value === null || Array.isArray(value)) return out;
  for (const [key, item] of Object.entries(value)) {
    if (item === null || typeof item === "number" || typeof item === "boolean") out[key] = item;
    else if (typeof item === "string") out[key] = item.length > 120 ? `${item.slice(0, 117)}...` : item;
  }
  return out;
}

/** Accepts a Vizier verify response, a receipt, a bare array of codes, or a single code. */
export function explainDecision(input: unknown): ExplainReport {
  const codes: { code: string; rule_id: string | null; status: string | null; details: unknown }[] = [];
  let decision: string | null = null;
  const seen = new Set<string>();
  const add = (code: unknown, rule: unknown, status: unknown, details: unknown): void => {
    if (typeof code !== "string" || code === "") return;
    const key = `${rule ?? ""}|${code}`;
    if (seen.has(key)) return;
    seen.add(key);
    codes.push({ code, rule_id: typeof rule === "string" ? rule : null, status: typeof status === "string" ? status : null, details });
  };
  if (typeof input === "string") add(input, null, null, undefined);
  else if (Array.isArray(input)) for (const code of input) add(code, null, null, undefined);
  else if (typeof input === "object" && input !== null) {
    const body = input as Record<string, unknown>;
    // Accept a wrapped response such as { response: {...} } or { result: {...} }.
    const root = ["response", "result"].map(k => body[k]).find(v => typeof v === "object" && v !== null) as Record<string, unknown> | undefined ?? body;
    if (typeof root.decision === "string") decision = root.decision;
    if (Array.isArray(root.policy_results)) {
      for (const item of root.policy_results) {
        if (typeof item === "object" && item !== null) {
          const r = item as Record<string, unknown>;
          if (r.result !== "PASS") add(r.reason_code, r.rule_id, r.result, r.details);
        }
      }
    }
    if (Array.isArray(root.reason_codes)) for (const code of root.reason_codes) add(code, null, null, undefined);
  }
  // A code seen with a rule id supersedes the same code without one.
  const withRule = new Set(codes.filter(c => c.rule_id !== null).map(c => c.code));
  const unique = codes.filter(c => c.rule_id !== null || !withRule.has(c.code));
  const findings: ExplainFinding[] = [];
  const unknown: string[] = [];
  for (const item of unique) {
    const entry = lookup(item.code);
    if (entry === undefined) { unknown.push(item.code); continue; }
    findings.push({ code: item.code, rule_id: item.rule_id, status: item.status, meaning: entry.meaning,
      who_can_fix: entry.owner, what_to_change: entry.fix, details: scalars(item.details) });
  }
  return { evaluation_only: true, decision, findings, unknown_codes: unknown, note: NOTE };
}

export function formatExplanation(report: ExplainReport): string {
  const lines: string[] = [];
  lines.push(report.decision === null ? "Decision: not given" : `Decision: ${report.decision}`);
  if (report.findings.length === 0 && report.unknown_codes.length === 0) lines.push("No failing or review reason codes found in the input.");
  for (const f of report.findings) {
    lines.push("", `${f.code}${f.rule_id === null ? "" : `  (rule ${f.rule_id}${f.status === null ? "" : `, ${f.status}`})`}`,
      `  Why: ${f.meaning}`, `  Who can fix it: ${f.who_can_fix}`);
    for (const step of f.what_to_change) lines.push(`  - ${step}`);
    const detailText = Object.entries(f.details).map(([k, v]) => `${k}=${String(v)}`).join(", ");
    if (detailText !== "") lines.push(`  Details: ${detailText}`);
  }
  if (report.unknown_codes.length > 0) lines.push("", `Not in the explain catalog: ${report.unknown_codes.join(", ")}. Check docs or the raw policy_results.`);
  lines.push("", report.note);
  return lines.join("\n");
}

export function listExplainableCodes(): readonly string[] {
  return Object.freeze(Object.keys(CATALOG).sort());
}
