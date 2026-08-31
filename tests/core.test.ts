import { describe, expect, it } from "vitest";

import {
  aggregateDecision,
  calculateRiskScore,
  canonicalize,
  evaluatePolicies,
  sha256,
  verificationRequestSchema,
  verifyAction,
  type PolicyResult,
  type VerificationRequest,
} from "../src/core/index";

interface FixtureOptions {
  readonly actionType?: string;
  readonly target?: string;
  readonly parameters?: Record<string, string | number | boolean | null>;
  readonly allowedActions?: readonly string[];
  readonly principalId?: string | null;
  readonly maxAmount?: number;
  readonly currency?: string;
  readonly allowedTargets?: readonly string[];
  readonly blockedTargets?: readonly string[];
  readonly allowedSensitiveActions?: readonly string[];
  readonly isReversible?: boolean;
  readonly requireReviewForIrreversible?: boolean;
}

function fixture(options: FixtureOptions = {}): VerificationRequest {
  return verificationRequestSchema.parse({
    agent: {
      id: "procurement-agent-01",
      owner: "acme-corp",
    },
    principal:
      options.principalId === null
        ? null
        : { id: options.principalId ?? "acme-corp" },
    action: {
      type: options.actionType ?? "purchase",
      target: options.target ?? "supplier.example",
      parameters: options.parameters ?? { amount: 8_200, currency: "USD" },
      ...(options.isReversible === undefined
        ? {}
        : { is_reversible: options.isReversible }),
    },
    authority: {
      allowed_actions: options.allowedActions ?? ["purchase"],
      constraints: {
        ...(options.maxAmount === undefined
          ? {}
          : { max_amount: options.maxAmount }),
        ...(options.currency === undefined ? {} : { currency: options.currency }),
        ...(options.allowedTargets === undefined
          ? {}
          : { allowed_targets: options.allowedTargets }),
        ...(options.blockedTargets === undefined
          ? {}
          : { blocked_targets: options.blockedTargets }),
        ...(options.allowedSensitiveActions === undefined
          ? {}
          : { allowed_sensitive_actions: options.allowedSensitiveActions }),
        ...(options.requireReviewForIrreversible === undefined
          ? {}
          : {
              require_review_for_irreversible:
                options.requireReviewForIrreversible,
            }),
      },
    },
    context: {
      request_id: "request-01",
      timestamp: "2026-08-09T08:00:00Z",
      source: "rest",
    },
  });
}

describe("policy engine", () => {
  it("allows a delegated action when all constraints pass", async () => {
    const response = await verifyAction(fixture({ maxAmount: 10_000, currency: "USD" }));

    expect(response.decision).toBe("ALLOW");
    expect(response.risk_score).toBe(0);
    expect(response.reason_codes).toEqual([]);
  });

  it("never allows caller-supplied authority in evaluation mode", async () => {
    const response = await verifyAction(fixture(), { trustedAuthority: false });

    expect(response.decision).toBe("REVIEW");
    expect(response.reason_codes).toContain("AUTHORITY_SOURCE_UNTRUSTED");
  });

  it("blocks an action that was not delegated", async () => {
    const response = await verifyAction(fixture({ allowedActions: ["read_catalog"] }));

    expect(response.decision).toBe("BLOCK");
    expect(response.reason_codes).toContain("ACTION_NOT_DELEGATED");
  });

  it.each([
    [9_999, "ALLOW"],
    [10_000, "ALLOW"],
    [10_001, "BLOCK"],
  ] as const)("evaluates amount %s as %s", async (amount, expected) => {
    const response = await verifyAction(
      fixture({
        maxAmount: 10_000,
        currency: "USD",
        parameters: { amount, currency: "USD" },
      }),
    );

    expect(response.decision).toBe(expected);
    if (expected === "BLOCK") {
      expect(response.reason_codes).toContain("AUTHORITY_LIMIT_EXCEEDED");
    }
  });

  it("allows a target present in the allowlist", async () => {
    const response = await verifyAction(
      fixture({ allowedTargets: ["supplier.example"] }),
    );

    expect(response.decision).toBe("ALLOW");
  });

  it("blocks a target present in the denylist even when also allowed", async () => {
    const response = await verifyAction(
      fixture({
        allowedTargets: ["supplier.example"],
        blockedTargets: ["supplier.example"],
      }),
    );

    expect(response.decision).toBe("BLOCK");
    expect(response.reason_codes).toContain("TARGET_BLOCKED");
  });

  it("reviews a delegated sensitive action without explicit sensitive authority", async () => {
    const response = await verifyAction(
      fixture({
        actionType: "send_external_message",
        allowedActions: ["send_external_message"],
        parameters: {},
      }),
    );

    expect(response.decision).toBe("REVIEW");
    expect(response.reason_codes).toContain("SENSITIVE_ACTION_REVIEW");
  });

  it("treats a Worker deployment as a sensitive action", async () => {
    const response = await verifyAction(
      fixture({
        actionType: "deploy_worker",
        allowedActions: ["deploy_worker"],
        target: "worker:vizier",
        parameters: {},
      }),
    );

    expect(response.decision).toBe("REVIEW");
    expect(response.reason_codes).toContain("SENSITIVE_ACTION_REVIEW");
  });

  it("reviews an explicitly unknown principal", async () => {
    const response = await verifyAction(fixture({ principalId: null }));

    expect(response.decision).toBe("REVIEW");
    expect(response.reason_codes).toContain("PRINCIPAL_UNVERIFIED");
  });

  it("reviews an irreversible action when delegated authority requires it", async () => {
    const response = await verifyAction(
      fixture({
        isReversible: false,
        requireReviewForIrreversible: true,
      }),
    );

    expect(response.decision).toBe("REVIEW");
    expect(response.reason_codes).toContain("IRREVERSIBLE_ACTION_REVIEW");
  });

  it("allows a declared reversible action under a reversibility requirement", async () => {
    const response = await verifyAction(
      fixture({
        isReversible: true,
        requireReviewForIrreversible: true,
      }),
    );

    expect(response.decision).toBe("ALLOW");
    expect(response.reason_codes).not.toContain("IRREVERSIBLE_ACTION_REVIEW");
  });

  it("fails schema validation for an omitted principal or unknown fields", () => {
    const valid = fixture();
    const withoutPrincipal = Object.fromEntries(
      Object.entries(valid).filter(([key]) => key !== "principal"),
    );
    const withUnknownField = { ...valid, bypass_policy: true };

    expect(verificationRequestSchema.safeParse(withoutPrincipal).success).toBe(false);
    expect(verificationRequestSchema.safeParse(withUnknownField).success).toBe(false);
  });

  it("scores the same policy results deterministically", () => {
    const request = fixture({
      actionType: "delete_data",
      allowedActions: ["read_data"],
      principalId: null,
      parameters: {},
    });
    const first = evaluatePolicies(request);
    const second = evaluatePolicies(request);

    expect(first).toEqual(second);
    expect(calculateRiskScore(first)).toBe(1);
    expect(calculateRiskScore(second)).toBe(1);
  });
});

describe("receipts and decision aggregation", () => {
  it("canonicalizes object keys before hashing", async () => {
    const first = canonicalize({ b: 2, a: { d: 4, c: 3 } });
    const second = canonicalize({ a: { c: 3, d: 4 }, b: 2 });

    expect(first).toBe('{"a":{"c":3,"d":4},"b":2}');
    expect(await sha256(first)).toBe(await sha256(second));
    expect(await sha256("abc")).toBe(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );
  });

  it("creates a stable request hash with injected receipt metadata", async () => {
    const request = fixture({ maxAmount: 10_000, currency: "USD" });
    const options = {
      createId: () => "vrf_test",
      now: () => new Date("2026-08-09T08:30:00Z"),
    };
    const first = await verifyAction(request, options);
    const second = await verifyAction(request, options);

    expect(first.receipt).toEqual(second.receipt);
    expect(first.receipt.request_hash).toMatch(/^[a-f0-9]{64}$/);
    expect(first.receipt.policy_rule_ids).toHaveLength(7);
  });

  it("applies BLOCK over REVIEW over ALLOW precedence", () => {
    const result = (
      status: PolicyResult["result"],
      index: number,
    ): PolicyResult => ({
      rule_id: `test.${index}`,
      result: status,
      reason_code: null,
      details: {},
    });

    expect(aggregateDecision([result("PASS", 1)])).toBe("ALLOW");
    expect(aggregateDecision([result("PASS", 1), result("REVIEW", 2)])).toBe(
      "REVIEW",
    );
    expect(
      aggregateDecision([
        result("PASS", 1),
        result("REVIEW", 2),
        result("FAIL", 3),
      ]),
    ).toBe("BLOCK");
  });
});
