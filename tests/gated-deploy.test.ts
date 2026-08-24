import { describe, expect, it, vi } from "vitest";

import {
  assertCleanWorktree,
  runCovenantGatedDeploy,
  runGatedDeploy,
} from "../packages/gated-deploy/src/index";

describe("vizier-gated-deploy", () => {
  it("refuses to bind a deployment receipt to a dirty worktree", () => {
    expect(() =>
      assertCleanWorktree({ commit: "abc123", dirty: true }),
    ).toThrowError("Commit or stash local changes before deployment.");
  });

  it("does not deploy when Vizier requires review", async () => {
    const execute = vi.fn(async () => 0);

    const result = await runGatedDeploy({
      metadata: { commit: "abc123", dirty: false },
      verify: async () => ({
        decision: "REVIEW",
        reason_codes: ["SENSITIVE_ACTION_REVIEW"],
        receipt: { id: "vrf_review" },
      }),
      execute,
    });

    expect(result).toEqual({
      status: "stopped",
      decision: "REVIEW",
      reasonCodes: ["SENSITIVE_ACTION_REVIEW"],
      receiptId: "vrf_review",
    });
    expect(execute).not.toHaveBeenCalled();
  });

  it("deploys only after an ALLOW receipt", async () => {
    const execute = vi.fn(async () => 0);

    const result = await runGatedDeploy({
      metadata: { commit: "abc123", dirty: false },
      verify: async (request) => {
        expect(request.action).toMatchObject({
          type: "deploy_worker",
          target: "worker:vizier",
        });
        expect(request.authority).toEqual({
          allowed_actions: ["deploy_worker"],
          constraints: {
            allowed_targets: ["worker:vizier"],
            allowed_sensitive_actions: ["deploy_worker"],
          },
        });
        return {
          decision: "ALLOW",
          reason_codes: [],
          receipt: { id: "vrf_allow" },
        };
      },
      execute,
    });

    expect(result).toEqual({
      status: "deployed",
      decision: "ALLOW",
      reasonCodes: [],
      receiptId: "vrf_allow",
      exitCode: 0,
    });
    expect(execute).toHaveBeenCalledExactlyOnceWith("vrf_allow");
  });

  it("reports a failed deployment after an ALLOW receipt", async () => {
    const result = await runGatedDeploy({
      metadata: { commit: "abc123", dirty: false },
      verify: async () => ({
        decision: "ALLOW",
        reason_codes: [],
        receipt: { id: "vrf_allow" },
      }),
      execute: async () => 1,
    });

    expect(result).toEqual({
      status: "failed",
      decision: "ALLOW",
      reasonCodes: [],
      receiptId: "vrf_allow",
      exitCode: 1,
    });
  });

  it("fails closed when verification is unavailable", async () => {
    const execute = vi.fn(async () => 0);

    await expect(
      runGatedDeploy({
        metadata: { commit: "abc123", dirty: false },
        verify: async () => {
          throw new Error("network unavailable");
        },
        execute,
      }),
    ).rejects.toThrowError("network unavailable");
    expect(execute).not.toHaveBeenCalled();
  });
});

describe("vizier-gated-deploy Action Covenant adapter", () => {
  it("executes only after the accepted exact action is authorized and records outcome", async () => {
    const execute = vi.fn(async () => 0);
    const activateCovenant = vi.fn(async (request) => ({
      id: "acv_deploy",
      version: 1 as const,
      status: "ACTIVE" as const,
      activated_at: request.acceptance.accepted_at,
      draft: request.draft,
      acceptance: request.acceptance,
      covenant_hash: "a".repeat(64),
    }));
    const authorizeCovenant = vi.fn(async (request) => ({
      decision: "ALLOW" as const,
      risk_score: 0,
      reason_codes: [],
      explanation: "Allowed.",
      policy_results: [],
      authorization_receipt: {
        payload: {
          type: "ACTION_AUTHORIZATION" as const,
          version: 1 as const,
          id: "azr_deploy",
          issuer: "https://vizier.example",
          issued_at: "2026-08-24T08:00:00.000Z",
          expires_at: "2026-08-24T08:05:00.000Z",
          covenant_id: request.covenant.id,
          covenant_hash: request.covenant.covenant_hash,
          request_hash: "b".repeat(64),
          action_hash: "c".repeat(64),
          evidence_hash: "d".repeat(64),
          signals_hash: "e".repeat(64),
          decision: "ALLOW" as const,
          risk_score: 0,
          policy_rule_ids: ["test.rule"],
          reason_codes: [],
        },
        token: "header.payload.signature",
      },
    }));
    const recordOutcome = vi.fn(async (request) => ({
      payload: {
        type: "OUTCOME_RECEIPT" as const,
        version: 1 as const,
        id: "out_deploy",
        issuer: "https://vizier.example",
        issued_at: request.outcome.finished_at,
        authorization_receipt_id:
          request.authorization_receipt.payload.id,
        authorization_token_hash: "f".repeat(64),
        covenant_id: request.covenant.id,
        covenant_hash: request.covenant.covenant_hash,
        outcome_hash: "1".repeat(64),
        compliance: "COMPLIANT" as const,
        violation_codes: [],
      },
      token: "header.outcome.signature",
    }));
    const times = [
      new Date("2026-08-24T08:00:00.000Z"),
      new Date("2026-08-24T08:00:01.000Z"),
      new Date("2026-08-24T08:00:02.000Z"),
    ];
    const result = await runCovenantGatedDeploy({
      metadata: { commit: "abc123", dirty: false },
      gate: { activateCovenant, authorizeCovenant, recordOutcome },
      execute,
      now: () => times.shift() ?? new Date("2026-08-24T08:00:02.000Z"),
    });

    expect(result).toEqual({
      status: "deployed",
      decision: "ALLOW",
      reasonCodes: [],
      authorizationReceiptId: "azr_deploy",
      outcomeReceiptId: "out_deploy",
      outcomeCompliance: "COMPLIANT",
      exitCode: 0,
    });
    expect(execute).toHaveBeenCalledExactlyOnceWith("azr_deploy");
    expect(activateCovenant).toHaveBeenCalledOnce();
    expect(authorizeCovenant).toHaveBeenCalledOnce();
    expect(recordOutcome).toHaveBeenCalledOnce();
    const authorizationRequest = authorizeCovenant.mock.calls[0]?.[0];
    expect(authorizationRequest?.action.parameters).toMatchObject({
      git_commit: "abc123",
      dirty_worktree: false,
    });
    expect(authorizationRequest?.evidence[0]?.content_hash).toMatch(
      /^[a-f0-9]{64}$/,
    );
  });

  it("does not execute or record an outcome when covenant authorization stops", async () => {
    const execute = vi.fn(async () => 0);
    const recordOutcome = vi.fn();
    const result = await runCovenantGatedDeploy({
      metadata: { commit: "abc123", dirty: true },
      gate: {
        activateCovenant: async (request) => ({
          id: "acv_dirty",
          version: 1,
          status: "ACTIVE",
          activated_at: request.acceptance.accepted_at,
          draft: request.draft,
          acceptance: request.acceptance,
          covenant_hash: "a".repeat(64),
        }),
        authorizeCovenant: async () => ({
          decision: "BLOCK",
          risk_score: 1,
          reason_codes: ["COVENANT_INVALIDATED"],
          explanation: "Blocked.",
          policy_results: [],
          authorization_receipt: {
            payload: {
              type: "ACTION_AUTHORIZATION",
              version: 1,
              id: "azr_dirty",
              issuer: "https://vizier.example",
              issued_at: "2026-08-24T08:00:00.000Z",
              expires_at: "2026-08-24T08:05:00.000Z",
              covenant_id: "acv_dirty",
              covenant_hash: "a".repeat(64),
              request_hash: "b".repeat(64),
              action_hash: "c".repeat(64),
              evidence_hash: "d".repeat(64),
              signals_hash: "e".repeat(64),
              decision: "BLOCK",
              risk_score: 1,
              policy_rule_ids: ["covenant.invalidation.clear"],
              reason_codes: ["COVENANT_INVALIDATED"],
            },
            token: "header.payload.signature",
          },
        }),
        recordOutcome,
      },
      execute,
      now: () => new Date("2026-08-24T08:00:00.000Z"),
    });

    expect(result).toEqual({
      status: "stopped",
      decision: "BLOCK",
      reasonCodes: ["COVENANT_INVALIDATED"],
      authorizationReceiptId: "azr_dirty",
    });
    expect(execute).not.toHaveBeenCalled();
    expect(recordOutcome).not.toHaveBeenCalled();
  });

  it("does not report a proven deployment when outcome recording fails", async () => {
    const result = await runCovenantGatedDeploy({
      metadata: { commit: "abc123", dirty: false },
      gate: {
        activateCovenant: async (request) => ({
          id: "acv_unrecorded",
          version: 1,
          status: "ACTIVE",
          activated_at: request.acceptance.accepted_at,
          draft: request.draft,
          acceptance: request.acceptance,
          covenant_hash: "a".repeat(64),
        }),
        authorizeCovenant: async (request) => ({
          decision: "ALLOW",
          risk_score: 0,
          reason_codes: [],
          explanation: "Allowed.",
          policy_results: [],
          authorization_receipt: {
            payload: {
              type: "ACTION_AUTHORIZATION",
              version: 1,
              id: "azr_unrecorded",
              issuer: "https://vizier.example",
              issued_at: "2026-08-24T08:00:00.000Z",
              expires_at: "2026-08-24T08:05:00.000Z",
              covenant_id: request.covenant.id,
              covenant_hash: request.covenant.covenant_hash,
              request_hash: "b".repeat(64),
              action_hash: "c".repeat(64),
              evidence_hash: "d".repeat(64),
              signals_hash: "e".repeat(64),
              decision: "ALLOW",
              risk_score: 0,
              policy_rule_ids: ["test.rule"],
              reason_codes: [],
            },
            token: "header.payload.signature",
          },
        }),
        recordOutcome: async () => {
          throw new Error("outcome endpoint unavailable");
        },
      },
      execute: async () => 0,
      now: () => new Date("2026-08-24T08:00:00.000Z"),
    });

    expect(result).toEqual({
      status: "outcome_unrecorded",
      deploymentStatus: "deployed",
      decision: "ALLOW",
      reasonCodes: [],
      authorizationReceiptId: "azr_unrecorded",
      exitCode: 0,
      error: "outcome endpoint unavailable",
    });
  });
});
