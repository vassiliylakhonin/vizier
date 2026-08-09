import { describe, expect, it, vi } from "vitest";

import {
  assertCleanWorktree,
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
