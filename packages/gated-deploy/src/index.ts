import type {
  Decision,
  VerificationRequest,
  VerificationResponse,
} from "@vizier/sdk";

export interface DeployMetadata {
  readonly commit: string;
  readonly dirty: boolean;
}

export function assertCleanWorktree(metadata: DeployMetadata): void {
  if (metadata.dirty) {
    throw new Error("Commit or stash local changes before deployment.");
  }
}

interface GateResponse {
  readonly decision: Decision;
  readonly reason_codes: readonly string[];
  readonly receipt: { readonly id: string };
}

export interface GatedDeployOptions {
  readonly metadata: DeployMetadata;
  readonly verify: (
    request: VerificationRequest,
  ) => Promise<GateResponse | VerificationResponse>;
  readonly execute: (receiptId: string) => Promise<number>;
}

export type GatedDeployResult =
  | {
      readonly status: "stopped";
      readonly decision: Exclude<Decision, "ALLOW">;
      readonly reasonCodes: readonly string[];
      readonly receiptId: string;
    }
  | {
      readonly status: "deployed" | "failed";
      readonly decision: "ALLOW";
      readonly reasonCodes: readonly string[];
      readonly receiptId: string;
      readonly exitCode: number;
    };

export function createDeployRequest(metadata: DeployMetadata): VerificationRequest {
  return {
    agent: { id: "vizier-gated-deploy", owner: "vassiliy-lakhonin" },
    principal: { id: "vassiliy-lakhonin" },
    action: {
      type: "deploy_worker",
      target: "worker:vizier",
      parameters: {
        git_commit: metadata.commit,
        dirty_worktree: metadata.dirty,
      },
    },
    authority: {
      allowed_actions: ["deploy_worker"],
      constraints: {
        allowed_targets: ["worker:vizier"],
        allowed_sensitive_actions: ["deploy_worker"],
      },
    },
    context: {
      request_id: null,
      timestamp: null,
      source: "internal",
    },
  };
}

export async function runGatedDeploy(
  options: GatedDeployOptions,
): Promise<GatedDeployResult> {
  assertCleanWorktree(options.metadata);
  const response = await options.verify(createDeployRequest(options.metadata));
  if (response.decision !== "ALLOW") {
    return {
      status: "stopped",
      decision: response.decision,
      reasonCodes: response.reason_codes,
      receiptId: response.receipt.id,
    };
  }

  const exitCode = await options.execute(response.receipt.id);
  return {
    status: exitCode === 0 ? "deployed" : "failed",
    decision: "ALLOW",
    reasonCodes: response.reason_codes,
    receiptId: response.receipt.id,
    exitCode,
  };
}
