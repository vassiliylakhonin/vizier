import type {
  ActionCovenant,
  ActionCovenantActivationRequest,
  ActionCovenantAuthorizationRequest,
  ActionCovenantAuthorizationResponse,
  ActionCovenantDraft,
  Decision,
  OutcomeRecordingRequest,
  SignedOutcomeReceipt,
  VerificationRequest,
  VerificationResponse,
} from "@vizier/sdk";
import {
  hashActionCovenantDraft,
  hashCanonicalJson,
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

const DEPLOY_AGENT = {
  id: "vizier-gated-deploy",
  owner: "vassiliy-lakhonin",
} as const;
const DEPLOY_PRINCIPAL = { id: "vassiliy-lakhonin" } as const;
const DEPLOY_TARGET = "worker:vizier";
const COVENANT_TTL_MS = 5 * 60 * 1_000;

export function createDeployCovenantDraft(
  metadata: DeployMetadata,
  draftedAt: Date,
): ActionCovenantDraft {
  return {
    schema_version: "0.2",
    drafted_by: {
      kind: "SYSTEM",
      identifier: "@vizier/gated-deploy",
    },
    drafted_at: draftedAt.toISOString(),
    principal: DEPLOY_PRINCIPAL,
    agent: DEPLOY_AGENT,
    intent: "Deploy exactly the observed Vizier commit and worktree state.",
    action: {
      type: "deploy_worker",
      target: DEPLOY_TARGET,
      parameters: {
        git_commit: metadata.commit,
        dirty_worktree: metadata.dirty,
      },
    },
    authority: {
      allowed_actions: ["deploy_worker"],
      constraints: {
        allowed_targets: [DEPLOY_TARGET],
        allowed_sensitive_actions: ["deploy_worker"],
      },
    },
    evidence_requirements: [
      {
        id: "source-tree",
        evidence_type: "git_worktree_snapshot",
        description: "SHA-256 of the commit and dirty-worktree observation.",
        max_age_seconds: 120,
      },
    ],
    invalidation_rules: [
      {
        id: "worktree-dirty",
        signal_type: "git_worktree_status",
        match: { dirty: true },
        reason: "A deployment must not start from a dirty worktree.",
      },
    ],
    forbidden_outcomes: [
      {
        id: "vizier-worker-deleted",
        effect_type: "delete_worker",
        target: DEPLOY_TARGET,
        reason: "The deploy operation must not delete the Vizier Worker.",
      },
    ],
    expires_at: new Date(draftedAt.getTime() + COVENANT_TTL_MS).toISOString(),
  };
}

export interface CovenantGate {
  readonly activateCovenant: (
    request: ActionCovenantActivationRequest,
  ) => Promise<ActionCovenant>;
  readonly authorizeCovenant: (
    request: ActionCovenantAuthorizationRequest,
  ) => Promise<ActionCovenantAuthorizationResponse>;
  readonly recordOutcome: (
    request: OutcomeRecordingRequest,
  ) => Promise<SignedOutcomeReceipt>;
}

export interface CovenantGatedDeployOptions {
  readonly metadata: DeployMetadata;
  readonly gate: CovenantGate;
  readonly execute: (authorizationReceiptId: string) => Promise<number>;
  readonly now?: () => Date;
}

export type CovenantGatedDeployResult =
  | {
      readonly status: "stopped";
      readonly decision: Exclude<Decision, "ALLOW">;
      readonly reasonCodes: readonly string[];
      readonly authorizationReceiptId: string;
    }
  | {
      readonly status: "deployed" | "failed";
      readonly decision: "ALLOW";
      readonly reasonCodes: readonly string[];
      readonly authorizationReceiptId: string;
      readonly outcomeReceiptId: string;
      readonly outcomeCompliance: "COMPLIANT" | "VIOLATION";
      readonly exitCode: number;
    }
  | {
      readonly status: "outcome_unrecorded";
      readonly deploymentStatus: "deployed" | "failed";
      readonly decision: "ALLOW";
      readonly reasonCodes: readonly string[];
      readonly authorizationReceiptId: string;
      readonly exitCode: number;
      readonly error: string;
    };

export async function runCovenantGatedDeploy(
  options: CovenantGatedDeployOptions,
): Promise<CovenantGatedDeployResult> {
  const now = options.now ?? (() => new Date());
  const observedAt = now();
  const draft = createDeployCovenantDraft(options.metadata, observedAt);
  const covenant = await options.gate.activateCovenant({
    draft,
    acceptance: {
      accepted_by: draft.principal,
      accepted_at: observedAt.toISOString(),
      draft_hash: await hashActionCovenantDraft(draft),
    },
  });
  const authorization = await options.gate.authorizeCovenant({
    covenant,
    action: draft.action,
    evidence: [
      {
        requirement_id: "source-tree",
        evidence_type: "git_worktree_snapshot",
        source: "local-git",
        observed_at: observedAt.toISOString(),
        content_hash: await hashCanonicalJson(options.metadata),
      },
    ],
    signals: [
      {
        signal_type: "git_worktree_status",
        source: "local-git",
        observed_at: observedAt.toISOString(),
        attributes: { dirty: options.metadata.dirty },
      },
    ],
    context: {
      request_id: null,
      timestamp: observedAt.toISOString(),
      source: "internal",
    },
  });
  const authorizationReceiptId =
    authorization.authorization_receipt.payload.id;
  if (authorization.decision !== "ALLOW") {
    return {
      status: "stopped",
      decision: authorization.decision,
      reasonCodes: authorization.reason_codes,
      authorizationReceiptId,
    };
  }

  const startedAt = now();
  const exitCode = await options.execute(authorizationReceiptId);
  const finishedAt = now();
  const deploymentStatus = exitCode === 0 ? "deployed" : "failed";
  try {
    const outcomeReceipt = await options.gate.recordOutcome({
      covenant,
      authorization_receipt: authorization.authorization_receipt,
      outcome: {
        status: exitCode === 0 ? "SUCCEEDED" : "FAILED",
        started_at: startedAt.toISOString(),
        finished_at: finishedAt.toISOString(),
        effects:
          exitCode === 0
            ? [
                {
                  type: "deploy_worker",
                  target: DEPLOY_TARGET,
                  parameters: { git_commit: options.metadata.commit },
                },
              ]
            : [],
        external_reference: null,
      },
    });
    return {
      status: deploymentStatus,
      decision: "ALLOW",
      reasonCodes: authorization.reason_codes,
      authorizationReceiptId,
      outcomeReceiptId: outcomeReceipt.payload.id,
      outcomeCompliance: outcomeReceipt.payload.compliance,
      exitCode,
    };
  } catch (error) {
    return {
      status: "outcome_unrecorded",
      deploymentStatus,
      decision: "ALLOW",
      reasonCodes: authorization.reason_codes,
      authorizationReceiptId,
      exitCode,
      error: error instanceof Error ? error.message : "Unknown outcome error",
    };
  }
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
