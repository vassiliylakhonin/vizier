import { z } from "zod";
import { type HumanReviewRequest, type Vizier } from "@agenda-intelligence/vizier-sdk";

const accountId = z.string().regex(/^[a-f0-9]{32}$/);
const workerName = z.string().regex(/^[a-z0-9][a-z0-9-]{0,62}$/);
const identity = z.string().min(1).max(256);
const versionId = z.string().uuid();

const scopeSchema = z.strictObject({
  account_id: accountId,
  worker_name: workerName,
  principal_id: identity,
  agent_id: identity,
});

/** The only operation admitted by this adapter. No URLs, shell or credentials. */
const planSchema = z.strictObject({
  operation: z.literal("deploy_worker_version"),
  account_id: accountId,
  worker_name: workerName,
  version_id: versionId,
  percentage: z.literal(100),
});

export type WorkerDeploymentScope = Readonly<z.infer<typeof scopeSchema>>;
export type WorkerVersionPlan = Readonly<z.infer<typeof planSchema>>;

export const WORKER_DEPLOY_REVIEW_AUDIENCE = "vizier:cloudflare-worker-version-deploy";

function scopedPlan(scope: WorkerDeploymentScope, input: unknown): WorkerVersionPlan {
  const plan = planSchema.parse(input);
  if (plan.account_id !== scope.account_id || plan.worker_name !== scope.worker_name) {
    throw new Error("Plan is outside the operator's fixed Worker scope.");
  }
  return Object.freeze(plan);
}

function target(scope: WorkerDeploymentScope): string {
  return `cloudflare:account:${scope.account_id}:worker:${scope.worker_name}`;
}

/** This exact authority must be signed by the owner, outside the agent process. */
export function workerDeploymentAuthority(scope: WorkerDeploymentScope) {
  const checked = scopeSchema.parse(scope);
  return {
    allowed_actions: ["deploy_worker_version"],
    constraints: {
      allowed_targets: [target(checked)],
      allowed_sensitive_actions: ["deploy_worker_version"],
    },
  };
}

/** Submit this exact packet to Vizier's existing human-review queue. */
export function prepareWorkerDeploymentReview(
  scope: WorkerDeploymentScope,
  input: unknown,
): HumanReviewRequest {
  const checked = scopeSchema.parse(scope);
  const plan = scopedPlan(checked, input);
  return {
    audience: WORKER_DEPLOY_REVIEW_AUDIENCE,
    action: { type: plan.operation, target: target(checked), parameters: { ...plan } },
    evidence: { principal_id: checked.principal_id, agent_id: checked.agent_id },
    escalation_reason: "Approve this exact existing Worker version at 100% traffic.",
    expires_in_seconds: 1800,
  };
}

export interface WorkerVersionDeploymentOptions {
  /** Trusted operator configuration; never construct it from an agent request. */
  readonly scope: WorkerDeploymentScope;
  readonly vizier: Vizier;
  readonly cloudflareApiToken: string;
  readonly cloudflareFetch?: typeof globalThis.fetch;
}

export interface WorkerVersionDeploymentInput {
  readonly plan: unknown;
  readonly grant: string;
  readonly approval: { readonly id: string; readonly token: string };
}

export type WorkerVersionDeploymentResult =
  | { readonly status: "stopped"; readonly reason: string; readonly execution: "not_performed" }
  | {
      readonly status: "deployment_created";
      readonly execution: "acknowledged";
      readonly deploymentId: string;
      readonly receiptId: string;
      readonly approvalId: string;
    }
  | {
      readonly status: "reconcile_required";
      readonly execution: "unknown";
      readonly receiptId: string;
      readonly approvalId: string;
      readonly deploymentId?: string;
    };

const deploymentSchema = z.object({
  id: z.string().uuid(),
  strategy: z.literal("percentage"),
  versions: z.array(z.object({ version_id: versionId, percentage: z.literal(100) })).length(1),
});
const acknowledgementSchema = z.object({
  success: z.literal(true),
  errors: z.array(z.unknown()).length(0),
  result: z.object({
    id: z.string().uuid(),
    strategy: z.unknown().optional(),
    versions: z.unknown().optional(),
  }),
});
const historySchema = z.object({
  success: z.literal(true),
  errors: z.array(z.unknown()).length(0),
  result: z.object({ deployments: z.array(z.unknown()).max(1000) }),
});

/**
 * Operator-owned executor. The returned function is the agent's sole capability.
 * Cloudflare credentials and the raw SDK must not be exposed to the agent.
 */
export function createWorkerVersionDeployer(options: WorkerVersionDeploymentOptions) {
  const scope = Object.freeze(scopeSchema.parse(options.scope));
  const token = z.string().min(1).regex(/^\S+$/).parse(options.cloudflareApiToken);
  const vizier = options.vizier;
  const cloudflareFetch = options.cloudflareFetch ?? globalThis.fetch;
  const url = `https://api.cloudflare.com/client/v4/accounts/${scope.account_id}/workers/scripts/${scope.worker_name}/deployments`;

  return async (input: WorkerVersionDeploymentInput): Promise<WorkerVersionDeploymentResult> => {
    const stop = (reason: string): WorkerVersionDeploymentResult => ({
      status: "stopped", reason, execution: "not_performed",
    });
    let plan: WorkerVersionPlan;
    try { plan = scopedPlan(scope, input.plan); }
    catch { return stop("PLAN_OUTSIDE_SCOPE_OR_INVALID"); }
    // Snapshot agent-controlled inputs before any asynchronous boundary.
    const grant = input.grant;
    const approval = { ...input.approval };
    if (typeof grant !== "string" || !grant || typeof approval.id !== "string" || !approval.id ||
        typeof approval.token !== "string" || !approval.token) return stop("AUTHORIZATION_REQUIRED");
    const review = prepareWorkerDeploymentReview(scope, plan);
    const body = JSON.stringify({
      strategy: "percentage", versions: [{ version_id: plan.version_id, percentage: 100 }],
    });
    let receipt;
    try {
      const response = await vizier.verify({
        agent: { id: scope.agent_id, owner: scope.principal_id },
        principal: { id: scope.principal_id },
        action: { type: plan.operation, target: target(scope), parameters: { ...plan } },
        authority: workerDeploymentAuthority(scope),
        context: { request_id: approval.id, timestamp: null, source: "internal" },
        grant,
      }, { signal: AbortSignal.timeout(10_000) });
      if (response.decision !== "ALLOW") return stop(`POLICY_${response.decision}`);
      receipt = response.receipt;
      if (receipt.authority_provenance !== "principal_signed" ||
          receipt.grant?.issuer !== scope.principal_id || receipt.grant.subject !== scope.agent_id ||
          Date.parse(receipt.grant.expires_at) <= Date.now()) return stop("SIGNED_AUTHORIZATION_REQUIRED");
      // SDK verifies signature, issuer, audience, exact review hash and expiry.
      // Server consumption atomically admits only one claimant for this review.
      await vizier.claimHumanReview(review, approval.id, approval.token, {
        signal: AbortSignal.timeout(10_000),
      });
      if (Date.parse(receipt.grant.expires_at) <= Date.now()) return stop("GRANT_EXPIRED_BEFORE_EXECUTION");
    } catch {
      // A failed/lost claim may have consumed approval. Never auto-retry it.
      return stop("AUTHORIZATION_FAILED_RECONCILE_APPROVAL");
    }
    let acknowledgedId: string | undefined;
    try {
      const signal = AbortSignal.timeout(15_000);
      const headers = { Authorization: `Bearer ${token}`, "Content-Type": "application/json" };
      const response = await cloudflareFetch(url, {
        method: "POST",
        headers,
        body,
        redirect: "error",
        signal,
      });
      const result = acknowledgementSchema.safeParse(await response.json());
      let deployment: unknown;
      if (response.ok && result.success) {
        acknowledgedId = result.data.result.id;
        deployment = result.data.result;
        // The real API may acknowledge only {id}. Confirm it by reading history;
        // do not infer the version or issue another deployment request.
        if (result.data.result.strategy === undefined && result.data.result.versions === undefined) {
          const historyResponse = await cloudflareFetch(url, { method: "GET", headers, redirect: "error", signal });
          const history = historySchema.safeParse(await historyResponse.json());
          if (historyResponse.ok && history.success) {
            const matching = history.data.result.deployments.filter(row =>
              typeof row === "object" && row !== null && "id" in row && row.id === acknowledgedId,
            );
            if (matching.length === 1) deployment = matching[0];
          }
        }
      }
      const confirmed = deploymentSchema.safeParse(deployment);
      if (confirmed.success && confirmed.data.id === acknowledgedId && confirmed.data.versions[0]?.version_id === plan.version_id) {
        return {
          status: "deployment_created", execution: "acknowledged",
          deploymentId: confirmed.data.id, receiptId: receipt.id, approvalId: approval.id,
        };
      }
    } catch { /* The cloud may have committed the request before response loss. */ }
    return {
      status: "reconcile_required", execution: "unknown",
      receiptId: receipt.id, approvalId: approval.id,
      ...(acknowledgedId === undefined ? {} : { deploymentId: acknowledgedId }),
    };
  };
}
