import type { KVNamespace } from "@cloudflare/workers-types";
import { canonicalize, sha256 } from "./receipts";
import type {
  QuorumApproval,
  QuorumConstraints,
  VerificationRequest,
} from "./schemas";

export interface QuorumProposal {
  readonly proposal_id: string;
  readonly proposer: {
    readonly id: string;
    readonly owner?: string | null;
  };
  readonly action_hash: string;
  readonly action: {
    readonly type: string;
    readonly target: string;
    readonly parameters: Record<string, unknown>;
  };
  readonly constraints: QuorumConstraints;
  readonly created_at: string;
  readonly expires_at: string;
  readonly status: "PENDING" | "APPROVED" | "REJECTED" | "EXPIRED" | "CONSUMED";
  readonly approvals: readonly QuorumApproval[];
}

export type QuorumFailureReason =
  | "QUORUM_NOT_MET"
  | "QUORUM_REJECTED"
  | "SELF_APPROVAL_DISALLOWED"
  | "QUORUM_ACTION_MISMATCH"
  | "PROPOSAL_EXPIRED"
  | "PROPOSAL_NOT_FOUND"
  | "PROPOSAL_ALREADY_CONSUMED"
  | "UNAUTHORIZED_APPROVER";

export interface QuorumEvaluationResult {
  readonly required: boolean;
  readonly satisfied: boolean;
  readonly reasonCode?: QuorumFailureReason;
  readonly details: Readonly<{
    required_approvals?: number;
    current_approvals?: number;
    approvers?: readonly string[];
    proposal_id?: string;
    action_hash?: string;
    [key: string]: unknown;
  }>;
}

// In-memory store for local testing and standalone mode
const memoryProposalStore = new Map<string, QuorumProposal>();

export function clearMemoryProposalStore(): void {
  memoryProposalStore.clear();
}

/**
 * Computes the deterministic SHA-256 hash of an action payload.
 */
export async function computeActionHash(
  action: VerificationRequest["action"],
): Promise<string> {
  const canonical = canonicalize(action);
  return sha256(canonical);
}

/**
 * Generates a unique proposal ID.
 */
export function generateProposalId(): string {
  return `prp_${crypto.randomUUID()}`;
}

/**
 * Creates and stores a new quorum proposal.
 */
export async function createQuorumProposal(
  options: {
    kv?: KVNamespace;
    proposer: { id: string; owner?: string | null };
    action: VerificationRequest["action"];
    constraints: QuorumConstraints;
    ttlSeconds?: number;
    now?: () => Date;
  },
): Promise<QuorumProposal> {
  const now = options.now ? options.now() : new Date();
  const ttl = options.ttlSeconds ?? options.constraints.max_age_seconds ?? 900;
  const expiresAt = new Date(now.getTime() + ttl * 1000);
  const actionHash = await computeActionHash(options.action);
  const proposalId = generateProposalId();

  const proposal: QuorumProposal = Object.freeze({
    proposal_id: proposalId,
    proposer: Object.freeze({ ...options.proposer }),
    action_hash: actionHash,
    action: Object.freeze({
      type: options.action.type,
      target: options.action.target,
      parameters: Object.freeze({ ...options.action.parameters }),
    }),
    constraints: Object.freeze({ ...options.constraints }),
    created_at: now.toISOString(),
    expires_at: expiresAt.toISOString(),
    status: "PENDING",
    approvals: Object.freeze([]),
  });

  if (options.kv) {
    await options.kv.put(`quorum:proposal:${proposalId}`, JSON.stringify(proposal), {
      expirationTtl: Math.max(ttl, 60),
    });
  } else {
    memoryProposalStore.set(proposalId, proposal);
  }

  return proposal;
}

/**
 * Retrieves a quorum proposal from KV or in-memory store.
 */
export async function getQuorumProposal(
  proposalId: string,
  kv?: KVNamespace,
): Promise<QuorumProposal | null> {
  if (kv) {
    const raw = await kv.get(`quorum:proposal:${proposalId}`);
    if (!raw) return null;
    try {
      const parsed = JSON.parse(raw) as QuorumProposal;
      if (Date.parse(parsed.expires_at) < Date.now() && parsed.status === "PENDING") {
        return { ...parsed, status: "EXPIRED" };
      }
      return parsed;
    } catch {
      return null;
    }
  }

  const found = memoryProposalStore.get(proposalId);
  if (!found) return null;
  if (Date.parse(found.expires_at) < Date.now() && found.status === "PENDING") {
    return { ...found, status: "EXPIRED" };
  }
  return found;
}

/**
 * Records an approval or rejection for an existing proposal.
 */
export async function recordQuorumApproval(
  options: {
    kv?: KVNamespace;
    proposalId: string;
    approval: QuorumApproval;
    now?: () => Date;
  },
): Promise<QuorumProposal> {
  const proposal = await getQuorumProposal(options.proposalId, options.kv);
  if (!proposal) {
    throw new Error(`Proposal '${options.proposalId}' not found.`);
  }

  const now = options.now ? options.now() : new Date();
  if (Date.parse(proposal.expires_at) < now.getTime()) {
    throw new Error(`Proposal '${options.proposalId}' has expired.`);
  }

  if (proposal.status === "REJECTED") {
    throw new Error(`Proposal '${options.proposalId}' is already rejected.`);
  }

  // Prevent self-approval
  if (options.approval.approver_id === proposal.proposer.id) {
    throw new Error("Self-approval is disallowed: proposing agent cannot approve own proposal.");
  }

  // Verify action hash match
  if (options.approval.action_hash !== proposal.action_hash) {
    throw new Error("Approval action_hash does not match proposal action_hash.");
  }

  // Check allowed approvers
  if (
    proposal.constraints.allowed_approvers &&
    !proposal.constraints.allowed_approvers.includes(options.approval.approver_id)
  ) {
    throw new Error(
      `Approver '${options.approval.approver_id}' is not in allowed_approvers set.`,
    );
  }

  // Check distinct owners if required
  if (
    proposal.constraints.require_distinct_owners &&
    proposal.proposer.owner &&
    options.approval.approver_owner &&
    options.approval.approver_owner === proposal.proposer.owner
  ) {
    throw new Error("Approver and proposer must have distinct owners.");
  }

  // Deduplicate previous approvals by this approver_id
  const filteredApprovals = proposal.approvals.filter(
    (a) => a.approver_id !== options.approval.approver_id,
  );
  const updatedApprovals = [...filteredApprovals, options.approval];

  let newStatus: QuorumProposal["status"] = proposal.status;
  if (options.approval.decision === "REJECT") {
    newStatus = "REJECTED";
  } else {
    const validCount = updatedApprovals.filter((a) => a.decision === "APPROVE").length;
    if (validCount >= proposal.constraints.min_approvals) {
      newStatus = "APPROVED";
    }
  }

  const updatedProposal: QuorumProposal = Object.freeze({
    ...proposal,
    status: newStatus,
    approvals: Object.freeze(updatedApprovals),
  });

  if (options.kv) {
    const remainingSeconds = Math.max(
      Math.floor((Date.parse(proposal.expires_at) - now.getTime()) / 1000),
      60,
    );
    await options.kv.put(
      `quorum:proposal:${options.proposalId}`,
      JSON.stringify(updatedProposal),
      { expirationTtl: remainingSeconds },
    );
  } else {
    memoryProposalStore.set(options.proposalId, updatedProposal);
  }

  return updatedProposal;
}

/**
 * Marks an approved quorum proposal as CONSUMED so it cannot be re-executed or replayed.
 */
export async function consumeQuorumProposal(
  proposalId: string,
  kv?: KVNamespace,
): Promise<boolean> {
  const proposal = await getQuorumProposal(proposalId, kv);
  if (!proposal || proposal.status === "CONSUMED") {
    return false;
  }
  const consumedProposal: QuorumProposal = Object.freeze({
    ...proposal,
    status: "CONSUMED" as const,
  });
  if (kv) {
    const remainingSeconds = Math.max(
      Math.floor((Date.parse(proposal.expires_at) - Date.now()) / 1000),
      60,
    );
    await kv.put(
      `quorum:proposal:${proposalId}`,
      JSON.stringify(consumedProposal),
      { expirationTtl: remainingSeconds },
    );
  } else {
    memoryProposalStore.set(proposalId, consumedProposal);
  }
  return true;
}

/**
 * Evaluates whether quorum requirements are satisfied for a VerificationRequest.
 */
export async function evaluateQuorum(
  request: VerificationRequest,
  kv?: KVNamespace,
  nowFn: () => Date = () => new Date(),
): Promise<QuorumEvaluationResult> {
  const constraints = request.authority.constraints.quorum;
  if (!constraints) {
    return { required: false, satisfied: true, details: {} };
  }

  const expectedActionHash = await computeActionHash(request.action);
  const minApprovals = constraints.min_approvals;
  const maxAgeMs = (constraints.max_age_seconds ?? 900) * 1000;
  const now = nowFn();

  let approvalsToEvaluate: readonly QuorumApproval[];
  let proposalId: string | undefined;

  // 1. If context has proposal_id, look it up
  if (request.context.proposal_id) {
    proposalId = request.context.proposal_id;
    const proposal = await getQuorumProposal(proposalId, kv);
    if (!proposal) {
      return {
        required: true,
        satisfied: false,
        reasonCode: "PROPOSAL_NOT_FOUND",
        details: { proposal_id: proposalId },
      };
    }

    if (proposal.status === "CONSUMED") {
      return {
        required: true,
        satisfied: false,
        reasonCode: "PROPOSAL_ALREADY_CONSUMED",
        details: { proposal_id: proposalId },
      };
    }

    if (proposal.status === "EXPIRED" || Date.parse(proposal.expires_at) < now.getTime()) {
      return {
        required: true,
        satisfied: false,
        reasonCode: "PROPOSAL_EXPIRED",
        details: { proposal_id: proposalId, expires_at: proposal.expires_at },
      };
    }

    if (proposal.action_hash !== expectedActionHash) {
      return {
        required: true,
        satisfied: false,
        reasonCode: "QUORUM_ACTION_MISMATCH",
        details: {
          proposal_id: proposalId,
          expected_action_hash: expectedActionHash,
          proposal_action_hash: proposal.action_hash,
        },
      };
    }

    approvalsToEvaluate = proposal.approvals;
  } else if (request.context.approvals && request.context.approvals.length > 0) {
    // 2. Stateless mode: approvals passed inline in context
    approvalsToEvaluate = request.context.approvals;
  } else {
    // 3. No proposal_id and no inline approvals provided
    return {
      required: true,
      satisfied: false,
      reasonCode: "QUORUM_NOT_MET",
      details: {
        required_approvals: minApprovals,
        current_approvals: 0,
        missing: minApprovals,
        action_hash: expectedActionHash,
      },
    };
  }

  // Check for self-approval
  for (const app of approvalsToEvaluate) {
    if (app.approver_id === request.agent.id) {
      return {
        required: true,
        satisfied: false,
        reasonCode: "SELF_APPROVAL_DISALLOWED",
        details: {
          approver_id: app.approver_id,
          agent_id: request.agent.id,
          action_hash: expectedActionHash,
        },
      };
    }
  }

  // Check for explicit rejection
  const rejection = approvalsToEvaluate.find((a) => a.decision === "REJECT");
  if (rejection) {
    return {
      required: true,
      satisfied: false,
      reasonCode: "QUORUM_REJECTED",
      details: {
        rejected_by: rejection.approver_id,
        notes: rejection.notes,
        action_hash: expectedActionHash,
      },
    };
  }

  // Validate each approval
  const validApprovers = new Set<string>();
  for (const app of approvalsToEvaluate) {
    if (app.decision !== "APPROVE") continue;

    // Action hash match
    if (app.action_hash !== expectedActionHash) {
      return {
        required: true,
        satisfied: false,
        reasonCode: "QUORUM_ACTION_MISMATCH",
        details: {
          approver_id: app.approver_id,
          expected_action_hash: expectedActionHash,
          approval_action_hash: app.action_hash,
        },
      };
    }

    // Expiration
    const approvalTime = Date.parse(app.timestamp);
    if (now.getTime() - approvalTime > maxAgeMs) {
      continue; // Expired approval, ignore
    }

    // Allowed approvers
    if (
      constraints.allowed_approvers &&
      !constraints.allowed_approvers.includes(app.approver_id)
    ) {
      return {
        required: true,
        satisfied: false,
        reasonCode: "UNAUTHORIZED_APPROVER",
        details: {
          approver_id: app.approver_id,
          allowed_approvers: constraints.allowed_approvers,
        },
      };
    }

    // Distinct owners check
    if (
      constraints.require_distinct_owners &&
      request.agent.owner &&
      app.approver_owner &&
      app.approver_owner === request.agent.owner
    ) {
      continue; // Ignored if not distinct owner
    }

    validApprovers.add(app.approver_id);
  }

  if (validApprovers.size < minApprovals) {
    return {
      required: true,
      satisfied: false,
      reasonCode: "QUORUM_NOT_MET",
      details: {
        required_approvals: minApprovals,
        current_approvals: validApprovers.size,
        missing: minApprovals - validApprovers.size,
        approvers: Array.from(validApprovers),
        action_hash: expectedActionHash,
        ...(proposalId ? { proposal_id: proposalId } : {}),
      },
    };
  }

  return {
    required: true,
    satisfied: true,
    details: {
      required_approvals: minApprovals,
      current_approvals: validApprovers.size,
      approvers: Array.from(validApprovers),
      action_hash: expectedActionHash,
      ...(proposalId ? { proposal_id: proposalId } : {}),
    },
  };
}
