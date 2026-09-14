import { describe, expect, it, beforeEach } from "vitest";
import type { KVNamespace } from "@cloudflare/workers-types";
import {
  clearMemoryProposalStore,
  computeActionHash,
  consumeQuorumProposal,
  createQuorumProposal,
  evaluateQuorum,
  getQuorumProposal,
  recordQuorumApproval,
  verifyAction,
  type VerificationRequest,
} from "../src/core/index";
import { handleHttpRequest } from "../src/transport/http";

const TEST_API_KEY = "test-api-key-quorum";

function makeRequest(
  method: string,
  path: string,
  body?: unknown,
  auth = true,
): Request {
  const headers = new Headers();
  if (auth) {
    headers.set("Authorization", `Bearer ${TEST_API_KEY}`);
  }
  if (body !== undefined) {
    headers.set("Content-Type", "application/json");
  }
  return new Request(`https://test.local${path}`, {
    method,
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
}

function makeKvMock(): KVNamespace {
  const store = new Map<string, string>();
  return {
    async get(key: string) {
      return store.get(key) ?? null;
    },
    async put(key: string, value: string) {
      store.set(key, value);
    },
    async delete(key: string) {
      store.delete(key);
    },
    store,
  } as unknown as KVNamespace;
}

describe("Multi-Agent Quorum & Dual-Control Gate", () => {
  beforeEach(() => {
    clearMemoryProposalStore();
  });

  describe("Action Hashing & Canonicalization", () => {
    it("computes identical hash for actions with differently ordered keys", async () => {
      const action1 = {
        type: "transfer_funds",
        target: "bank_api",
        parameters: { recipient: "alice", amount: 500, currency: "USD" },
      };
      const action2 = {
        type: "transfer_funds",
        target: "bank_api",
        parameters: { currency: "USD", amount: 500, recipient: "alice" },
      };
      const hash1 = await computeActionHash(action1);
      const hash2 = await computeActionHash(action2);
      expect(hash1).toBe(hash2);
      expect(hash1).toMatch(/^[a-f0-9]{64}$/);
    });

    it("computes different hashes for actions with different parameter values", async () => {
      const action1 = {
        type: "transfer_funds",
        target: "bank_api",
        parameters: { recipient: "alice", amount: 500 },
      };
      const action2 = {
        type: "transfer_funds",
        target: "bank_api",
        parameters: { recipient: "alice", amount: 501 },
      };
      const hash1 = await computeActionHash(action1);
      const hash2 = await computeActionHash(action2);
      expect(hash1).not.toBe(hash2);
    });
  });

  describe("Proposal Storage & Approval Lifecycle", () => {
    const proposer = { id: "agent-alpha", owner: "corp" };
    const action = {
      type: "deploy_worker",
      target: "cloudflare_edge",
      parameters: { worker_name: "payment-router", environment: "production" },
    };

    it("creates proposal in PENDING status and retrieves it", async () => {
      const proposal = await createQuorumProposal({
        proposer,
        action,
        constraints: { min_approvals: 2 },
      });

      expect(proposal.proposal_id).toMatch(/^prp_/);
      expect(proposal.status).toBe("PENDING");
      expect(proposal.approvals).toHaveLength(0);

      const fetched = await getQuorumProposal(proposal.proposal_id);
      expect(fetched).not.toBeNull();
      expect(fetched?.proposal_id).toBe(proposal.proposal_id);
      expect(fetched?.action_hash).toBe(proposal.action_hash);
    });

    it("prohibits self-approval by the proposing agent", async () => {
      const proposal = await createQuorumProposal({
        proposer,
        action,
        constraints: { min_approvals: 2 },
      });

      await expect(
        recordQuorumApproval({
          proposalId: proposal.proposal_id,
          approval: {
            approver_id: "agent-alpha", // same as proposer!
            action_hash: proposal.action_hash,
            timestamp: new Date().toISOString(),
            decision: "APPROVE",
          },
        }),
      ).rejects.toThrow(/Self-approval is disallowed/);
    });

    it("rejects approval if action_hash does not match proposal", async () => {
      const proposal = await createQuorumProposal({
        proposer,
        action,
        constraints: { min_approvals: 2 },
      });

      await expect(
        recordQuorumApproval({
          proposalId: proposal.proposal_id,
          approval: {
            approver_id: "auditor-1",
            action_hash: "0000000000000000000000000000000000000000000000000000000000000000",
            timestamp: new Date().toISOString(),
            decision: "APPROVE",
          },
        }),
      ).rejects.toThrow(/action_hash does not match/);
    });

    it("enforces allowed_approvers whitelist when configured", async () => {
      const proposal = await createQuorumProposal({
        proposer,
        action,
        constraints: {
          min_approvals: 1,
          allowed_approvers: ["security-auditor-agent", "ciso-agent"],
        },
      });

      // Rogue agent tries to approve
      await expect(
        recordQuorumApproval({
          proposalId: proposal.proposal_id,
          approval: {
            approver_id: "rogue-agent",
            action_hash: proposal.action_hash,
            timestamp: new Date().toISOString(),
            decision: "APPROVE",
          },
        }),
      ).rejects.toThrow(/not in allowed_approvers set/);

      // Authorized agent approves
      const updated = await recordQuorumApproval({
        proposalId: proposal.proposal_id,
        approval: {
          approver_id: "security-auditor-agent",
          action_hash: proposal.action_hash,
          timestamp: new Date().toISOString(),
          decision: "APPROVE",
        },
      });
      expect(updated.status).toBe("APPROVED");
    });

    it("enforces distinct owners when require_distinct_owners is true", async () => {
      const proposal = await createQuorumProposal({
        proposer: { id: "agent-alpha", owner: "corp" },
        action,
        constraints: {
          min_approvals: 1,
          require_distinct_owners: true,
        },
      });

      // Approver with same owner fails
      await expect(
        recordQuorumApproval({
          proposalId: proposal.proposal_id,
          approval: {
            approver_id: "agent-beta",
            approver_owner: "corp", // Same owner!
            action_hash: proposal.action_hash,
            timestamp: new Date().toISOString(),
            decision: "APPROVE",
          },
        }),
      ).rejects.toThrow(/distinct owners/);

      // Approver with independent owner succeeds
      const approved = await recordQuorumApproval({
        proposalId: proposal.proposal_id,
        approval: {
          approver_id: "auditor-external",
          approver_owner: "external-audit-firm",
          action_hash: proposal.action_hash,
          timestamp: new Date().toISOString(),
          decision: "APPROVE",
        },
      });
      expect(approved.status).toBe("APPROVED");
    });

    it("transitions to APPROVED when min_approvals reached and REJECTED on explicit veto", async () => {
      const proposal = await createQuorumProposal({
        proposer,
        action,
        constraints: { min_approvals: 2 },
      });

      // 1st approval
      const afterFirst = await recordQuorumApproval({
        proposalId: proposal.proposal_id,
        approval: {
          approver_id: "auditor-1",
          action_hash: proposal.action_hash,
          timestamp: new Date().toISOString(),
          decision: "APPROVE",
        },
      });
      expect(afterFirst.status).toBe("PENDING");
      expect(afterFirst.approvals).toHaveLength(1);

      // 2nd approval -> threshold met!
      const afterSecond = await recordQuorumApproval({
        proposalId: proposal.proposal_id,
        approval: {
          approver_id: "auditor-2",
          action_hash: proposal.action_hash,
          timestamp: new Date().toISOString(),
          decision: "APPROVE",
        },
      });
      expect(afterSecond.status).toBe("APPROVED");
      expect(afterSecond.approvals).toHaveLength(2);
    });

    it("vetoes immediately when an approver casts REJECT", async () => {
      const proposal = await createQuorumProposal({
        proposer,
        action,
        constraints: { min_approvals: 2 },
      });

      const rejected = await recordQuorumApproval({
        proposalId: proposal.proposal_id,
        approval: {
          approver_id: "security-auditor",
          action_hash: proposal.action_hash,
          timestamp: new Date().toISOString(),
          decision: "REJECT",
          notes: "Detected suspicious payload syntax",
        },
      });
      expect(rejected.status).toBe("REJECTED");
    });

    it("transitions to CONSUMED via consumeQuorumProposal and rejects re-use with PROPOSAL_ALREADY_CONSUMED", async () => {
      const proposal = await createQuorumProposal({
        proposer,
        action,
        constraints: { min_approvals: 1 },
      });

      await recordQuorumApproval({
        proposalId: proposal.proposal_id,
        approval: {
          approver_id: "auditor-1",
          action_hash: proposal.action_hash,
          timestamp: new Date().toISOString(),
          decision: "APPROVE",
        },
      });

      const verificationReq: VerificationRequest = {
        agent: { id: "agent-caller", owner: "corp" },
        principal: { id: "corp" },
        action,
        authority: {
          allowed_actions: [action.type],
          constraints: { quorum: { min_approvals: 1 } },
        },
        context: {
          request_id: "req-consume-test",
          timestamp: new Date().toISOString(),
          source: "rest",
          proposal_id: proposal.proposal_id,
        },
      };

      // First evaluation before consumption -> satisfied!
      const evalBefore = await evaluateQuorum(verificationReq);
      expect(evalBefore.satisfied).toBe(true);

      // Consume the proposal
      const consumed = await consumeQuorumProposal(proposal.proposal_id);
      expect(consumed).toBe(true);

      const stored = await getQuorumProposal(proposal.proposal_id);
      expect(stored?.status).toBe("CONSUMED");

      // Second evaluation after consumption -> rejected with PROPOSAL_ALREADY_CONSUMED!
      const evalAfter = await evaluateQuorum(verificationReq);
      expect(evalAfter.satisfied).toBe(false);
      expect(evalAfter.reasonCode).toBe("PROPOSAL_ALREADY_CONSUMED");
    });
  });

  describe("Core Kernel Quorum Policy Evaluation", () => {
    const sampleAction = {
      type: "transfer_funds",
      target: "bank_gateway",
      parameters: { recipient: "supplier_123", amount: 10000 },
      is_reversible: true,
    };

    it("passes immediately when quorum is not configured", async () => {
      const req: VerificationRequest = {
        agent: { id: "agent-1", owner: "corp" },
        principal: { id: "corp" },
        action: sampleAction,
        authority: {
          allowed_actions: ["transfer_funds"],
          constraints: {
            allowed_sensitive_actions: ["transfer_funds"],
          },
        },
        context: {
          request_id: "req-1",
          timestamp: new Date().toISOString(),
          source: "rest",
        },
      };
      const res = await verifyAction(req);
      expect(res.decision).toBe("ALLOW");
    });

    it("blocks with QUORUM_NOT_MET when quorum is required but no proposal/approvals provided", async () => {
      const req: VerificationRequest = {
        agent: { id: "agent-1", owner: "corp" },
        principal: { id: "corp" },
        action: sampleAction,
        authority: {
          allowed_actions: ["transfer_funds"],
          constraints: {
            allowed_sensitive_actions: ["transfer_funds"],
            quorum: { min_approvals: 2 },
          },
        },
        context: {
          request_id: "req-1",
          timestamp: new Date().toISOString(),
          source: "rest",
        },
      };
      const res = await verifyAction(req);
      expect(res.decision).toBe("BLOCK");
      expect(res.reason_codes).toContain("QUORUM_NOT_MET");
    });

    it("evaluates stateless inline approvals in context.approvals", async () => {
      const actionHash = await computeActionHash(sampleAction);

      // Request with 2 valid inline approvals
      const req: VerificationRequest = {
        agent: { id: "agent-1", owner: "corp" },
        principal: { id: "corp" },
        action: sampleAction,
        authority: {
          allowed_actions: ["transfer_funds"],
          constraints: {
            allowed_sensitive_actions: ["transfer_funds"],
            quorum: { min_approvals: 2 },
          },
        },
        context: {
          request_id: "req-1",
          timestamp: new Date().toISOString(),
          source: "rest",
          approvals: [
            {
              approver_id: "auditor-agent-alpha",
              action_hash: actionHash,
              timestamp: new Date().toISOString(),
              decision: "APPROVE",
            },
            {
              approver_id: "auditor-agent-beta",
              action_hash: actionHash,
              timestamp: new Date().toISOString(),
              decision: "APPROVE",
            },
          ],
        },
      };

      const res = await verifyAction(req);
      expect(res.decision).toBe("ALLOW");
      const quorumRule = res.policy_results.find(
        (p) => p.rule_id === "governance.quorum",
      );
      expect(quorumRule?.result).toBe("PASS");
      expect(quorumRule?.details).toMatchObject({
        required_approvals: 2,
        current_approvals: 2,
        approvers: ["auditor-agent-alpha", "auditor-agent-beta"],
      });
    });

    it("blocks inline approvals if proposing agent attempted self-approval", async () => {
      const actionHash = await computeActionHash(sampleAction);
      const req: VerificationRequest = {
        agent: { id: "agent-1", owner: "corp" },
        principal: { id: "corp" },
        action: sampleAction,
        authority: {
          allowed_actions: ["transfer_funds"],
          constraints: {
            allowed_sensitive_actions: ["transfer_funds"],
            quorum: { min_approvals: 2 },
          },
        },
        context: {
          request_id: "req-1",
          timestamp: new Date().toISOString(),
          source: "rest",
          approvals: [
            {
              approver_id: "agent-1", // Self-approval!
              action_hash: actionHash,
              timestamp: new Date().toISOString(),
              decision: "APPROVE",
            },
            {
              approver_id: "auditor-2",
              action_hash: actionHash,
              timestamp: new Date().toISOString(),
              decision: "APPROVE",
            },
          ],
        },
      };

      const res = await verifyAction(req);
      expect(res.decision).toBe("BLOCK");
      expect(res.reason_codes).toContain("SELF_APPROVAL_DISALLOWED");
    });
  });

  describe("HTTP Transport Endpoints", () => {
    const sampleAction = {
      type: "modify_permissions",
      target: "iam_service",
      parameters: { role: "admin", grant_to: "devops-agent" },
      is_reversible: true,
    };

    it("handles full quorum workflow over HTTP with KV: propose -> approve -> verify", async () => {
      const kv = makeKvMock();
      const options = {
        apiKey: TEST_API_KEY,
        circuitBreakerKv: kv,
      };

      // 1. Propose quorum
      const proposeReq = makeRequest("POST", "/v1/quorum/propose", {
        proposer: { id: "initiating-agent", owner: "corp" },
        action: sampleAction,
        constraints: { min_approvals: 1 },
      });
      const proposeRes = await handleHttpRequest(proposeReq, options);
      expect(proposeRes.status).toBe(201);
      const proposal = (await proposeRes.json()) as { proposal_id: string; status: string; action_hash: string };
      expect(proposal.proposal_id).toMatch(/^prp_/);
      expect(proposal.status).toBe("PENDING");

      // 2. Before approval, verifyAction blocks
      const verifyBeforeReq = makeRequest("POST", "/v1/verify", {
        agent: { id: "initiating-agent", owner: "corp" },
        principal: { id: "corp" },
        action: sampleAction,
        authority: {
          allowed_actions: ["modify_permissions"],
          constraints: {
            allowed_sensitive_actions: ["modify_permissions"],
            quorum: { min_approvals: 1 },
          },
        },
        context: {
          request_id: "req-kv-1",
          proposal_id: proposal.proposal_id,
          timestamp: new Date().toISOString(),
          source: "rest",
        },
      });
      const verifyBeforeRes = await handleHttpRequest(verifyBeforeReq, options);
      const verifyBeforeJson = (await verifyBeforeRes.json()) as { decision: string; reason_codes: string[] };
      expect(verifyBeforeJson.decision).toBe("BLOCK");
      expect(verifyBeforeJson.reason_codes).toContain("QUORUM_NOT_MET");

      // 3. Auditor approves proposal
      const approveReq = makeRequest("POST", "/v1/quorum/approve", {
        proposal_id: proposal.proposal_id,
        approval: {
          approver_id: "security-auditor-99",
          action_hash: proposal.action_hash,
          timestamp: new Date().toISOString(),
          decision: "APPROVE",
          notes: "Approved after security posture check",
        },
      });
      const approveRes = await handleHttpRequest(approveReq, options);
      expect(approveRes.status).toBe(200);
      const approveJson = (await approveRes.json()) as { status: string };
      expect(approveJson.status).toBe("APPROVED");

      // 4. Query proposal status via GET
      const getReq = makeRequest("GET", `/v1/quorum/proposals/${proposal.proposal_id}`);
      const getRes = await handleHttpRequest(getReq, options);
      expect(getRes.status).toBe(200);
      const getJson = (await getRes.json()) as { status: string; approvals: unknown[] };
      expect(getJson.status).toBe("APPROVED");
      expect(getJson.approvals).toHaveLength(1);

      // 5. Verify action again -> passes now!
      const verifyAfterReq = makeRequest("POST", "/v1/verify", {
        agent: { id: "initiating-agent", owner: "corp" },
        principal: { id: "corp" },
        action: sampleAction,
        authority: {
          allowed_actions: ["modify_permissions"],
          constraints: {
            allowed_sensitive_actions: ["modify_permissions"],
            quorum: { min_approvals: 1 },
          },
        },
        context: {
          request_id: "req-kv-2",
          proposal_id: proposal.proposal_id,
          timestamp: new Date().toISOString(),
          source: "rest",
        },
      });
      const verifyAfterRes = await handleHttpRequest(verifyAfterReq, options);
      const verifyAfterJson = (await verifyAfterRes.json()) as { decision: string; reason_codes: string[]; receipt: { id: string } };
      expect(verifyAfterJson.decision).toBe("ALLOW");
      expect(verifyAfterJson.reason_codes).toHaveLength(0);
      expect(verifyAfterJson.receipt.id).toMatch(/^vrf_/);
    });

    it("returns 404 for unknown proposal ID", async () => {
      const getReq = makeRequest("GET", "/v1/quorum/proposals/prp_unknown-12345");
      const getRes = await handleHttpRequest(getReq, {
        apiKey: TEST_API_KEY,
        circuitBreakerKv: makeKvMock(),
      });
      expect(getRes.status).toBe(404);
    });

    it("returns 405 for invalid HTTP method", async () => {
      const wrongMethodReq = makeRequest("DELETE", "/v1/quorum/propose");
      const wrongMethodRes = await handleHttpRequest(wrongMethodReq, {
        apiKey: TEST_API_KEY,
      });
      expect(wrongMethodRes.status).toBe(405);
      expect(wrongMethodRes.headers.get("Allow")).toBe("POST");
    });
  });
});
