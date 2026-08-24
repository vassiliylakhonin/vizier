import { webcrypto } from "node:crypto";

import { describe, expect, it } from "vitest";

import {
  activateActionCovenant,
  actionCovenantActivationRequestSchema,
  actionCovenantAuthorizationRequestSchema,
  actionCovenantDraftSchema,
  authorizeActionCovenant,
  hashActionCovenantDraft,
  outcomeRecordingRequestSchema,
  recordActionOutcome,
  type ActionCovenantDraft,
  type EvidenceObservation,
  type SignalObservation,
} from "../src/covenants/index";

async function createTestSigningKey(): Promise<string> {
  const keyPair = await webcrypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  );
  const privateJwk = await webcrypto.subtle.exportKey("jwk", keyPair.privateKey);
  return JSON.stringify({
    ...privateJwk,
    alg: "ES256",
    kid: "vizier-covenant-test-key",
    use: "sig",
  });
}

const NOW = new Date("2026-08-24T08:00:00.000Z");
const ISSUER = "https://vizier.example";

function draft(overrides: Partial<ActionCovenantDraft> = {}): ActionCovenantDraft {
  return actionCovenantDraftSchema.parse({
    schema_version: "0.2",
    drafted_by: {
      kind: "MODEL",
      identifier: "semantic-compiler-test",
    },
    drafted_at: "2026-08-24T07:59:00.000Z",
    principal: { id: "vassiliy-lakhonin" },
    agent: { id: "vizier-gated-deploy", owner: "vassiliy-lakhonin" },
    intent: "Deploy exactly the reviewed Vizier commit.",
    action: {
      type: "deploy_worker",
      target: "worker:vizier",
      parameters: {
        git_commit: "530871e",
        dirty_worktree: false,
      },
    },
    authority: {
      allowed_actions: ["deploy_worker"],
      constraints: {
        allowed_targets: ["worker:vizier"],
        allowed_sensitive_actions: ["deploy_worker"],
      },
    },
    evidence_requirements: [
      {
        id: "source-tree",
        evidence_type: "git_worktree_snapshot",
        description: "Hash of the commit and worktree state used for deployment.",
        max_age_seconds: 120,
      },
    ],
    invalidation_rules: [
      {
        id: "worktree-became-dirty",
        signal_type: "git_worktree_status",
        match: { dirty: true },
        reason: "The source tree changed after the covenant was drafted.",
      },
    ],
    forbidden_outcomes: [
      {
        id: "forbid-production-delete",
        effect_type: "delete_worker",
        target: "worker:vizier",
        reason: "A deployment must not delete the Worker.",
      },
    ],
    expires_at: "2026-08-24T08:10:00.000Z",
    ...overrides,
  });
}

async function activate(
  covenantDraft = draft(),
): Promise<Awaited<ReturnType<typeof activateActionCovenant>>> {
  const request = actionCovenantActivationRequestSchema.parse({
    draft: covenantDraft,
    acceptance: {
      accepted_by: { id: covenantDraft.principal.id },
      accepted_at: NOW.toISOString(),
      draft_hash: await hashActionCovenantDraft(covenantDraft),
    },
  });
  return activateActionCovenant(request, {
    now: () => NOW,
    createId: () => "acv_test",
  });
}

function freshEvidence(): readonly EvidenceObservation[] {
  return [
    {
      requirement_id: "source-tree",
      evidence_type: "git_worktree_snapshot",
      source: "local-git",
      observed_at: "2026-08-24T07:59:30.000Z",
      content_hash: "a".repeat(64),
    },
  ];
}

function signals(dirty = false): readonly SignalObservation[] {
  return [
    {
      signal_type: "git_worktree_status",
      source: "local-git",
      observed_at: "2026-08-24T07:59:30.000Z",
      attributes: { dirty },
    },
  ];
}

describe("Action Covenant lifecycle", () => {
  it("does not let a model draft activate itself or change after acceptance", async () => {
    const covenantDraft = draft();
    const draftHash = await hashActionCovenantDraft(covenantDraft);

    await expect(
      activateActionCovenant(
        actionCovenantActivationRequestSchema.parse({
          draft: covenantDraft,
          acceptance: {
            accepted_by: { id: "semantic-compiler-test" },
            accepted_at: NOW.toISOString(),
            draft_hash: draftHash,
          },
        }),
        { now: () => NOW },
      ),
    ).rejects.toMatchObject({ code: "ACCEPTANCE_PRINCIPAL_MISMATCH" });

    const changedDraft = draft({ intent: "Deploy any convenient commit." });
    await expect(
      activateActionCovenant(
        actionCovenantActivationRequestSchema.parse({
          draft: changedDraft,
          acceptance: {
            accepted_by: changedDraft.principal,
            accepted_at: NOW.toISOString(),
            draft_hash: draftHash,
          },
        }),
        { now: () => NOW },
      ),
    ).rejects.toMatchObject({ code: "DRAFT_HASH_MISMATCH" });
  });

  it("allows an exact action with fresh evidence and produces a verifiable signed receipt", async () => {
    const signingKey = await createTestSigningKey();
    const covenant = await activate();
    const request = actionCovenantAuthorizationRequestSchema.parse({
      covenant,
      action: covenant.draft.action,
      evidence: freshEvidence(),
      signals: signals(),
      context: {
        request_id: "authorize-01",
        timestamp: NOW.toISOString(),
        source: "internal",
      },
    });

    const response = await authorizeActionCovenant(request, {
      signingKey,
      issuer: ISSUER,
      trustedAuthority: true,
      now: () => NOW,
      createId: () => "azr_test",
    });

    expect(response).toMatchObject({
      decision: "ALLOW",
      reason_codes: [],
      authorization_receipt: {
        payload: {
          id: "azr_test",
          issuer: ISSUER,
          covenant_id: "acv_test",
          covenant_hash: covenant.covenant_hash,
          decision: "ALLOW",
        },
      },
    });
    expect(response.authorization_receipt.token.split(".")).toHaveLength(3);
  });

  it("defaults to REVIEW when authority provenance is not explicitly trusted", async () => {
    const signingKey = await createTestSigningKey();
    const covenant = await activate();
    const request = actionCovenantAuthorizationRequestSchema.parse({
      covenant,
      action: covenant.draft.action,
      evidence: freshEvidence(),
      signals: signals(),
      context: {
        request_id: "authorize-untrusted",
        timestamp: NOW.toISOString(),
        source: "internal",
      },
    });

    const response = await authorizeActionCovenant(request, {
      signingKey,
      issuer: ISSUER,
      now: () => NOW,
    });

    expect(response.decision).toBe("REVIEW");
    expect(response.reason_codes).toContain("AUTHORITY_SOURCE_UNTRUSTED");
  });

  it.each([
    ["missing", [], "EVIDENCE_MISSING"],
    [
      "stale",
      [
        {
          requirement_id: "source-tree",
          evidence_type: "git_worktree_snapshot",
          source: "local-git",
          observed_at: "2026-08-24T07:00:00.000Z",
          content_hash: "a".repeat(64),
        },
      ],
      "EVIDENCE_STALE",
    ],
  ] as const)("requires review for %s evidence", async (_name, evidence, reason) => {
    const signingKey = await createTestSigningKey();
    const covenant = await activate();
    const request = actionCovenantAuthorizationRequestSchema.parse({
      covenant,
      action: covenant.draft.action,
      evidence,
      signals: signals(),
      context: {
        request_id: null,
        timestamp: NOW.toISOString(),
        source: "internal",
      },
    });

    const response = await authorizeActionCovenant(request, {
      signingKey,
      issuer: ISSUER,
      trustedAuthority: true,
      now: () => NOW,
    });

    expect(response.decision).toBe("REVIEW");
    expect(response.reason_codes).toContain(reason);
  });

  it("blocks an action change, covenant expiry, and matching invalidation signal", async () => {
    const signingKey = await createTestSigningKey();
    const covenant = await activate();
    const cases = [
      {
        action: { ...covenant.draft.action, target: "worker:other" },
        evidence: freshEvidence(),
        signals: signals(),
        now: NOW,
        reason: "ACTION_COVENANT_MISMATCH",
      },
      {
        action: covenant.draft.action,
        evidence: freshEvidence(),
        signals: signals(),
        now: new Date("2026-08-24T08:11:00.000Z"),
        reason: "COVENANT_EXPIRED",
      },
      {
        action: covenant.draft.action,
        evidence: freshEvidence(),
        signals: signals(true),
        now: NOW,
        reason: "COVENANT_INVALIDATED",
      },
    ] as const;

    for (const item of cases) {
      const request = actionCovenantAuthorizationRequestSchema.parse({
        covenant,
        action: item.action,
        evidence: item.evidence,
        signals: item.signals,
        context: {
          request_id: null,
          timestamp: item.now.toISOString(),
          source: "internal",
        },
      });
      const response = await authorizeActionCovenant(request, {
        signingKey,
        issuer: ISSUER,
        trustedAuthority: true,
        now: () => item.now,
      });

      expect(response.decision).toBe("BLOCK");
      expect(response.reason_codes).toContain(item.reason);
    }
  });

  it("blocks a covenant envelope changed after activation", async () => {
    const signingKey = await createTestSigningKey();
    const covenant = await activate();
    const changedCovenant = {
      ...covenant,
      activated_at: "2026-08-24T07:59:59.000Z",
    };
    const response = await authorizeActionCovenant(
      actionCovenantAuthorizationRequestSchema.parse({
        covenant: changedCovenant,
        action: covenant.draft.action,
        evidence: freshEvidence(),
        signals: signals(),
        context: {
          request_id: null,
          timestamp: NOW.toISOString(),
          source: "internal",
        },
      }),
      {
        signingKey,
        issuer: ISSUER,
        trustedAuthority: true,
        now: () => NOW,
      },
    );

    expect(response.decision).toBe("BLOCK");
    expect(response.reason_codes).toContain("COVENANT_INTEGRITY_INVALID");
  });

  it("rejects a tampered authorization receipt and binds the signed outcome", async () => {
    const signingKey = await createTestSigningKey();
    const covenant = await activate();
    const authorizationRequest = actionCovenantAuthorizationRequestSchema.parse({
      covenant,
      action: covenant.draft.action,
      evidence: freshEvidence(),
      signals: signals(),
      context: {
        request_id: "authorize-outcome",
        timestamp: NOW.toISOString(),
        source: "internal",
      },
    });
    const authorization = await authorizeActionCovenant(authorizationRequest, {
      signingKey,
      issuer: ISSUER,
      trustedAuthority: true,
      now: () => NOW,
      createId: () => "azr_outcome",
    });

    const tampered = structuredClone(authorization.authorization_receipt);
    tampered.payload.action_hash = "f".repeat(64);
    await expect(
      recordActionOutcome(
        outcomeRecordingRequestSchema.parse({
          covenant,
          authorization_receipt: tampered,
          outcome: {
            status: "FAILED",
            started_at: "2026-08-24T08:00:01.000Z",
            finished_at: "2026-08-24T08:00:02.000Z",
            effects: [],
            external_reference: null,
          },
        }),
        {
          signingKey,
          issuer: ISSUER,
          now: () => new Date("2026-08-24T08:00:03.000Z"),
        },
      ),
    ).rejects.toMatchObject({ code: "AUTHORIZATION_RECEIPT_INVALID" });

    const outcomeRequest = outcomeRecordingRequestSchema.parse({
      covenant,
      authorization_receipt: authorization.authorization_receipt,
      outcome: {
        status: "SUCCEEDED",
        started_at: "2026-08-24T08:00:01.000Z",
        finished_at: "2026-08-24T08:00:15.000Z",
        effects: [
          {
            type: "deploy_worker",
            target: "worker:vizier",
            parameters: { git_commit: "530871e" },
          },
        ],
        external_reference: "cloudflare-deployment-test",
      },
    });
    const receipt = await recordActionOutcome(outcomeRequest, {
      signingKey,
      issuer: ISSUER,
      now: () => new Date("2026-08-24T08:00:16.000Z"),
      createId: () => "out_test",
    });

    expect(receipt.payload).toMatchObject({
      id: "out_test",
      authorization_receipt_id: "azr_outcome",
      covenant_id: "acv_test",
      compliance: "COMPLIANT",
      violation_codes: [],
    });
  });

  it("records forbidden effects as a signed violation rather than hiding them", async () => {
    const signingKey = await createTestSigningKey();
    const covenant = await activate();
    const authorization = await authorizeActionCovenant(
      actionCovenantAuthorizationRequestSchema.parse({
        covenant,
        action: covenant.draft.action,
        evidence: freshEvidence(),
        signals: signals(),
        context: {
          request_id: "authorize-forbidden-outcome",
          timestamp: NOW.toISOString(),
          source: "internal",
        },
      }),
      {
        signingKey,
        issuer: ISSUER,
        trustedAuthority: true,
        now: () => NOW,
      },
    );
    const request = outcomeRecordingRequestSchema.parse({
      covenant,
      authorization_receipt: authorization.authorization_receipt,
      outcome: {
        status: "SUCCEEDED",
        started_at: "2026-08-24T08:00:01.000Z",
        finished_at: "2026-08-24T08:00:02.000Z",
        effects: [
          {
            type: "delete_worker",
            target: "worker:vizier",
            parameters: {},
          },
        ],
        external_reference: null,
      },
    });

    const receipt = await recordActionOutcome(request, {
      signingKey,
      issuer: ISSUER,
      now: () => new Date("2026-08-24T08:00:03.000Z"),
    });

    expect(receipt.payload.compliance).toBe("VIOLATION");
    expect(receipt.payload.violation_codes).toEqual([
      "FORBIDDEN_OUTCOME:forbid-production-delete",
    ]);
  });

  it("rejects execution that starts after the signed authorization window", async () => {
    const signingKey = await createTestSigningKey();
    const covenant = await activate();
    const authorization = await authorizeActionCovenant(
      actionCovenantAuthorizationRequestSchema.parse({
        covenant,
        action: covenant.draft.action,
        evidence: freshEvidence(),
        signals: signals(),
        context: {
          request_id: "authorize-expired-window",
          timestamp: NOW.toISOString(),
          source: "internal",
        },
      }),
      {
        signingKey,
        issuer: ISSUER,
        trustedAuthority: true,
        now: () => NOW,
      },
    );

    await expect(
      recordActionOutcome(
        outcomeRecordingRequestSchema.parse({
          covenant,
          authorization_receipt: authorization.authorization_receipt,
          outcome: {
            status: "FAILED",
            started_at: "2026-08-24T08:05:01.000Z",
            finished_at: "2026-08-24T08:05:02.000Z",
            effects: [],
            external_reference: null,
          },
        }),
        {
          signingKey,
          issuer: ISSUER,
          now: () => new Date("2026-08-24T08:05:03.000Z"),
        },
      ),
    ).rejects.toMatchObject({
      code: "AUTHORIZATION_EXPIRED_BEFORE_EXECUTION",
    });
  });
});
