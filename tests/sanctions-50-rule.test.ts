import { describe, expect, it } from "vitest";
import {
  evaluateSanctions50Rule,
  evaluateSanctions,
  verifyAction,
  type EntityOwnershipGraph,
  type VerificationRequest,
} from "../src/core/index";
import { handleHttpRequest } from "../src/transport/http";

describe("OFAC 50% Rule & Aggregate Ownership Graph Engine", () => {
  it("detects direct SDN match on target entity itself", async () => {
    const graph: EntityOwnershipGraph = {
      entity_name: "Garantex Europe",
      shareholders: [
        { name: "Clean Investor LLC", percentage: 100.0 },
      ],
    };

    const result = await evaluateSanctions50Rule(graph);
    expect(result.clean).toBe(false);
    expect(result.violation).toBe(true);
    expect(result.reason_codes).toContain("SANCTIONED_ENTITY_MATCH");
    expect(result.aggregate_blocked_percentage).toBe(100.0);
    expect(result.direct_match).toBeDefined();
  });

  it("blocks entity with single SDN shareholder >= 50%", async () => {
    const graph: EntityOwnershipGraph = {
      entity_name: "Central Asia Logistics LLP",
      shareholders: [
        { name: "Garantex Europe", percentage: 51.0 },
        { name: "Kazakh Partner Ltd", percentage: 49.0 },
      ],
    };

    const result = await evaluateSanctions50Rule(graph);
    expect(result.clean).toBe(false);
    expect(result.violation).toBe(true);
    expect(result.reason_codes).toContain("SANCTIONS_50_RULE_VIOLATION");
    expect(result.aggregate_blocked_percentage).toBe(51.0);
    expect(result.blocked_shareholders.length).toBe(1);
    expect(result.blocked_shareholders[0]!.name).toBe("Garantex Europe");
  });

  it("blocks entity when multiple SDN shareholders aggregate to >= 50%", async () => {
    const graph: EntityOwnershipGraph = {
      entity_name: "Caspian Trade Consortium",
      shareholders: [
        { name: "Garantex Europe", percentage: 30.0 },
        { name: "Tornado Cash", percentage: 25.0 },
        { name: "Independent Trader LLC", percentage: 45.0 },
      ],
    };

    const result = await evaluateSanctions50Rule(graph);
    expect(result.clean).toBe(false);
    expect(result.violation).toBe(true);
    expect(result.reason_codes).toContain("SANCTIONS_50_RULE_VIOLATION");
    expect(result.aggregate_blocked_percentage).toBe(55.0);
    expect(result.blocked_shareholders.length).toBe(2);
  });

  it("passes entity when aggregate SDN ownership is < 50%", async () => {
    const graph: EntityOwnershipGraph = {
      entity_name: "Baku Energy Services",
      shareholders: [
        { name: "Garantex Europe", percentage: 20.0 },
        { name: "Tornado Cash", percentage: 20.0 },
        { name: "Global Clean Energy AG", percentage: 60.0 },
      ],
    };

    const result = await evaluateSanctions50Rule(graph);
    expect(result.clean).toBe(true);
    expect(result.violation).toBe(false);
    expect(result.aggregate_blocked_percentage).toBe(40.0);
    expect(result.reason_codes).toHaveLength(0);
  });

  it("blocks multi-tier holding structure where parent is deemed blocked", async () => {
    const graph: EntityOwnershipGraph = {
      entity_name: "Subsidiary Operating Co",
      shareholders: [
        {
          name: "Holding Parent NV",
          percentage: 70.0,
          shareholders: [
            { name: "Garantex Europe", percentage: 55.0 },
            { name: "Other Shareholder", percentage: 45.0 },
          ],
        },
        { name: "Minority Founder", percentage: 30.0 },
      ],
    };

    const result = await evaluateSanctions50Rule(graph);
    expect(result.clean).toBe(false);
    expect(result.violation).toBe(true);
    expect(result.reason_codes).toContain("SANCTIONS_50_RULE_VIOLATION");
    expect(result.aggregate_blocked_percentage).toBe(70.0);
  });

  it("handles circular ownership without infinite loop", async () => {
    const graph: EntityOwnershipGraph = {
      entity_name: "Entity Alpha",
      shareholders: [
        {
          name: "Entity Beta",
          percentage: 40.0,
          shareholders: [
            { name: "Entity Alpha", percentage: 50.0 },
          ],
        },
        { name: "Clean Partner", percentage: 60.0 },
      ],
    };

    const result = await evaluateSanctions50Rule(graph);
    expect(result.clean).toBe(true);
    expect(result.violation).toBe(false);
  });

  it("respects custom threshold percentage", async () => {
    const graph: EntityOwnershipGraph = {
      entity_name: "Strict Compliance Target",
      threshold_percentage: 25.0,
      shareholders: [
        { name: "Garantex Europe", percentage: 26.0 },
        { name: "Clean Partner", percentage: 74.0 },
      ],
    };

    const result = await evaluateSanctions50Rule(graph);
    expect(result.clean).toBe(false);
    expect(result.violation).toBe(true);
    expect(result.reason_codes).toContain("SANCTIONS_50_RULE_VIOLATION");
    expect(result.aggregate_blocked_percentage).toBe(26.0);
  });
});

describe("Sanctions 50% Rule via Core Verification & HTTP API", () => {
  it("blocks verification request containing blocked shareholders parameter", async () => {
    const request: VerificationRequest = {
      agent: { id: "procurement-agent", owner: "procurement-dept" },
      principal: { id: "corp-cfo" },
      action: {
        type: "fund_transfer",
        target: "Caspian Trade LLP",
        parameters: {
          counterparty: "Caspian Trade LLP",
          shareholders: [
            { name: "Garantex Europe", percentage: 35.0 },
            { name: "Tornado Cash", percentage: 20.0 },
          ],
        },
      },
      authority: {
        allowed_actions: ["fund_transfer"],
        constraints: {
          sanctions_screening: true,
        },
      },
      context: {
        request_id: "req_test_50",
        timestamp: new Date().toISOString(),
        source: "rest",
      },
    };

    const sanctionsRes = await evaluateSanctions(request);
    expect(sanctionsRes.clean).toBe(false);
    expect(sanctionsRes.rule50_result?.violation).toBe(true);
    expect(sanctionsRes.rule50_result?.aggregate_blocked_percentage).toBe(55.0);

    const verification = await verifyAction(request, {
      sanctions: sanctionsRes,
      trustedAuthority: true,
    });

    expect(verification.decision).toBe("BLOCK");
    expect(verification.reason_codes).toContain("SANCTIONS_50_RULE_VIOLATION");
  });

  it("handles POST /v1/sanctions/screen-entity HTTP endpoint", async () => {
    const body = JSON.stringify({
      entity_name: "Silk Road Trading Ltd",
      shareholders: [
        { name: "Garantex Europe", percentage: 30.0 },
        { name: "Tornado Cash", percentage: 25.0 },
        { name: "Local Entrepreneur", percentage: 45.0 },
      ],
    });

    const res = await handleHttpRequest(
      new Request("https://vizier.local/v1/sanctions/screen-entity", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Vizier-Key": "test-secret",
        },
        body,
      }),
      { apiKey: "test-secret" },
    );

    expect(res.status).toBe(200);
    const data = await res.json() as {
      clean: boolean;
      violation: boolean;
      aggregate_blocked_percentage: number;
      reason_codes: string[];
    };
    expect(data.clean).toBe(false);
    expect(data.violation).toBe(true);
    expect(data.aggregate_blocked_percentage).toBe(55.0);
    expect(data.reason_codes).toContain("SANCTIONS_50_RULE_VIOLATION");
  });
});
