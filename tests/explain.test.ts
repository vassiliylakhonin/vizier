import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

import { explainDecision, formatExplanation, listExplainableCodes } from "../packages/mcp-proxy/src/explain";

describe("vizier explain", () => {
  it("explains failing policy results with details and skips passing ones", () => {
    const report = explainDecision({
      decision: "BLOCK",
      reason_codes: ["AUTHORITY_LIMIT_EXCEEDED"],
      policy_results: [
        { rule_id: "authority.action.allowed", result: "PASS", reason_code: null, details: {} },
        { rule_id: "authority.amount.within_limit", result: "FAIL", reason_code: "AUTHORITY_LIMIT_EXCEEDED", details: { amount: 900, max_amount: 500, nested: { a: 1 } } },
      ],
    });
    expect(report.decision).toBe("BLOCK");
    expect(report.findings).toHaveLength(1);
    expect(report.findings[0]).toMatchObject({ code: "AUTHORITY_LIMIT_EXCEEDED", rule_id: "authority.amount.within_limit", who_can_fix: "owner", details: { amount: 900, max_amount: 500 } });
    expect(report.findings[0]!.details).not.toHaveProperty("nested");
    expect(formatExplanation(report)).toContain("max_amount");
  });

  it("accepts bare codes, resolves prefixed codes and lists unknown ones without guessing", () => {
    const report = explainDecision(["CIRCUIT_TRIPPED:LOOP_DETECTED", "NOT_A_REAL_CODE"]);
    expect(report.findings.map(f => f.code)).toEqual(["CIRCUIT_TRIPPED:LOOP_DETECTED"]);
    expect(report.unknown_codes).toEqual(["NOT_A_REAL_CODE"]);
  });

  it("is deterministic and never promises ALLOW", () => {
    const input = { decision: "BLOCK", reason_codes: ["GRANT_EXPIRED", "TARGET_NOT_ALLOWED"] };
    const a = JSON.stringify(explainDecision(input));
    expect(JSON.stringify(explainDecision(input))).toBe(a);
    expect(a).toContain("cannot promise");
    expect(a.toLowerCase()).not.toMatch(/guarantee/);
  });

  it("reports an empty input honestly", () => {
    expect(formatExplanation(explainDecision({ decision: "ALLOW", reason_codes: [] }))).toContain("No failing or review reason codes");
  });

  it("covers every grant failure and policy reason code in the source", () => {
    const known = new Set(listExplainableCodes());
    const sources = ["src/core/grants.ts", "src/core/policies.ts", "src/core/budget.ts"].map(f => readFileSync(f, "utf8")).join("\n");
    const emitted = new Set([...sources.matchAll(/"((?:GRANT|BUDGET|AUTHORITY|ACTION|TARGET|AMOUNT|CURRENCY|SENSITIVE|IRREVERSIBLE|PRINCIPAL)_[A-Z_]+)"/g)].map(m => m[1]!));
    const ignore = new Set(["GRANT_STATE_MAX_SECONDS", "BUDGET_CEILING", "BUDGET_EXCEEDED", "ACTION_AUTHORIZATION", "ACTION_COVENANT_MISMATCH", "ACTION_NOT_AUTHORIZED"]);
    const missing = [...emitted].filter(c => !known.has(c) && !ignore.has(c));
    expect(missing).toEqual([]);
  });
});
