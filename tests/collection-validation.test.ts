import { describe, expect, it } from "vitest";

import { verificationResponseContractSchema } from "../src/transport/contracts";

describe("bounded response collection validation", () => {
  it.each([
    { name: "reason codes", schema: verificationResponseContractSchema.shape.reason_codes },
    { name: "policy results", schema: verificationResponseContractSchema.shape.policy_results },
  ])("rejects oversized $name before reading invalid elements", ({ schema }) => {
    let reads = 0;
    const values: unknown[] = Array.from({ length: 101 }, () => null);
    Object.defineProperty(values, 0, {
      get() { reads += 1; return null; },
    });

    const result = schema.safeParse(values);

    expect(result.success).toBe(false);
    expect(reads).toBe(0);
    if (!result.success) {
      expect(result.error.issues).toHaveLength(1);
      expect(result.error.issues[0]?.code).toBe("too_big");
    }
  });

  it("keeps valid boundary values and rejects invalid values within the limit", () => {
    const schema = verificationResponseContractSchema.shape.reason_codes;
    expect(schema.safeParse(Array.from({ length: 100 }, () => "review_required")).success).toBe(true);
    expect(schema.safeParse([""]).success).toBe(false);
    expect(schema.safeParse([null]).success).toBe(false);
  });
});
