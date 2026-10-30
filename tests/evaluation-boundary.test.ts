import { describe, expect, it } from "vitest";
import { assertEvaluationCannotAllow } from "../src/transport/evaluation-boundary";

describe("anonymous evaluation boundary", () => {
  it("fails closed if a future policy produces ALLOW", () => {
    expect(() => assertEvaluationCannotAllow("ALLOW")).toThrow();
    expect(() => assertEvaluationCannotAllow("REVIEW")).not.toThrow();
    expect(() => assertEvaluationCannotAllow("BLOCK")).not.toThrow();
  });
});
