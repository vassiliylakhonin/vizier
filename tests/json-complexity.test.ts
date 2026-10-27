import { describe, expect, it } from "vitest";

import { assertJsonComplexity, JsonComplexityError } from "../src/core/json-complexity";
import { canonicalize } from "../src/core/receipts";

describe("JSON complexity before canonical hashing", () => {
  it("accepts shared acyclic values with the same canonical bytes as expanded JSON", () => {
    const shared = { amount: 7, labels: ["review"] };
    const value = { b: shared, a: shared };
    const expanded: unknown = JSON.parse(JSON.stringify(value));
    expect(canonicalize(value)).toBe(canonicalize(expanded));
    expect(canonicalize(value)).toBe('{"a":{"amount":7,"labels":["review"]},"b":{"amount":7,"labels":["review"]}}');
  });

  it("rejects direct and indirect cycles", () => {
    const direct: Record<string, unknown> = {};
    direct.self = direct;
    const indirect: Record<string, unknown> = {};
    indirect.child = [indirect];
    for (const value of [direct, indirect]) {
      expect(() => canonicalize(value)).toThrowError(expect.objectContaining({ reason: "cycle" }));
    }
  });

  it("counts every serialized occurrence of an alias against the node budget", () => {
    const shared = { amount: 7 };
    const value = [shared, shared]; // array + two objects + two numbers = five nodes
    expect(() => assertJsonComplexity(value, { maxNodes: 5 })).not.toThrow();
    expect(() => assertJsonComplexity(value, { maxNodes: 4 }))
      .toThrowError(expect.objectContaining({ reason: "nodes" }));
  });

  it("retains the depth limit even when values are shared", () => {
    const shared = { amount: 7 };
    expect(() => assertJsonComplexity({ shallow: shared, deep: { child: shared } }, { maxDepth: 2 }))
      .toThrowError(expect.objectContaining({ reason: "depth" }));
  });

  it("rejects exponential alias expansion before building a canonical string", () => {
    let value: unknown = { amount: 7 };
    for (let i = 0; i < 20; i += 1) value = [value, value];
    expect(() => canonicalize(value)).toThrowError(expect.objectContaining({ reason: "nodes" }));
  });

  it("keeps non-JSON primitives invalid", () => {
    expect(() => canonicalize({ amount: 7n })).toThrow(TypeError);
    expect(() => assertJsonComplexity([1, 2], { maxNodes: 1 })).toThrow(JsonComplexityError);
  });
});
