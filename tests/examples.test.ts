import { readFile } from "node:fs/promises";

import { describe, expect, it } from "vitest";

import { verificationRequestSchema, verifyAction } from "../src/core/index";

describe("copy-paste examples", () => {
  it.each([
    ["allow.json", "ALLOW", null],
    ["block.json", "BLOCK", "AUTHORITY_LIMIT_EXCEEDED"],
    ["review.json", "REVIEW", "SENSITIVE_ACTION_REVIEW"],
  ] as const)("%s produces %s", async (filename, decision, reason) => {
    const text = await readFile(new URL(`../examples/${filename}`, import.meta.url), "utf8");
    const request = verificationRequestSchema.parse(JSON.parse(text));
    const result = await verifyAction(request);

    expect(result.decision).toBe(decision);
    if (reason !== null) {
      expect(result.reason_codes).toContain(reason);
    }
  });
});

