import type { Decision, PolicyResult } from "./types";

export function aggregateDecision(results: readonly PolicyResult[]): Decision {
  if (results.some((item) => item.result === "FAIL")) {
    return "BLOCK";
  }
  if (results.some((item) => item.result === "REVIEW")) {
    return "REVIEW";
  }
  return "ALLOW";
}

