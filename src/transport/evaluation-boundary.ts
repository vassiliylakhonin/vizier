/** Anonymous evaluation is never an execution authorization. Fail closed if a future policy regresses. */
export function assertEvaluationCannotAllow(decision: string): void {
  if (decision === "ALLOW") throw new Error("Anonymous evaluation cannot grant ALLOW.");
}

export const EVALUATION_METADATA = Object.freeze({
  evaluation_only: true,
  allow_impossible: true,
});

export const EVALUATION_HEADERS = Object.freeze({
  "X-Vizier-Evaluation-Only": "true",
  "X-Vizier-Allow-Impossible": "true",
});
