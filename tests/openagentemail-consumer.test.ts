import { createHash } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
import { DatabaseSync, type SQLInputValue } from "node:sqlite";
import type { D1Database } from "@cloudflare/workers-types";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Vizier, type HumanReviewRequest, type JsonValue } from "../packages/sdk/src/index";
import { canonicalizeJson } from "../src/crypto/jws";
import { handleHttpRequest } from "../src/transport/http";
import type { TransportOptions } from "../src/transport/shared";

type ToolAction = {
  type: string;
  name: string;
  arguments: { a: { x: number; y: number }; z: JsonValue[] };
};

const { vector } = JSON.parse(readFileSync(
  new URL("./fixtures/openagentemail-nested-order-v1.json", import.meta.url), "utf8",
)) as { vector: {
  source: ToolAction;
  equivalentSource: ToolAction;
  canonicalUtf8Json: string;
  sha256: string;
  mutations: { path: string; value: number; sha256: string }[];
} };
const mutation = vector.mutations[0]!;
const changedAction = structuredClone(vector.source);
changedAction.arguments.a.x = mutation.value;
const digest = (action: ToolAction) => createHash("sha256")
  .update(canonicalizeJson(action), "utf8").digest("hex");

let db: DatabaseSync;
let options: TransportOptions;
let client: Vizier;
let consumeRequests: number;

function localDatabase(): D1Database {
  db = new DatabaseSync(":memory:");
  db.exec("PRAGMA foreign_keys=ON");
  const directory = new URL("../migrations/", import.meta.url);
  for (const file of readdirSync(directory).filter(name => name.endsWith(".sql")).sort()) {
    db.exec(readFileSync(new URL(file, directory), "utf8"));
  }
  function prepare(query: string, values: SQLInputValue[] = []) {
    return {
      bind(...args: SQLInputValue[]) { return prepare(query, args); },
      async first() { return db.prepare(query).get(...values) ?? null; },
      async all() { return { results: db.prepare(query).all(...values), success: true }; },
      async run() { return { success: true, meta: { changes: Number(db.prepare(query).run(...values).changes) } }; },
    };
  }
  return { prepare } as unknown as D1Database;
}

function reviewRequest(action: ToolAction): HumanReviewRequest {
  return {
    audience: "openagentemail-vector-consumer",
    action,
    evidence: { digest_recipe: "openagentemail.v1", action_sha256: vector.sha256 },
    escalation_reason: "Synthetic exact-action interoperability fixture",
    expires_in_seconds: 60,
  };
}

beforeEach(async () => {
  vi.spyOn(console, "log").mockImplementation(() => undefined);
  const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  options = {
    apiKey: "synthetic-integration", reviewerApiKey: "synthetic-reviewer", db: localDatabase(),
    receiptSigningKey: JSON.stringify({
      ...await crypto.subtle.exportKey("jwk", pair.privateKey), alg: "ES256", kid: "fixture-only", use: "sig",
    }),
  };
  consumeRequests = 0;
  client = new Vizier({
    baseUrl: "https://vizier.test", apiKey: "synthetic-integration",
    fetch: async (input, init) => {
      const request = new Request(input, init);
      if (new URL(request.url).pathname.endsWith("/consume")) consumeRequests += 1;
      return handleHttpRequest(request, options);
    },
  });
});

afterEach(() => { db.close(); vi.restoreAllMocks(); });

describe("OpenAgentEmail nested-order-v1 consumer fixture", () => {
  it("reproduces the published canonical bytes, equivalent order and mutation digest", () => {
    expect(mutation.path).toBe("/arguments/a/x");
    expect(canonicalizeJson(vector.source)).toBe(vector.canonicalUtf8Json);
    expect(digest(vector.source)).toBe(vector.sha256);
    expect(digest(vector.equivalentSource)).toBe(vector.sha256);
    expect(digest(changedAction)).toBe(mutation.sha256);
    expect(mutation.sha256).not.toBe(vector.sha256);
  });

  it("stops changed arguments before execution, accepts reordered keys once and rejects replay", async () => {
    const request = reviewRequest(vector.source);
    const submitted = await client.submitHumanReview(request);
    const decision = await handleHttpRequest(new Request(
      `https://vizier.test/v1/reviews/${submitted.id}/decision`, {
        method: "POST",
        headers: { Authorization: "Bearer synthetic-reviewer", "Content-Type": "application/json" },
        body: JSON.stringify({
          request_hash: submitted.request_hash, decision: "APPROVED", reason: "Synthetic reviewer decision",
        }),
      },
    ), options);
    expect(decision.status).toBe(200);
    const approved = await decision.json() as { token: string };
    const execute = vi.fn(async (action: ToolAction) => ({ status: "mock_executed", action }));
    const invoke = async (action: ToolAction) => {
      const snapshot = structuredClone(action);
      await client.claimHumanReview(reviewRequest(snapshot), submitted.id, approved.token);
      return execute(snapshot);
    };

    await expect(invoke(changedAction)).rejects.toMatchObject({ code: "INVALID_ATTESTATION" });
    expect(execute).not.toHaveBeenCalled();
    expect(consumeRequests).toBe(0);
    expect(db.prepare("SELECT status FROM human_reviews WHERE id=?").get(submitted.id)!.status).toBe("APPROVED");

    await expect(invoke(vector.equivalentSource)).resolves.toEqual({ status: "mock_executed", action: vector.source });
    expect(execute).toHaveBeenCalledExactlyOnceWith(vector.equivalentSource);
    expect(consumeRequests).toBe(1);
    expect(db.prepare("SELECT status FROM human_reviews WHERE id=?").get(submitted.id)!.status).toBe("CONSUMED");

    await expect(invoke(vector.source)).rejects.toThrow("already claimed");
    expect(execute).toHaveBeenCalledTimes(1);
  });
});
