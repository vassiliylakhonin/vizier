import { Vizier } from "../packages/sdk/src/index";
import { readFileSync } from "node:fs";
import { DatabaseSync, type SQLInputValue } from "node:sqlite";
import { webcrypto } from "node:crypto";
import type { D1Database } from "@cloudflare/workers-types";
import { beforeEach, afterEach, describe, expect, it, vi } from "vitest";
import { handleHttpRequest } from "../src/transport/http";
import type { TransportOptions } from "../src/transport/shared";
import { decodeCompactJws, publicJwkFromPrivate, verifyJwsSignature } from "../src/crypto/jws";

let mem: DatabaseSync;
let options: TransportOptions;
const submission = { audience: "agenda-financial-guard", action: { chain_id: 8453, amount_base_units: "1000000", type: "test-only" }, evidence: { status: "incomplete" }, escalation_reason: "Trusted sanctions data unavailable", expires_in_seconds: 60 };
function fakeD1(): D1Database {
  mem = new DatabaseSync(":memory:");
  mem.exec("PRAGMA foreign_keys=ON");
  mem.exec(readFileSync(new URL("../migrations/0006_human_reviews.sql", import.meta.url), "utf8"));
  function prepare(query: string, values: SQLInputValue[] = []) {
    return { bind(...args: SQLInputValue[]) { return prepare(query, args); },
      async first() { return mem.prepare(query).get(...values) ?? null; },
      async all() { return { results: mem.prepare(query).all(...values), success: true }; },
      async run() { const result = mem.prepare(query).run(...values); return { success: true, meta: { changes: Number(result.changes) } }; } };
  }
  return { prepare } as unknown as D1Database;
}
async function call(path: string, body?: unknown, key = "integration", origin = "https://vizier.test") {
  return handleHttpRequest(new Request(origin + path, { method: body === undefined ? "GET" : "POST", headers: { Authorization: `Bearer ${key}`, "Content-Type": "application/json" }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) }), options);
}
interface Review { id: string; request_hash: string; token: string; status: string; token_expires_at: number; }
async function create(): Promise<Review> { const response = await call("/v1/reviews", submission); expect(response.status).toBe(201); return response.json() as Promise<Review>; }
async function decide(row: Review, decision = "APPROVED", key = "reviewer") {
  return call(`/v1/reviews/${row.id}/decision`, { request_hash: row.request_hash, decision, reason: "Synthetic operator decision" }, key);
}
async function approve(): Promise<Review> { const response = await decide(await create()); expect(response.status).toBe(200); return response.json() as Promise<Review>; }
function consume(row: Review, overrides = {}) { return call(`/v1/reviews/${row.id}/consume`, { token: row.token, request_hash: row.request_hash, audience: submission.audience, ...overrides }); }

beforeEach(async () => {
  const pair = await webcrypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  options = { apiKey: "integration", reviewerApiKey: "reviewer", db: fakeD1(), receiptSigningKey: JSON.stringify({ ...await webcrypto.subtle.exportKey("jwk", pair.privateKey), alg: "ES256", kid: "review-test", use: "sig" }) };
});
afterEach(() => { vi.useRealTimers(); mem.close(); });

describe("durable human reviews", () => {
  it("separates integration and reviewer authority and denies tenant keys", async () => {
    expect((await call("/v1/reviews", submission, "reviewer")).status).toBe(403);
    expect((await call("/v1/reviews", undefined, "vz_live_tenant")).status).toBe(401);
    expect((await call("/v1/reviews", undefined, "wrong")).status).toBe(401);
    const row = await create();
    expect((await decide(row, "APPROVED", "integration")).status).toBe(403);
    const approved = await approve();
    expect((await call(`/v1/reviews/${approved.id}/consume`, { token: approved.token, request_hash: approved.request_hash, audience: submission.audience }, "reviewer")).status).toBe(403);
  });
  it.each(["reviewerApiKey", "receiptSigningKey", "db", "apiKey"] as const)("fails closed without %s", async field => {
    options = { ...options, [field]: undefined };
    expect((await call("/v1/reviews", submission)).status).toBe(503);
  });
  it("rejects identical role credentials", async () => {
    options = { ...options, reviewerApiKey: options.apiKey };
    expect((await call("/v1/reviews", submission)).status).toBe(503);
  });
  it("binds normalized exact content, not object order", async () => {
    const a = await create();
    const b: Review = await (await call("/v1/reviews", { ...submission, action: { type: "test-only", amount_base_units: "1000000", chain_id: 8453 } })).json() as Review;
    expect(a.request_hash).toBe(b.request_hash);
    const c: Review = await (await call("/v1/reviews", { ...submission, evidence: { status: "changed" } })).json() as Review;
    expect(c.request_hash).not.toBe(a.request_hash);
    expect((await decide({ ...a, request_hash: c.request_hash })).status).toBe(409);
  });
  it("produces a publicly verifiable domain-separated attestation", async () => {
    const row = await approve();
    const parts = decodeCompactJws(row.token)!;
    expect(parts.header).toMatchObject({ typ: "VIZIER-HUMAN-REVIEW+JWS", alg: "ES256" });
    expect(parts.payload).toMatchObject({ iss: "https://vizier.test", aud: submission.audience, jti: row.id, request_hash: row.request_hash, decision: "APPROVED" });
    expect(await verifyJwsSignature(parts, publicJwkFromPrivate(options.receiptSigningKey!))).toBe(true);
    expect(row.token_expires_at).toBeLessThanOrEqual(Math.floor(Date.now() / 1000) + 60);
  });
  it("allows one winner across concurrent decisions and writes one decision event", async () => {
    const row = await create();
    const results = await Promise.all([decide(row), decide(row, "REJECTED")]);
    expect(results.map(r => r.status).sort()).toEqual([200, 409]);
    expect(mem.prepare("SELECT COUNT(*) AS n FROM human_review_events").get()!.n).toBe(2);
  });
  it("allows exactly one concurrent claim, preserves trail and blocks resurrection", async () => {
    const row = await approve();
    const results = await Promise.all(Array.from({ length: 12 }, () => consume(row)));
    expect(results.filter(r => r.status === 200)).toHaveLength(1);
    expect(results.filter(r => r.status === 409)).toHaveLength(11);
    expect((await decide(row)).status).toBe(409);
    const detail = await (await call(`/v1/reviews/${row.id}`)).json() as { events: { state: string; actor: string }[] };
    expect(detail.events.map(e => [e.state, e.actor])).toEqual([["PENDING", "integration"], ["APPROVED", "reviewer"], ["CONSUMED", "integration"]]);
  });
  it("cannot consume a rejection", async () => {
    const row: Review = await (await decide(await create(), "REJECTED")).json() as Review;
    expect((await consume(row)).status).toBe(409);
  });
  it("rejects mismatched audience, hash, issuer and forged token without consuming", async () => {
    const row = await approve();
    for (const change of [{ audience: "other" }, { request_hash: "0".repeat(64) }, { token: row.token.slice(0, -5) + "aaaaa" }]) {
      expect((await consume(row, change)).status).toBe(409);
    }
    expect((await call(`/v1/reviews/${row.id}/consume`, { token: row.token, request_hash: row.request_hash, audience: submission.audience }, "integration", "https://other.test")).status).toBe(409);
    expect((await consume(row)).status).toBe(200);
  });
  it("rejects a stored token after signing key rotation", async () => {
    const row = await approve();
    const pair = await webcrypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
    options = { ...options, receiptSigningKey: JSON.stringify({ ...await webcrypto.subtle.exportKey("jwk", pair.privateKey), alg: "ES256", kid: "rotated", use: "sig" }) };
    expect((await consume(row)).status).toBe(409);
  });
  it("expires pending and approved requests without a cleanup job", async () => {
    const pending = await create(); const approved = await approve();
    vi.useFakeTimers(); vi.setSystemTime(Date.now() + 61000);
    expect((await decide(pending)).status).toBe(409);
    expect((await consume(approved)).status).toBe(409);
    const detail = await (await call(`/v1/reviews/${approved.id}`)).json() as { effective_status: string };
    expect(detail.effective_status).toBe("EXPIRED");
  });
  it("rolls back state when the mandatory audit write fails", async () => {
    const row = await create();
    mem.exec("CREATE TRIGGER reject_event BEFORE INSERT ON human_review_events BEGIN SELECT RAISE(ABORT,'audit unavailable'); END;");
    expect((await decide(row)).status).toBe(500);
    expect(mem.prepare("SELECT status FROM human_reviews WHERE id=?").get(row.id)!.status).toBe("PENDING");
  });
  it("enforces retention visibility and cascading audit deletion", async () => {
    const row = await create();
    vi.useFakeTimers(); vi.setSystemTime(Date.now() + 8 * 86400000);
    expect((await call(`/v1/reviews/${row.id}`)).status).toBe(404);
    const list = await (await call("/v1/reviews")).json() as { reviews: unknown[] };
    expect(list.reviews).toEqual([]);
    mem.prepare("DELETE FROM human_reviews WHERE id=?").run(row.id);
    expect(mem.prepare("SELECT COUNT(*) AS n FROM human_review_events").get()!.n).toBe(0);
  });
  it("rejects unbounded submissions, invalid TTL and caller supplied identities", async () => {
    expect((await call("/v1/reviews", { ...submission, evidence: { text: "x".repeat(33000) } })).status).toBe(413);
    expect((await call("/v1/reviews", { ...submission, expires_in_seconds: 3601 })).status).toBe(400);
    expect((await call("/v1/reviews", { ...submission, reviewer: "owner" })).status).toBe(400);
    expect((await call("/v1/reviews", { ...submission, action: { amount: 1e20 } })).status).toBe(400);
  });
  it("SDK verifies the local request and signature before claiming, then rejects replay", async () => {
    const client = new Vizier({ baseUrl: "https://vizier.test", apiKey: "integration", fetch: async (input, init) => handleHttpRequest(new Request(input, init), options) });
    const submitted = await client.submitHumanReview(submission);
    const row: Review = await (await decide({ ...submitted, token: "", status: "PENDING", token_expires_at: 0 })).json() as Review;
    await expect(client.claimHumanReview({ ...submission, action: { amount_base_units: "2000000" } }, row.id, row.token)).rejects.toThrow("not bound");
    await expect(client.claimHumanReview(submission, row.id, row.token.slice(0, -5) + "aaaaa")).rejects.toThrow();
    expect(await client.claimHumanReview(submission, row.id, row.token)).toMatchObject({ status: "CONSUMED", execution: "not_performed" });
    await expect(client.claimHumanReview(submission, row.id, row.token)).rejects.toThrow("already claimed");
  });
  it("serves a no-store, frame-protected console with text-only rendering", async () => {
    const response = await call("/reviews"); const html = await response.text();
    expect(response.headers.get("content-security-policy")).toContain("frame-ancestors 'none'");
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(html).not.toMatch(/innerHTML|localStorage|sessionStorage/);
    expect(html).toContain("content.textContent=JSON.stringify");
  });
});
