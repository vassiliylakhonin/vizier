import { Vizier } from "../packages/sdk/src/index";
import { readFileSync } from "node:fs";
import { DatabaseSync, type SQLInputValue } from "node:sqlite";
import { webcrypto } from "node:crypto";
import type { D1Database } from "@cloudflare/workers-types";
import { beforeEach, afterEach, describe, expect, it, vi } from "vitest";
import { handleHttpRequest } from "../src/transport/http";
import type { TransportOptions } from "../src/transport/shared";
import { FINANCIAL_AUDIENCE, USDC, verifyFinancialOutcome, type FinancialAction } from "../src/reviews/financial";
import { OFAC_SOURCE } from "../src/reviews/ofac";

let mem: DatabaseSync;
let options: TransportOptions;
const wallet = "0x" + "1".repeat(40), recipient = "0x" + "2".repeat(40);
function action(amount = "60000000"): FinancialAction {
  return { type: "base-native-usdc-transfer", chain_id: 8453, from: wallet, to: USDC, value: "0", recipient,
    amount_base_units: amount, data: "0xa9059cbb" + recipient.slice(2).padStart(64, "0") + BigInt(amount).toString(16).padStart(64, "0") };
}
function submission(amount?: string) { return { audience: FINANCIAL_AUDIENCE, action: action(amount), evidence: {}, escalation_reason: "Local synthetic test", expires_in_seconds: 1800 }; }
function fakeD1(): D1Database {
  mem = new DatabaseSync(":memory:"); mem.exec("PRAGMA foreign_keys=ON");
  for (const name of ["0006_human_reviews.sql", "0007_financial_reservations.sql"]) mem.exec(readFileSync(new URL("../migrations/" + name, import.meta.url), "utf8"));
  function prepare(query: string, values: SQLInputValue[] = []) {
    return { bind(...args: SQLInputValue[]) { return prepare(query, args); },
      execute() { return mem.prepare(query).all(...values); },
      async first() { return mem.prepare(query).get(...values) ?? null; },
      async all() { return { results: mem.prepare(query).all(...values), success: true }; },
      async run() { mem.prepare(query).run(...values); return { success: true }; } };
  }
  async function batch(statements: ReturnType<typeof prepare>[]) {
    mem.exec("BEGIN IMMEDIATE");
    try { const results = statements.map(s => ({ results: s.execute(), success: true })); mem.exec("COMMIT"); return results; }
    catch (error) { mem.exec("ROLLBACK"); throw error; }
  }
  return { prepare, batch } as unknown as D1Database;
}
async function call(path: string, body?: unknown, key = "integration") {
  return handleHttpRequest(new Request("https://vizier.test" + path, { method: body === undefined ? "GET" : "POST", headers: { Authorization: `Bearer ${key}`, "Content-Type": "application/json" }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) }), options);
}
async function policy(overrides = {}, key = "reviewer") {
  return call("/v1/reviews/policies", { wallet, single_limit: "100000000", daily_limit: "100000000", enabled: true, reason: "Local fixture, never production", ...overrides }, key);
}
interface Review { id: string; request_hash: string; token: string }
async function create(amount?: string): Promise<Review> {
  const response = await call("/v1/reviews", submission(amount)); expect(response.status).toBe(201); return response.json() as Promise<Review>;
}
async function approve(row: Review): Promise<Review> {
  const response = await call(`/v1/reviews/${row.id}/decision`, { request_hash: row.request_hash, decision: "APPROVED", reason: "Local fixture only" }, "reviewer");
  expect(response.status).toBe(200); return response.json() as Promise<Review>;
}
function claim(row: Review) { return call(`/v1/reviews/${row.id}/consume`, { request_hash: row.request_hash, token: row.token, audience: FINANCIAL_AUDIENCE }); }
function cancel(row: Review, key = "reviewer") { return call(`/v1/reviews/${row.id}/cancel`, { request_hash: row.request_hash, reason: "Cancelled locally" }, key); }
function reservation(row: Review) { return mem.prepare("SELECT * FROM financial_reservations WHERE review_id=?").get(row.id)!; }

beforeEach(async () => {
  const pair = await webcrypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const snapshot = { schema_version: 1, source: OFAC_SOURCE, checked_at: Math.floor(Date.now() / 1000), publish_date: "2026-09-18",
    source_sha256: "a".repeat(64), record_count: 19000, addresses: Array.from({ length: 100 }, (_, i) => "0x" + i.toString(16).padStart(40, "0")) };
  options = { apiKey: "integration", reviewerApiKey: "reviewer", db: fakeD1(),
    circuitBreakerKv: { get: async () => JSON.stringify(snapshot) } as unknown as TransportOptions["circuitBreakerKv"],
    receiptSigningKey: JSON.stringify({ ...await webcrypto.subtle.exportKey("jwk", pair.privateKey), alg: "ES256", kid: "test", use: "sig" }) };
});
afterEach(() => { vi.unstubAllGlobals(); mem.close(); });

describe("financial reservations", () => {
  it("blocks financial requests when official address evidence is absent, stale or an exact match", async () => {
    await policy();
    options = { ...options, circuitBreakerKv: undefined };
    expect((await call("/v1/reviews", submission())).status).toBe(409);
    options = { ...options, circuitBreakerKv: { get: async () => JSON.stringify({ schema_version: 1, source: OFAC_SOURCE,
      checked_at: 1, publish_date: "2026-09-18", source_sha256: "a".repeat(64), record_count: 19000,
      addresses: Array.from({ length: 100 }, (_, i) => "0x" + i.toString(16).padStart(40, "0")) }) } as unknown as TransportOptions["circuitBreakerKv"] };
    expect((await call("/v1/reviews", submission())).status).toBe(409);
    options = { ...options, circuitBreakerKv: { get: async () => JSON.stringify({ schema_version: 1, source: OFAC_SOURCE,
      checked_at: Math.floor(Date.now()/1000), publish_date: "2026-09-18", source_sha256: "a".repeat(64), record_count: 19000,
      addresses: [...Array.from({ length: 99 }, (_, i) => "0x" + i.toString(16).padStart(40, "0")), recipient] }) } as unknown as TransportOptions["circuitBreakerKv"] };
    expect((await call("/v1/reviews", submission())).status).toBe(409);
    expect(mem.prepare("SELECT count(*) AS n FROM human_reviews").get()!.n).toBe(0);
  });
  it("rechecks the address snapshot at approval and claim", async () => {
    await policy();
    const goodKv = options.circuitBreakerKv;
    const pending = await create();
    options = { ...options, circuitBreakerKv: undefined };
    expect((await call(`/v1/reviews/${pending.id}/decision`, { request_hash: pending.request_hash, decision: "APPROVED", reason: "Synthetic" }, "reviewer")).status).toBe(409);
    options = { ...options, circuitBreakerKv: goodKv };
    const approved = await approve(pending);
    options = { ...options, circuitBreakerKv: undefined };
    expect((await claim(approved)).status).toBe(409);
    expect(reservation(approved).state).toBe("RESERVED");
  });
  it("has no default policy, rolls back the review, and separates policy authority", async () => {
    expect((await call("/v1/reviews", submission())).status).toBe(409);
    expect(mem.prepare("SELECT count(*) AS n FROM human_reviews").get()!.n).toBe(0);
    expect((await policy({}, "integration")).status).toBe(403);
    expect((await policy()).status).toBe(200);
    expect(mem.prepare("SELECT count(*) AS n FROM financial_policy_events").get()!.n).toBe(1);
    expect((await policy({ daily_limit: "1" })).status).toBe(400);
  });
  it("atomically admits only one of twelve competing 60 USDC requests into 100 USDC", async () => {
    await policy();
    const results = await Promise.all(Array.from({ length: 12 }, () => call("/v1/reviews", submission())));
    expect(results.filter(r => r.status === 201)).toHaveLength(1);
    expect(results.filter(r => r.status === 409)).toHaveLength(11);
    expect(mem.prepare("SELECT count(*) AS n FROM human_reviews").get()!.n).toBe(1);
    expect(mem.prepare("SELECT count(*) AS n FROM financial_events").get()!.n).toBe(1);
  });
  it("enforces per-transfer limits, exact calldata, asset, audience and bounded integers", async () => {
    await policy();
    expect((await call("/v1/reviews", submission("100000001"))).status).toBe(409);
    for (const patch of [{ data: "0x" }, { value: "1" }, { to: wallet }, { chain_id: 1 }, { amount_base_units: "01" }, { amount_base_units: "1000000000001" }, { amount_base_units: 1 }]) {
      expect((await call("/v1/reviews", { ...submission(), action: { ...action(), ...patch } })).status).toBe(400);
    }
    expect((await call("/v1/reviews", { ...submission(), audience: "other" })).status).toBe(400);
  });
  it("releases unclaimed cancellations but never permits claim of the old token", async () => {
    await policy(); const old = await approve(await create());
    expect((await cancel(old, "integration")).status).toBe(403);
    expect((await cancel(old)).status).toBe(200);
    await create(); expect((await claim(old)).status).toBe(409);
  });
  it("does not free a claimed hold on expiry, retention, cancellation or disabled policy", async () => {
    await policy(); const row = await approve(await create()); expect((await claim(row)).status).toBe(200);
    expect(reservation(row).state).toBe("CLAIMED");
    mem.prepare("UPDATE human_reviews SET created_at=1,expires_at=2,token_expires_at=2 WHERE id=?").run(row.id);
    expect((await cancel(row)).status).toBe(409);
    expect((await call("/v1/reviews", submission())).status).toBe(409);
    expect((await call(`/v1/reviews/${row.id}`)).status).toBe(200);
    expect(() => mem.prepare("DELETE FROM human_reviews WHERE id=?").run(row.id)).toThrow("FINANCIAL_RETENTION_HOLD");
    await policy({ enabled: false }); expect(reservation(row).state).toBe("CLAIMED");
  });
  it("rechecks policy disablement and lowered limits at claim time", async () => {
    await policy(); const row = await approve(await create());
    await policy({ enabled: false }); expect((await claim(row)).status).toBe(409);
    await policy({ single_limit: "50000000", daily_limit: "50000000" }); expect((await claim(row)).status).toBe(409);
    expect(reservation(row).state).toBe("RESERVED");
  });
  it("releases expired unclaimed requests and keeps settled spend for a rolling day", async () => {
    await policy(); const old = await create();
    mem.prepare("UPDATE human_reviews SET expires_at=1 WHERE id=?").run(old.id);
    const row = await approve(await create()); await claim(row);
    mem.prepare("UPDATE financial_reservations SET state='SETTLED',settled_at=unixepoch() WHERE review_id=?").run(row.id);
    expect((await call("/v1/reviews", submission())).status).toBe(409);
    mem.prepare("UPDATE financial_reservations SET settled_at=unixepoch()-86401 WHERE review_id=?").run(row.id);
    await create();
  });
  it("rolls back claim and reservation when financial audit fails", async () => {
    await policy(); const row = await approve(await create());
    mem.exec("CREATE TRIGGER broken_audit BEFORE INSERT ON financial_events BEGIN SELECT RAISE(ABORT,'audit down'); END;");
    expect((await claim(row)).status).toBe(500);
    expect(reservation(row).state).toBe("RESERVED");
    expect(mem.prepare("SELECT status FROM human_reviews WHERE id=?").get(row.id)!.status).toBe("APPROVED");
  });
  it("allows only one of concurrent claim and cancellation to win", async () => {
    await policy(); const row = await approve(await create());
    const results = await Promise.all([claim(row), cancel(row)]);
    expect(results.map(r => r.status).sort()).toEqual([200, 409]);
    const status = mem.prepare("SELECT status FROM human_reviews WHERE id=?").get(row.id)!.status;
    expect(reservation(row).state).toBe(status === "CONSUMED" ? "CLAIMED" : "RESERVED");
  });
});

const txHash = "0x" + "a".repeat(64), blockHash = "0x" + "b".repeat(64);
function mockRpc(change: Record<string, unknown> = {}) {
  const now = Math.floor(Date.now() / 1000);
  const answers: Record<string, unknown> = {
    eth_chainId: "0x2105",
    eth_getTransactionReceipt: { transactionHash: txHash, blockHash, blockNumber: "0x10", status: "0x1", logs: [{ address: USDC,
      topics: ["0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef", "0x" + wallet.slice(2).padStart(64,"0"), "0x" + recipient.slice(2).padStart(64,"0")],
      data: "0x" + BigInt(action().amount_base_units).toString(16).padStart(64,"0") }] },
    eth_getBlockByNumber: { number: "0x10", hash: blockHash, timestamp: "0x" + (now - 5).toString(16) },
    eth_getTransactionByHash: { hash: txHash, from: wallet, to: USDC, input: action().data, value: "0x0", chainId: "0x2105", blockHash, blockNumber: "0x10" },
    ...change,
  };
  vi.stubGlobal("fetch", vi.fn(async (url: string, init: RequestInit) => {
    expect(url).toBe("https://mainnet.base.org"); expect(init.redirect).toBe("error");
    const input = JSON.parse(init.body as string) as { method: string };
    return Response.json({ jsonrpc: "2.0", id: 1, result: answers[input.method] });
  }));
  return answers;
}
describe("finalized Base reconciliation", () => {
  it("verifies the exact transaction and Transfer log", async () => {
    mockRpc(); const outcome = await verifyFinancialOutcome(action(), txHash, Math.floor(Date.now()/1000)-20);
    expect(outcome).toMatchObject({ state: "SETTLED", block_number: 16, block_hash: blockHash });
  });
  it("retains holds for pending, wrong-chain, mismatched, old and missing-transfer evidence", async () => {
    mockRpc({ eth_getTransactionReceipt: null }); expect(await verifyFinancialOutcome(action(), txHash, 1)).toBeNull();
    mockRpc({ eth_chainId: "0x1" }); await expect(verifyFinancialOutcome(action(), txHash, 1)).rejects.toThrow();
    mockRpc(); await expect(verifyFinancialOutcome(action(), txHash, Math.floor(Date.now()/1000))).rejects.toThrow();
    const answers = mockRpc();
    mockRpc({ eth_getTransactionByHash: { ...(answers.eth_getTransactionByHash as object), input: "0x" } });
    await expect(verifyFinancialOutcome(action(), txHash, 1)).rejects.toThrow();
    mockRpc({ eth_getTransactionReceipt: { ...(answers.eth_getTransactionReceipt as object), logs: [] } });
    await expect(verifyFinancialOutcome(action(), txHash, 1)).rejects.toThrow();
  });
  it("attaches once, preserves hold on RPC failure, and settles exactly once", async () => {
    await policy(); const row = await approve(await create()); await claim(row);
    mem.prepare("UPDATE human_reviews SET consumed_at=consumed_at-20 WHERE id=?").run(row.id);
    mockRpc({ eth_getTransactionReceipt: null });
    expect((await call(`/v1/reviews/${row.id}/transaction`, { transaction_hash: txHash })).status).toBe(200);
    expect(reservation(row).state).toBe("CLAIMED");
    expect((await call(`/v1/reviews/${row.id}/transaction`, { transaction_hash: "0x"+"c".repeat(64) })).status).toBe(409);
    mockRpc(); expect((await call(`/v1/reviews/${row.id}/transaction`, { transaction_hash: txHash })).status).toBe(200);
    expect(reservation(row).state).toBe("SETTLED");
    expect((await call(`/v1/reviews/${row.id}/transaction`, { transaction_hash: txHash })).status).toBe(409);
  });
  it("the public SDK reconciles an exact consumed review", async () => {
    await policy(); const row = await approve(await create()); await claim(row);
    mem.prepare("UPDATE human_reviews SET consumed_at=consumed_at-20 WHERE id=?").run(row.id);
    mockRpc();
    const client = new Vizier({ baseUrl: "https://vizier.test", apiKey: "integration", fetch: async (input, init) => handleHttpRequest(new Request(input, init), options) });
    expect(await client.reconcileFinancialTransaction(row.id, txHash)).toMatchObject({ state: "SETTLED", finalized: true, transaction_hash: txHash });
    await expect(client.reconcileFinancialTransaction("../bad", txHash)).rejects.toThrow("Invalid review ID");
  });
  it("rejects nonfinality, stale anchors, reorganized blocks and reused transaction hashes", async () => {
    const answers = mockRpc();
    mockRpc({ eth_getTransactionReceipt: { ...(answers.eth_getTransactionReceipt as object), blockNumber: "0x11" } });
    expect(await verifyFinancialOutcome(action(), txHash, 1)).toBeNull();
    mockRpc({ eth_getBlockByNumber: { ...(answers.eth_getBlockByNumber as object), timestamp: "0x1" } });
    await expect(verifyFinancialOutcome(action(), txHash, 1)).rejects.toThrow("Stale");
    mockRpc({ eth_getTransactionReceipt: { ...(answers.eth_getTransactionReceipt as object), blockHash: "0x"+"c".repeat(64) } });
    await expect(verifyFinancialOutcome(action(), txHash, 1)).rejects.toThrow("match");
    await policy({ daily_limit: "200000000" }); const a = await approve(await create()), b = await approve(await create()); await claim(a); await claim(b);
    mockRpc({ eth_getTransactionReceipt: null });
    expect((await call(`/v1/reviews/${a.id}/transaction`, { transaction_hash: txHash })).status).toBe(200);
    expect((await call(`/v1/reviews/${b.id}/transaction`, { transaction_hash: txHash })).status).toBe(409);
    expect(reservation(b).state).toBe("CLAIMED"); expect(reservation(b).tx_hash).toBeNull();
  });
  it("only releases a failed transaction after exact finalized receipt verification", async () => {
    await policy(); const row = await approve(await create()); await claim(row);
    mem.prepare("UPDATE human_reviews SET consumed_at=consumed_at-20 WHERE id=?").run(row.id);
    const answers = mockRpc(); mockRpc({ eth_getTransactionReceipt: { ...(answers.eth_getTransactionReceipt as object), status: "0x0", logs: [] } });
    expect((await call(`/v1/reviews/${row.id}/transaction`, { transaction_hash: txHash })).status).toBe(200);
    expect(reservation(row).state).toBe("REVERTED"); await create();
  });
});
