import { z } from "zod";
import type { D1Database } from "@cloudflare/workers-types";
import { jsonResponse, readLimitedJson, TransportRequestError } from "../transport/shared";

export const FINANCIAL_AUDIENCE = "agenda-financial-guard:base-native-usdc";
export const USDC = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913";
const address = z.string().regex(/^0x[0-9a-f]{40}$/).refine(v => v !== "0x" + "0".repeat(40));
const units = z.string().regex(/^[1-9][0-9]{0,12}$/).refine(v => BigInt(v) <= 1000000000000n);
export const financialActionSchema = z.strictObject({
  type: z.literal("base-native-usdc-transfer"), chain_id: z.literal(8453), from: address,
  to: z.literal(USDC), value: z.literal("0"), data: z.string(), recipient: address, amount_base_units: units,
}).refine(v => v.data === "0xa9059cbb" + v.recipient.slice(2).padStart(64, "0") + BigInt(v.amount_base_units).toString(16).padStart(64, "0"));
export type FinancialAction = z.infer<typeof financialActionSchema>;
export const financialPolicySchema = z.strictObject({ wallet: address, single_limit: units, daily_limit: units,
  enabled: z.boolean(), reason: z.string().trim().min(1).max(2000),
}).refine(v => BigInt(v.single_limit) <= BigInt(v.daily_limit));
export const transactionSchema = z.strictObject({ transaction_hash: z.string().regex(/^0x[0-9a-f]{64}$/) });
export function financialAction(payload: { audience: string; action: Record<string, unknown> }): FinancialAction | null {
  if (payload.audience !== FINANCIAL_AUDIENCE && payload.action.type !== "base-native-usdc-transfer") return null;
  const parsed = financialActionSchema.safeParse(payload.action);
  if (payload.audience !== FINANCIAL_AUDIENCE || !parsed.success) {
    throw new TransportRequestError(400, "INVALID_FINANCIAL_ACTION", "Use the exact documented Base native-USDC action and audience.");
  }
  return parsed.data;
}
export function budgetError(error: unknown): never {
  if (error instanceof Error && /FINANCIAL_(BUDGET|RESERVATION)_UNAVAILABLE/.test(error.message)) {
    throw new TransportRequestError(409, "FINANCIAL_BUDGET_UNAVAILABLE", "No enabled policy, insufficient workflow budget, or unavailable reservation.");
  }
  throw error;
}
export async function handleFinancialPolicy(request: Request, db: D1Database, reviewer: boolean): Promise<Response> {
  if (request.method === "GET") {
    const policies = await db.prepare("SELECT wallet,CAST(single_limit AS TEXT) AS single_limit,CAST(daily_limit AS TEXT) AS daily_limit,enabled,updated_at,reason FROM financial_policies ORDER BY wallet LIMIT 100").all();
    return jsonResponse({ policies: policies.results, scope: "vizier_review_workflow_only", chain_id: 8453, asset: USDC });
  }
  if (request.method !== "POST") throw new TransportRequestError(405, "METHOD_NOT_ALLOWED", "Use GET or POST.");
  if (!reviewer) throw new TransportRequestError(403, "REVIEWER_REQUIRED", "Only the reviewer may configure owner-supplied limits.");
  const parsed = financialPolicySchema.safeParse(await readLimitedJson(request));
  if (!parsed.success) throw new TransportRequestError(400, "INVALID_FINANCIAL_POLICY", "Use exact positive base units; limits cannot exceed 1,000,000 USDC.");
  const p = parsed.data;
  await db.prepare(`INSERT INTO financial_policies(wallet,single_limit,daily_limit,enabled,updated_at,reason) VALUES(?,?,?,?,?,?)
    ON CONFLICT(wallet) DO UPDATE SET single_limit=excluded.single_limit,daily_limit=excluded.daily_limit,enabled=excluded.enabled,updated_at=excluded.updated_at,reason=excluded.reason`)
    .bind(p.wallet, Number(p.single_limit), Number(p.daily_limit), Number(p.enabled), Math.floor(Date.now() / 1000), p.reason).run();
  return jsonResponse({ ...p, scope: "vizier_review_workflow_only", execution: "not_performed" });
}

/** All reads go to one fixed Base endpoint; never accept caller RPC URLs or outcomes. */
export async function rpc(method: string, params: unknown[]): Promise<unknown> {
  const response = await fetch("https://base.public.blockpi.network/v1/rpc/public", { method: "POST", redirect: "manual",
    headers: { "Content-Type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }), signal: AbortSignal.timeout(10000) });
  if (!response.ok) throw new Error(`Base RPC HTTP ${response.status}`);
  if (!response.body) throw new Error("Base RPC empty response");
  const reader = response.body.getReader(); const chunks: Uint8Array[] = []; let size = 0;
  try {
    for (;;) { const part = await reader.read(); if (part.done) break; size += part.value.length;
      if (size > 262144) throw new Error("Base RPC response too large"); chunks.push(part.value); }
  } finally { await reader.cancel(); }
  const bytes = new Uint8Array(size); let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
  const data = JSON.parse(new TextDecoder().decode(bytes)) as { jsonrpc?: unknown; id?: unknown; error?: unknown; result?: unknown };
  if (data.jsonrpc !== "2.0" || data.id !== 1 || data.error || !("result" in data)) throw new Error("Invalid Base RPC envelope");
  return data.result;
}
const hex = z.string().regex(/^0x(?:0|[1-9a-f][0-9a-f]*)$/);
const hash = z.string().regex(/^0x[0-9a-f]{64}$/);
const blockSchema = z.object({ number: hex, hash, timestamp: hex });
const txSchema = z.object({ hash, from: address, to: z.literal(USDC), input: z.string(), value: hex, chainId: z.literal("0x2105"), blockHash: hash, blockNumber: hex });
const receiptSchema = z.object({ transactionHash: hash, blockHash: hash, blockNumber: hex, status: z.enum(["0x0", "0x1"]),
  logs: z.array(z.object({ address: z.string(), topics: z.array(z.string()), data: z.string(), removed: z.boolean().optional() })).max(1000) });
const TRANSFER = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
export async function verifyFinancialOutcome(action: FinancialAction, txHash: string, consumedAt: number) {
  if (await rpc("eth_chainId", []) !== "0x2105") throw new Error("Wrong chain");
  const rawReceipt = await rpc("eth_getTransactionReceipt", [txHash]);
  if (rawReceipt === null) return null;
  const receipt = receiptSchema.parse(rawReceipt);
  const finalized = blockSchema.parse(await rpc("eth_getBlockByNumber", ["finalized", false]));
  const now = Math.floor(Date.now() / 1000);
  if (BigInt(finalized.timestamp) > BigInt(now + 60) || BigInt(finalized.timestamp) < BigInt(now - 3600)) throw new Error("Stale finality anchor");
  if (BigInt(receipt.blockNumber) > BigInt(finalized.number)) return null;
  const block = blockSchema.parse(await rpc("eth_getBlockByNumber", [receipt.blockNumber, false]));
  const tx = txSchema.parse(await rpc("eth_getTransactionByHash", [txHash]));
  if (receipt.transactionHash !== txHash || tx.hash !== txHash || tx.from !== action.from || tx.input !== action.data || tx.value !== "0x0"
    || block.hash !== receipt.blockHash || tx.blockHash !== block.hash || tx.blockNumber !== block.number || receipt.blockNumber !== block.number
    || BigInt(block.timestamp) <= BigInt(consumedAt) || BigInt(block.timestamp) > BigInt(finalized.timestamp)) throw new Error("Transaction does not match claimed action");
  if (receipt.status === "0x1") {
    const transfers = receipt.logs.filter(log => log.address.toLowerCase() === USDC && log.topics[0] === TRANSFER);
    const log = transfers[0];
    if (transfers.length !== 1 || !log || log.removed || log.topics.length !== 3
      || log.topics[1] !== "0x" + action.from.slice(2).padStart(64, "0") || log.topics[2] !== "0x" + action.recipient.slice(2).padStart(64, "0")
      || log.data !== "0x" + BigInt(action.amount_base_units).toString(16).padStart(64, "0")) throw new Error("USDC Transfer evidence mismatch");
  }
  const number = Number(BigInt(block.number)); const timestamp = Number(BigInt(block.timestamp));
  if (!Number.isSafeInteger(number) || !Number.isSafeInteger(timestamp)) throw new Error("Unsafe block values");
  return { state: receipt.status === "0x1" ? "SETTLED" : "REVERTED", block_number: number, block_hash: block.hash, settled_at: timestamp };
}
export async function reconcileFinancial(request: Request, db: D1Database, id: string, action: FinancialAction, consumedAt: number): Promise<Response> {
  const parsed = transactionSchema.safeParse(await readLimitedJson(request));
  if (!parsed.success) throw new TransportRequestError(400, "INVALID_TRANSACTION_HASH", "Supply the transaction hash only.");
  const txHash = parsed.data.transaction_hash;
  // Immutable attachment and globally unique hash prevent cross-review reuse. Even
  // a pending/incorrect attachment retains the hold; no caller can free it.
  const attached = await db.prepare("UPDATE financial_reservations SET tx_hash=? WHERE review_id=? AND state='CLAIMED' AND (tx_hash IS NULL OR tx_hash=?) RETURNING review_id")
    .bind(txHash, id, txHash).first().catch((error: unknown) => {
      if (error instanceof Error && error.message.includes("UNIQUE constraint failed: financial_reservations.tx_hash")) {
        throw new TransportRequestError(409, "TRANSACTION_ALREADY_ATTACHED", "This transaction is already bound to another review.");
      }
      throw error;
    });
  if (!attached) throw new TransportRequestError(409, "RESERVATION_UNAVAILABLE", "Reservation is resolved, absent or attached to a different transaction.");
  let outcome;
  try { outcome = await verifyFinancialOutcome(action, txHash, consumedAt); }
  catch { throw new TransportRequestError(409, "OUTCOME_UNVERIFIED", "RPC evidence is unavailable or does not match. Reservation remains held."); }
  if (!outcome) return jsonResponse({ id, state: "CLAIMED", transaction_hash: txHash, finalized: false });
  const result = await db.prepare("UPDATE financial_reservations SET state=?,settled_at=?,block_number=?,block_hash=? WHERE review_id=? AND state='CLAIMED' AND tx_hash=? RETURNING review_id")
    .bind(outcome.state, outcome.settled_at, outcome.block_number, outcome.block_hash, id, txHash).first();
  if (!result) throw new TransportRequestError(409, "RESERVATION_UNAVAILABLE", "Another reconciliation completed.");
  return jsonResponse({ id, ...outcome, transaction_hash: txHash, finalized: true, execution: "observed_only" });
}
