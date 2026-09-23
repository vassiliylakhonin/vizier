import { financialAction, budgetError, handleFinancialPolicy, reconcileFinancial } from "./financial";
import { z } from "zod";
import { sha256 } from "../core/receipts";
import { canonicalizeJson, signCompactJws, verifyCompactJws } from "../crypto/jws";
import { authorizeEnforcement } from "../transport/auth";
import { jsonResponse, readLimitedJson, TransportRequestError, type TransportOptions } from "../transport/shared";

export const REVIEW_TYPE = "VIZIER-HUMAN-REVIEW+JWS";
const hashSchema = z.string().regex(/^[a-f0-9]{64}$/);
export const reviewSubmissionSchema = z.strictObject({
  audience: z.string().min(1).max(200),
  action: z.record(z.string(), z.unknown()),
  evidence: z.record(z.string(), z.unknown()),
  escalation_reason: z.string().min(1).max(2000),
  expires_in_seconds: z.number().int().min(60).max(3600).default(1800),
});
export const reviewDecisionSchema = z.strictObject({ request_hash: hashSchema, decision: z.enum(["APPROVED", "REJECTED"]), reason: z.string().trim().min(1).max(2000) });
export const reviewConsumeSchema = z.strictObject({ token: z.string().max(12000), request_hash: hashSchema, audience: z.string().min(1).max(200) });
interface ReviewRow {
  id: string; request_hash: string; payload_json: string; status: string;
  created_at: number; expires_at: number; decided_at: number | null;
  reason: string | null; token: string | null; token_expires_at: number | null; consumed_at: number | null;
}
function failure(status: number, code: string, message: string): never {
  throw new TransportRequestError(status, code, message);
}
function parse<T>(schema: z.ZodType<T>, value: unknown): T {
  const parsed = schema.safeParse(value);
  if (!parsed.success) failure(400, "INVALID_REVIEW_REQUEST", "Review request does not match the documented schema.");
  return parsed.data;
}
function view(row: ReviewRow, now: number) {
  return { ...row, payload_json: undefined, request: JSON.parse(row.payload_json) as unknown,
    effective_status: (row.status === "PENDING" && row.expires_at <= now) ||
      (row.status === "APPROVED" && (row.token_expires_at ?? 0) <= now) ? "EXPIRED" : row.status };
}
function claims(row: ReviewRow, issuer: string) {
  const payload = parse(reviewSubmissionSchema, JSON.parse(row.payload_json) as unknown);
  return { iss: issuer, aud: payload.audience, jti: row.id, request_hash: row.request_hash,
    decision: row.status === "REJECTED" ? "REJECTED" : "APPROVED",
    reviewer: "reviewer", reason: row.reason, iat: row.decided_at,
    exp: row.token_expires_at, purpose: "manual-action-review" };
}

/** Administrative single-operator queue. Tenant API keys have no access. */
export async function handleReviews(request: Request, options: TransportOptions): Promise<Response> {
  const url = new URL(request.url);
  if (!options.apiKey || !options.reviewerApiKey || !options.db || !options.receiptSigningKey || options.apiKey === options.reviewerApiKey) {
    failure(503, "REVIEWS_UNAVAILABLE", "Review storage, distinct reviewer credential and signing key are required.");
  }
  const integration = await authorizeEnforcement(request, options.apiKey) === "authenticated";
  const reviewer = await authorizeEnforcement(request, options.reviewerApiKey) === "authenticated";
  if (!integration && !reviewer) failure(401, "UNAUTHORIZED", "An integration or reviewer credential is required.");
  const db = options.db;
  const now = Math.floor(Date.now() / 1000);
  if (url.pathname === "/v1/reviews/policies") return handleFinancialPolicy(request, db, reviewer);
  if (url.pathname === "/v1/reviews") {
    if (request.method === "GET") {
      const rows = await db.prepare("SELECT * FROM human_reviews WHERE (created_at > ? OR id IN (SELECT review_id FROM financial_reservations WHERE state='CLAIMED' OR settled_at > unixepoch()-604800)) ORDER BY created_at DESC LIMIT 100").bind(now - 7 * 86400).all<ReviewRow>();
      return jsonResponse({ reviews: rows.results.map(row => view(row, now)), limit: 100 });
    }
    if (request.method !== "POST") failure(405, "METHOD_NOT_ALLOWED", "Use GET or POST.");
    if (!integration) failure(403, "INTEGRATION_REQUIRED", "Only the integration credential can submit a review.");
    const payload = parse(reviewSubmissionSchema, await readLimitedJson(request));
    const stack: unknown[] = [payload];
    while (stack.length) {
      const value = stack.pop();
      if (typeof value === "number" && (!Number.isFinite(value) || (Number.isInteger(value) && !Number.isSafeInteger(value)))) {
        failure(400, "UNSAFE_REVIEW_NUMBER", "Use exact strings for large amounts and integer values.");
      }
      if (value !== null && typeof value === "object") stack.push(...Object.values(value));
    }
    const canonical = canonicalizeJson(payload);
    if (new TextEncoder().encode(canonical).length > 32768) failure(413, "REVIEW_TOO_LARGE", "Review payload must fit in 32 KiB.");
    const row: ReviewRow = { id: `rev_${crypto.randomUUID()}`, request_hash: await sha256(canonical), payload_json: canonical,
      status: "PENDING", created_at: now, expires_at: now + payload.expires_in_seconds,
      decided_at: null, reason: null, token: null, token_expires_at: null, consumed_at: null };
    const action = financialAction(payload);
    const insertion = db.prepare("INSERT INTO human_reviews(id,request_hash,payload_json,status,created_at,expires_at) VALUES(?,?,?,'PENDING',?,?)")
      .bind(row.id, row.request_hash, canonical, now, row.expires_at);
    try {
      if (action) {
        await db.batch([insertion, db.prepare("INSERT INTO financial_reservations(review_id,wallet,amount,state) VALUES(?,?,?,'RESERVED')")
          .bind(row.id, action.from, Number(action.amount_base_units))]);
      } else { await insertion.run(); }
    } catch (error) { budgetError(error); }
    return jsonResponse(view(row, now), 201);
  }
  const match = /^\/v1\/reviews\/(rev_[a-f0-9-]{36})(?:\/(decision|consume|cancel|transaction))?$/.exec(url.pathname);
  if (!match) failure(404, "REVIEW_NOT_FOUND", "Unknown review route.");
  const row = await db.prepare("SELECT * FROM human_reviews WHERE id = ? AND (created_at > ? OR id IN (SELECT review_id FROM financial_reservations WHERE state='CLAIMED' OR settled_at > unixepoch()-604800))").bind(match[1]!, now - 7 * 86400).first<ReviewRow>();
  if (!row) failure(404, "REVIEW_NOT_FOUND", "Review not found or retention period elapsed.");
  if (!match[2] && request.method === "GET") {
    const events = await db.prepare("SELECT state,occurred_at,actor,reason FROM human_review_events WHERE review_id = ? ORDER BY id").bind(row.id).all();
    const reservation = await db.prepare("SELECT review_id,wallet,CAST(amount AS TEXT) AS amount,state,tx_hash,settled_at,block_number,block_hash FROM financial_reservations WHERE review_id=?").bind(row.id).first();
    const financialEvents = await db.prepare("SELECT state,occurred_at,tx_hash FROM financial_events WHERE review_id=? ORDER BY id").bind(row.id).all();
    return jsonResponse({ ...view(row, now), events: events.results, reservation, financial_events: financialEvents.results });
  }
  if (request.method !== "POST" || !match[2]) failure(405, "METHOD_NOT_ALLOWED", "Use the documented review method.");
  if (match[2] === "cancel") {
    if (!reviewer) failure(403, "REVIEWER_REQUIRED", "Only the reviewer may cancel an unclaimed approval.");
    const input = parse(z.strictObject({ request_hash: hashSchema, reason: z.string().trim().min(1).max(2000) }), await readLimitedJson(request));
    const changed = await db.prepare("UPDATE human_reviews SET status='REJECTED',reason=?,decided_at=?,token=NULL,token_expires_at=NULL WHERE id=? AND request_hash=? AND status IN ('PENDING','APPROVED') RETURNING id")
      .bind(input.reason, now, row.id, input.request_hash).first();
    if (!changed) failure(409, "REVIEW_NOT_CANCELLABLE", "Consumed or resolved requests cannot be cancelled.");
    return jsonResponse({ id: row.id, status: "REJECTED", execution: "not_performed" });
  }
  if (match[2] === "transaction") {
    if (!integration) failure(403, "INTEGRATION_REQUIRED", "Only the integration may attach transaction evidence.");
    const action = financialAction(parse(reviewSubmissionSchema, JSON.parse(row.payload_json) as unknown));
    if (!action || row.status !== "CONSUMED" || row.consumed_at === null) failure(409, "NO_CLAIMED_FINANCIAL_ACTION", "A consumed financial review is required.");
    return reconcileFinancial(request, db, row.id, action, row.consumed_at);
  }
  if (match[2] === "decision") {
    if (!reviewer) failure(403, "REVIEWER_REQUIRED", "Only the separate reviewer credential can decide.");
    const input = parse(reviewDecisionSchema, await readLimitedJson(request));
    if (input.request_hash !== row.request_hash) failure(409, "REQUEST_MISMATCH", "The displayed request hash must match.");
    if (row.status !== "PENDING" || row.expires_at <= now) failure(409, "REVIEW_NOT_PENDING", "Review was decided or expired.");
    const decided: ReviewRow = { ...row, status: input.decision, reason: input.reason, decided_at: now, token_expires_at: Math.min(now + 300, row.expires_at) };
    const token = await signCompactJws(claims(decided, url.origin), options.receiptSigningKey, REVIEW_TYPE);
    // The conditional update and audit trigger are one SQLite transaction.
    const changed = await db.prepare("UPDATE human_reviews SET status=?,reason=?,decided_at=?,token=?,token_expires_at=? WHERE id=? AND status='PENDING' AND expires_at > ? RETURNING id")
      .bind(decided.status, decided.reason, now, token, decided.token_expires_at, row.id, Math.floor(Date.now() / 1000)).first<{ id: string }>().catch(budgetError);
    if (!changed) failure(409, "REVIEW_NOT_PENDING", "Another decision won or the review expired.");
    return jsonResponse(view({ ...decided, token }, now));
  }
  if (!integration) failure(403, "INTEGRATION_REQUIRED", "Only the integration credential can claim an approval.");
  const input = parse(reviewConsumeSchema, await readLimitedJson(request));
  const payload = parse(reviewSubmissionSchema, JSON.parse(row.payload_json) as unknown);
  if (row.status !== "APPROVED" || (row.token_expires_at ?? 0) <= now || input.request_hash !== row.request_hash || input.audience !== payload.audience || input.token !== row.token) {
    failure(409, "APPROVAL_UNAVAILABLE", "Approval is expired, already claimed, rejected, or bound to a different request.");
  }
  if (!await verifyCompactJws(input.token, claims(row, url.origin), options.receiptSigningKey, REVIEW_TYPE)) {
    failure(409, "INVALID_ATTESTATION", "Attestation signature or bindings are invalid.");
  }
  const consumedAt = Math.floor(Date.now() / 1000);
  const changed = await db.prepare("UPDATE human_reviews SET status='CONSUMED',consumed_at=? WHERE id=? AND status='APPROVED' AND token=? AND token_expires_at > ? AND expires_at > ? RETURNING id")
    .bind(consumedAt, row.id, input.token, consumedAt, consumedAt).first<{ id: string }>().catch(budgetError);
  if (!changed) failure(409, "APPROVAL_UNAVAILABLE", "Approval was claimed concurrently or expired.");
  return jsonResponse({ id: row.id, request_hash: row.request_hash, audience: payload.audience, status: "CONSUMED", consumed_at: consumedAt,
    execution: "not_performed", next_step: "Manually verify the exact action in the wallet. This response is not a payment signature." });
}
