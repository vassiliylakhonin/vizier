import type { D1Database } from "@cloudflare/workers-types";
import { collectWalletHistory, type WalletHistory } from "./wallet-history";

const walletAddress = /^0x[0-9a-f]{40}$/;

// Persist only fixed categories, never arbitrary RPC text, URLs or credentials.
function historyFailureCode(error: unknown): string {
  if (!(error instanceof Error)) return "UNKNOWN";
  if (error.name === "TimeoutError" || error.name === "AbortError") return "RPC_TIMEOUT";
  if (error.name === "ZodError") return "INVALID_SCHEMA";
  if (error.message === "Too many subrequests.") return "SUBREQUEST_LIMIT";
  const http = /^Base RPC HTTP (\d{3})$/.exec(error.message);
  if (http) return `RPC_HTTP_${http[1]}`;
  if (error.message === "Invalid Base RPC envelope" && error.cause && typeof error.cause === "object"
    && "method" in error.cause && "providerCode" in error.cause) {
    const { method, providerCode } = error.cause;
    if (typeof method === "string" && ["eth_chainId", "eth_getBlockByNumber", "eth_getLogs"].includes(method)
      && typeof providerCode === "number" && Number.isSafeInteger(providerCode)) return `RPC_ENVELOPE_${method}_CODE_${providerCode}`;
  }
  const known: Record<string, string> = {
    "Invalid Base RPC envelope": "RPC_ENVELOPE",
    "Base RPC empty response": "RPC_EMPTY",
    "Base RPC response too large": "RPC_TOO_LARGE",
    "Wrong Base chain": "WRONG_CHAIN",
    "Insufficient Base history": "INSUFFICIENT_HISTORY",
    "Finalized history does not cover a fresh full day": "STALE_OR_SHORT_HISTORY",
    "Incomplete Base logs": "INCOMPLETE_LOGS",
    "Invalid Base transfer log": "INVALID_LOG",
    "Observed spend exceeds supported budget": "UNSUPPORTED_SPEND",
    "Base history timed out": "HISTORY_TIMEOUT",
    "Base finality anchor changed": "ANCHOR_CHANGED",
  };
  return Object.hasOwn(known, error.message) ? known[error.message]! : "UNKNOWN";
}

/** A scheduled observation only; this table is never read by budget admission. */
export async function runWalletHistoryMonitor(db: D1Database, wallet: string): Promise<WalletHistory> {
  if (!walletAddress.test(wallet) || wallet === "0x" + "0".repeat(40)) throw new Error("INVALID_MONITOR_WALLET");

  async function recordFailure(reason: string, diagnostic?: string): Promise<never> {
    const storedReason = diagnostic ? `${reason}:${diagnostic}` : reason;
    await db.prepare(`INSERT INTO wallet_history_monitor(id,wallet,checked_at,state,reason)
      VALUES(1,?,?,'FAILED',?) ON CONFLICT(id) DO UPDATE SET
      wallet=excluded.wallet,checked_at=excluded.checked_at,state=excluded.state,
      observed_outgoing=NULL,start_block=NULL,end_block=NULL,end_block_hash=NULL,reason=excluded.reason`)
      .bind(wallet, Math.floor(Date.now() / 1000), storedReason).run();
    throw new Error(reason, diagnostic ? { cause: diagnostic } : undefined);
  }

  const policy = await db.prepare("SELECT enabled FROM financial_policies WHERE wallet=?").bind(wallet).first<{ enabled: number }>();
  if (!policy) return recordFailure("MONITOR_POLICY_MISSING");
  if (policy.enabled !== 0) return recordFailure("MONITOR_POLICY_ENABLED");

  let history: WalletHistory;
  try { history = await collectWalletHistory(wallet, { paceRpc: true }); }
  catch (error: unknown) { return recordFailure("MONITOR_HISTORY_UNAVAILABLE", historyFailureCode(error)); }

  await db.prepare(`INSERT INTO wallet_history_monitor
    (id,wallet,checked_at,state,observed_outgoing,start_block,end_block,end_block_hash)
    VALUES(1,?,?,'OK',?,?,?,?) ON CONFLICT(id) DO UPDATE SET
    wallet=excluded.wallet,checked_at=excluded.checked_at,state=excluded.state,
    observed_outgoing=excluded.observed_outgoing,start_block=excluded.start_block,
    end_block=excluded.end_block,end_block_hash=excluded.end_block_hash,reason=NULL`)
    .bind(wallet, history.observedAt, history.outgoing, history.startBlock, history.endBlock, history.endBlockHash).run();
  return history;
}

/** Retry only when today's primary scan has not produced a complete observation. */
export async function retryWalletHistoryMonitor(db: D1Database, wallet: string, scheduledTime: number): Promise<WalletHistory | null> {
  if (!walletAddress.test(wallet) || wallet === '0x' + '0'.repeat(40)) throw new Error('INVALID_MONITOR_WALLET');
  if (!Number.isSafeInteger(scheduledTime) || scheduledTime < 0) throw new Error('INVALID_MONITOR_SCHEDULE');
  const row = await db.prepare(`SELECT m.state,m.checked_at,m.observed_outgoing,m.start_block,m.end_block,m.end_block_hash,m.reason,p.enabled
    FROM wallet_history_monitor m LEFT JOIN financial_policies p ON p.wallet=m.wallet
    WHERE m.id=1 AND m.wallet=?`).bind(wallet).first<{
      state: string; checked_at: number; observed_outgoing: number; start_block: number; end_block: number;
      end_block_hash: string; reason: string | null; enabled: number;
    }>();
  const primaryTime = Math.floor(scheduledTime / 86400000) * 86400 + 3 * 3600 + 17 * 60;
  const now = Math.floor(Date.now() / 1000);
  if (row?.state === 'OK' && row.enabled === 0 && row.reason === null
    && Number.isSafeInteger(row.checked_at) && row.checked_at >= primaryTime
    && row.checked_at <= now + 60 && now - row.checked_at <= 3 * 3600
    && Number.isSafeInteger(row.observed_outgoing) && row.observed_outgoing >= 0 && row.observed_outgoing <= 1000000000000
    && Number.isSafeInteger(row.start_block) && row.start_block >= 0 && Number.isSafeInteger(row.end_block)
    && row.end_block - row.start_block === 45000 && /^0x[0-9a-f]{64}$/.test(row.end_block_hash)) return null;
  return runWalletHistoryMonitor(db, wallet);
}
