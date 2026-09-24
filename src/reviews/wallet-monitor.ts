import type { D1Database } from "@cloudflare/workers-types";
import { collectWalletHistory, type WalletHistory } from "./wallet-history";

const walletAddress = /^0x[0-9a-f]{40}$/;

/** A scheduled observation only; this table is never read by budget admission. */
export async function runWalletHistoryMonitor(db: D1Database, wallet: string): Promise<WalletHistory> {
  if (!walletAddress.test(wallet) || wallet === "0x" + "0".repeat(40)) throw new Error("INVALID_MONITOR_WALLET");

  async function recordFailure(reason: string): Promise<never> {
    await db.prepare(`INSERT INTO wallet_history_monitor(id,wallet,checked_at,state,reason)
      VALUES(1,?,?,'FAILED',?) ON CONFLICT(id) DO UPDATE SET
      wallet=excluded.wallet,checked_at=excluded.checked_at,state=excluded.state,
      observed_outgoing=NULL,start_block=NULL,end_block=NULL,end_block_hash=NULL,reason=excluded.reason`)
      .bind(wallet, Math.floor(Date.now() / 1000), reason).run();
    throw new Error(reason);
  }

  const policy = await db.prepare("SELECT enabled FROM financial_policies WHERE wallet=?").bind(wallet).first<{ enabled: number }>();
  if (!policy) return recordFailure("MONITOR_POLICY_MISSING");
  if (policy.enabled !== 0) return recordFailure("MONITOR_POLICY_ENABLED");

  let history: WalletHistory;
  try { history = await collectWalletHistory(wallet); }
  catch { return recordFailure("MONITOR_HISTORY_UNAVAILABLE"); }

  await db.prepare(`INSERT INTO wallet_history_monitor
    (id,wallet,checked_at,state,observed_outgoing,start_block,end_block,end_block_hash)
    VALUES(1,?,?,'OK',?,?,?,?) ON CONFLICT(id) DO UPDATE SET
    wallet=excluded.wallet,checked_at=excluded.checked_at,state=excluded.state,
    observed_outgoing=excluded.observed_outgoing,start_block=excluded.start_block,
    end_block=excluded.end_block,end_block_hash=excluded.end_block_hash,reason=NULL`)
    .bind(wallet, history.observedAt, history.outgoing, history.startBlock, history.endBlock, history.endBlockHash).run();
  return history;
}
