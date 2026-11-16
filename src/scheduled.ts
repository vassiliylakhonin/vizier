import type { D1Database, ExecutionContext, ScheduledController } from '@cloudflare/workers-types';
import { pruneAuditMetadata } from './storage/audit';
import { pruneGrantLifecycle } from './transport/grant-lifecycle';
import { runWalletHistoryMonitor, retryWalletHistoryMonitor } from './reviews/wallet-monitor';

export function handleScheduled(controller: Pick<ScheduledController, 'cron' | 'scheduledTime'>,
  env: { DB: D1Database; VIZIER_MONITORED_WALLET?: string; VIZIER_MONITOR_FALLBACK_RPC_URL?: string },
  ctx: Pick<ExecutionContext, 'waitUntil'>): void {
  // Backoff after the 03:17 primary scan: +30, +60 and +120 minutes. When the
  // operator configures VIZIER_MONITOR_FALLBACK_RPC_URL, the first and last
  // retries scan through that endpoint instead of the throttled primary.
  // Match the scheduled UTC hour instead of the invocation time. Accept the
  // previous expressions while Cloudflare propagates the merged trigger.
  const retrySlot = new Date(controller.scheduledTime);
  const hour = retrySlot.getUTCHours();
  const retry = retrySlot.getUTCMinutes() === 47 && [3, 4, 6].includes(hour) &&
    (controller.cron === '47 3,4,6 * * *' || controller.cron === `47 ${hour} * * *`);
  const fallback = typeof env.VIZIER_MONITOR_FALLBACK_RPC_URL === 'string'
    && env.VIZIER_MONITOR_FALLBACK_RPC_URL.startsWith('https://')
    ? env.VIZIER_MONITOR_FALLBACK_RPC_URL : undefined;
  const retryUrl = hour === 3 || hour === 6 ? fallback : undefined;
  if (controller.cron !== '17 3 * * *' && !retry) return;
  // Extra observations must not repeat pruning or any other scheduled mutation.
  if (!retry) {
    ctx.waitUntil(env.DB.prepare("DELETE FROM human_reviews WHERE created_at <= ? AND id NOT IN (SELECT review_id FROM financial_reservations WHERE state='CLAIMED' OR settled_at > unixepoch()-604800)").bind(Math.floor(controller.scheduledTime / 1000) - 7 * 86400).run());
    ctx.waitUntil(pruneGrantLifecycle(env.DB, Math.floor(controller.scheduledTime / 1000)).catch((error: unknown) =>
      console.error(JSON.stringify({ event: 'vizier.grant_lifecycle.prune_failed', error: error instanceof Error ? error.name : 'UnknownError' }))));
    ctx.waitUntil(pruneAuditMetadata(env.DB, new Date(controller.scheduledTime))
      .then(result => console.log(JSON.stringify({ event: 'vizier.audit.pruned', cutoff: result.cutoff, deleted: result.deleted })))
      .catch((error: unknown) => console.error(JSON.stringify({ event: 'vizier.audit.prune_failed',
        error: error instanceof Error ? error.name : 'UnknownError' }))));
  }
  if (env.VIZIER_MONITORED_WALLET) {
    const observation = retry
      ? retryWalletHistoryMonitor(env.DB, env.VIZIER_MONITORED_WALLET, controller.scheduledTime, retryUrl)
      : runWalletHistoryMonitor(env.DB, env.VIZIER_MONITORED_WALLET);
    ctx.waitUntil(observation
      .then(history => console.log(JSON.stringify(history
        ? { event: 'vizier.wallet_history.monitor', state: 'OK', observed_at: history.observedAt, end_block: history.endBlock }
        : { event: 'vizier.wallet_history.monitor', state: 'SKIPPED_FRESH' })))
      .catch((error: unknown) => console.error(JSON.stringify({ event: 'vizier.wallet_history.monitor', state: 'FAILED',
        reason: error instanceof Error ? error.message : 'UNKNOWN',
        diagnostic: error instanceof Error && typeof error.cause === 'string' ? error.cause : null }))));
  } else {
    console.error(JSON.stringify({ event: 'vizier.wallet_history.monitor', state: 'FAILED', reason: 'MONITOR_WALLET_NOT_CONFIGURED' }));
  }
}
