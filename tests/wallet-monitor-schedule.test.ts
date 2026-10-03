import { describe, it, expect, vi, beforeEach } from 'vitest';
import { readFileSync } from 'node:fs';
const mocks = vi.hoisted(() => ({ run: vi.fn(), retry: vi.fn(), prune: vi.fn() }));
vi.mock('../src/reviews/wallet-monitor', () => ({ runWalletHistoryMonitor: mocks.run, retryWalletHistoryMonitor: mocks.retry }));
vi.mock('../src/storage/audit', () => ({ pruneAuditMetadata: mocks.prune }));
import { handleScheduled } from '../src/scheduled';

function schedule(cron: string) {
  const run = vi.fn().mockResolvedValue({ success: true });
  const prepare = vi.fn(() => ({ bind: vi.fn(() => ({ run })) }));
  const pending: Promise<unknown>[] = [];
  handleScheduled({ cron, scheduledTime: Date.now() },
    { DB: { prepare }, VIZIER_MONITORED_WALLET: '0x' + '1'.repeat(40) } as unknown as Parameters<typeof handleScheduled>[1],
    { waitUntil: (value: Promise<unknown>) => { pending.push(value); } });
  return { prepare, pending };
}
beforeEach(() => {
  vi.clearAllMocks();
  mocks.run.mockResolvedValue({ observedAt: 1, endBlock: 2 });
  mocks.retry.mockResolvedValue(null);
  mocks.prune.mockResolvedValue({ cutoff: 'test', deleted: 0 });
});
describe('bounded wallet observation schedule', () => {
  it.each(['47 3 * * *', '7 4 * * *'])('retry %s invokes only the read-only monitor', async cron => {
    const { prepare, pending } = schedule(cron); await Promise.all(pending);
    expect(mocks.retry).toHaveBeenCalledOnce(); expect(mocks.run).not.toHaveBeenCalled();
    expect(mocks.prune).not.toHaveBeenCalled(); expect(prepare).not.toHaveBeenCalled();
  });
  it('daily cron still prunes and observes once', async () => {
    const { prepare, pending } = schedule('17 3 * * *'); await Promise.all(pending);
    expect(mocks.run).toHaveBeenCalledOnce(); expect(mocks.retry).not.toHaveBeenCalled();
    expect(mocks.prune).toHaveBeenCalledOnce(); expect(prepare).toHaveBeenCalledOnce();
  });
  it('unknown schedules perform no work', async () => {
    const { prepare, pending } = schedule('* * * * *'); await Promise.all(pending);
    expect(mocks.run).not.toHaveBeenCalled(); expect(mocks.retry).not.toHaveBeenCalled();
    expect(mocks.prune).not.toHaveBeenCalled(); expect(prepare).not.toHaveBeenCalled();
  });
  it('config declares exactly the primary scan and two pre-check retries', () => {
    const config = readFileSync(new URL('../wrangler.jsonc', import.meta.url), 'utf8');
    expect(config).toMatch(/"crons": \["17 3 \* \* \*", "47 3 \* \* \*", "7 4 \* \* \*"\]/);
  });
});
