import { describe, it, expect, vi, beforeEach } from 'vitest';
import { readFileSync } from 'node:fs';
const mocks = vi.hoisted(() => ({ run: vi.fn(), retry: vi.fn(), prune: vi.fn(), pruneGrants: vi.fn() }));
vi.mock('../src/reviews/wallet-monitor', () => ({ runWalletHistoryMonitor: mocks.run, retryWalletHistoryMonitor: mocks.retry }));
vi.mock('../src/storage/audit', () => ({ pruneAuditMetadata: mocks.prune }));
vi.mock('../src/transport/grant-lifecycle', () => ({ pruneGrantLifecycle: mocks.pruneGrants }));
import { handleScheduled } from '../src/scheduled';

const RETRY_CRON = '47 3,4,6 * * *';
const retryHours = [3, 4, 6];
const retrySlot = (hour: number) => Date.UTC(2026, 10, 16, hour, 47);

function schedule(cron: string, scheduledTime: number, fallbackUrl?: string) {
  const run = vi.fn().mockResolvedValue({ success: true });
  const prepare = vi.fn(() => ({ bind: vi.fn(() => ({ run })) }));
  const pending: Promise<unknown>[] = [];
  handleScheduled({ cron, scheduledTime },
    { DB: { prepare }, VIZIER_MONITORED_WALLET: '0x' + '1'.repeat(40),
      VIZIER_MONITOR_FALLBACK_RPC_URL: fallbackUrl } as unknown as Parameters<typeof handleScheduled>[1],
    { waitUntil: (value: Promise<unknown>) => { pending.push(value); } });
  return { prepare, pending };
}
beforeEach(() => {
  vi.clearAllMocks();
  mocks.run.mockResolvedValue({ observedAt: 1, endBlock: 2 });
  mocks.retry.mockResolvedValue(null);
  mocks.prune.mockResolvedValue({ cutoff: 'test', deleted: 0 });
  mocks.pruneGrants.mockResolvedValue(undefined);
});
describe('bounded wallet observation schedule', () => {
  it.each(retryHours)('retry at hour %s UTC invokes only the read-only monitor', async hour => {
    const { prepare, pending } = schedule(RETRY_CRON, retrySlot(hour)); await Promise.all(pending);
    expect(mocks.retry).toHaveBeenCalledOnce(); expect(mocks.run).not.toHaveBeenCalled();
    expect(mocks.prune).not.toHaveBeenCalled(); expect(prepare).not.toHaveBeenCalled();
  });
  it('daily cron still prunes and observes once', async () => {
    const { prepare, pending } = schedule('17 3 * * *', Date.UTC(2026, 10, 16, 3, 17)); await Promise.all(pending);
    expect(mocks.run).toHaveBeenCalledOnce(); expect(mocks.retry).not.toHaveBeenCalled();
    expect(mocks.prune).toHaveBeenCalledOnce(); expect(mocks.pruneGrants).toHaveBeenCalledOnce(); expect(prepare).toHaveBeenCalledOnce();
  });
  it('first and last retries use the configured fallback endpoint, middle retry stays public', async () => {
    const url = 'https://lb.drpc.org/ogrpc?network=base&dkey=test-key';
    schedule(RETRY_CRON, retrySlot(3), url);
    expect(mocks.retry).toHaveBeenCalledWith(expect.anything(), expect.anything(), expect.anything(), url);
    vi.clearAllMocks();
    schedule(RETRY_CRON, retrySlot(4), url);
    expect(mocks.retry).toHaveBeenCalledWith(expect.anything(), expect.anything(), expect.anything(), undefined);
    vi.clearAllMocks();
    schedule(RETRY_CRON, retrySlot(6), url);
    expect(mocks.retry).toHaveBeenCalledWith(expect.anything(), expect.anything(), expect.anything(), url);
  });
  it('no fallback endpoint keeps every retry on the public primary', async () => {
    for (const hour of retryHours) {
      vi.clearAllMocks();
      schedule(RETRY_CRON, retrySlot(hour));
      expect(mocks.retry).toHaveBeenCalledWith(expect.anything(), expect.anything(), expect.anything(), undefined);
    }
  });
  it('a non-https fallback endpoint is ignored', async () => {
    schedule(RETRY_CRON, retrySlot(3), 'http://insecure.example');
    expect(mocks.retry).toHaveBeenCalledWith(expect.anything(), expect.anything(), expect.anything(), undefined);
  });
  it('unknown schedules perform no work', async () => {
    const { prepare, pending } = schedule('* * * * *', retrySlot(3)); await Promise.all(pending);
    expect(mocks.run).not.toHaveBeenCalled(); expect(mocks.retry).not.toHaveBeenCalled();
    expect(mocks.prune).not.toHaveBeenCalled(); expect(prepare).not.toHaveBeenCalled();
  });
  it.each(retryHours)('accepts the previous cron at %s UTC during rollout', async hour => {
    const { pending } = schedule(`47 ${hour} * * *`, retrySlot(hour));
    await Promise.all(pending);
    expect(mocks.retry).toHaveBeenCalledOnce();
    expect(mocks.prune).not.toHaveBeenCalled();
  });
  it('the combined cron ignores times outside its retry slots', async () => {
    for (const time of [retrySlot(5), Date.UTC(2026, 10, 16, 3, 48)]) {
      const { pending } = schedule(RETRY_CRON, time);
      await Promise.all(pending);
      expect(mocks.retry).not.toHaveBeenCalled();
      expect(mocks.prune).not.toHaveBeenCalled();
    }
  });
  it('config declares only the primary and combined retry triggers', () => {
    const config = readFileSync(new URL('../wrangler.jsonc', import.meta.url), 'utf8');
    expect(config).toMatch(/"crons": \["17 3 \* \* \*", "47 3,4,6 \* \* \*"\]/);
  });
});
