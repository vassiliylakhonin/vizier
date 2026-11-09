import { execFileSync, spawnSync } from 'node:child_process';
import { readFileSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, it, expect } from 'vitest';

const now = 1794229200;
const good = { state: 'OK', enabled: 0, checked_at: now, observed_outgoing: 0,
  start_block: 55000000, end_block: 55432000, end_block_hash: '0x' + 'a'.repeat(64), reason: null };
function assess(row: unknown) {
  return JSON.parse(execFileSync(process.execPath, ['--input-type=module', '-e', `
    import { assessWalletMonitor } from './scripts/check-wallet-monitor.mjs';
    console.log(JSON.stringify(assessWalletMonitor(JSON.parse(process.argv[1]), ${now})));
  `, JSON.stringify(row)], { encoding: 'utf8' })) as { outcome: string; ok: boolean; diagnostic: string | null };
}
function read(output: string | null) {
  return JSON.parse(execFileSync(process.execPath, ['--input-type=module', '-e', `
    import { readWalletMonitor } from './scripts/check-wallet-monitor.mjs';
    console.log(JSON.stringify(readWalletMonitor(() => {
      if (process.argv[1] === 'throw') throw new Error('secret-provider-url');
      return process.argv[1];
    })));
  `, output ?? 'throw'], { encoding: 'utf8' })) as { outcome: string; ok: boolean; message: string };
}
function failed(reason: string) { return { ...good, state: 'FAILED', observed_outgoing: null, reason }; }

describe('wallet observation reporting remains fail-closed', () => {
  it('only a fresh complete observation with disabled policy passes', () => {
    expect(assess(good)).toMatchObject({ outcome: 'OBSERVED', ok: true });
    expect(assess({ ...good, checked_at: now - 18 * 3600 })).toMatchObject({ outcome: 'OBSERVED', ok: true });
  });
  it.each(['RPC_HTTP_429', 'RPC_HTTP_500', 'RPC_HTTP_503', 'RPC_TIMEOUT'])('reports %s as unavailable provider, never a healthy wallet', code => {
    expect(assess(failed(`MONITOR_HISTORY_UNAVAILABLE:${code}`))).toEqual({
      outcome: 'PROVIDER_UNAVAILABLE', ok: false, diagnostic: code,
      message: 'RPC provider unavailable or throttled. Wallet history is unknown, not healthy. Wait for a complete scheduled scan; do not enable spending.',
    });
  });
  it.each(['INCOMPLETE_LOGS', 'INVALID_SCHEMA', 'WRONG_CHAIN', 'ANCHOR_CHANGED', 'UNSUPPORTED_SPEND',
    'SUBREQUEST_LIMIT', 'RPC_HTTP_403', 'RPC_ENVELOPE_eth_getLogs_CODE_-32000'])('does not mislabel %s as merely a provider outage', code => {
    expect(assess(failed(`MONITOR_HISTORY_UNAVAILABLE:${code}`))).toMatchObject({ outcome: 'EVIDENCE_UNAVAILABLE', ok: false, diagnostic: code });
  });
  it('does not repeat arbitrary provider text, URLs or workflow commands', () => {
    const assessment = assess(failed('MONITOR_HISTORY_UNAVAILABLE:secret-url\n::notice::hidden'));
    expect(assessment).toMatchObject({ outcome: 'EVIDENCE_UNAVAILABLE', ok: false, diagnostic: 'UNKNOWN' });
    expect(JSON.stringify(assessment)).not.toMatch(/secret-url|notice|hidden/);
  });
  it('keeps policy problems separate, even during an RPC outage', () => {
    expect(assess({ ...failed('MONITOR_HISTORY_UNAVAILABLE:RPC_HTTP_429'), enabled: 1 }))
      .toMatchObject({ outcome: 'POLICY_UNSAFE', ok: false });
    expect(assess({ ...good, enabled: null })).toMatchObject({ outcome: 'CONFIGURATION_ERROR', ok: false });
    expect(assess(failed('MONITOR_POLICY_ENABLED'))).toMatchObject({ outcome: 'POLICY_UNSAFE', ok: false });
    expect(assess(failed('MONITOR_POLICY_MISSING'))).toMatchObject({ outcome: 'CONFIGURATION_ERROR', ok: false });
  });
  it('distinguishes missing and stale evidence', () => {
    expect(assess(null)).toMatchObject({ outcome: 'MISSING_OBSERVATION', ok: false });
    expect(assess({ ...good, checked_at: now - 18 * 3600 - 1 })).toMatchObject({ outcome: 'STALE_OBSERVATION', ok: false });
  });
  it.each([
    { checked_at: now + 61 }, { checked_at: -1 }, { checked_at: 'now' }, { observed_outgoing: -1 },
    { observed_outgoing: null }, { observed_outgoing: 1000000000001 }, { start_block: -1 },
    { end_block: good.start_block }, { end_block_hash: 'bad' }, { reason: 'old failure' }, { state: 'UNKNOWN' },
  ])('refuses malformed/inconsistent evidence %j', change => {
    expect(assess({ ...good, ...change })).toMatchObject({ outcome: 'INVALID_EVIDENCE', ok: false });
  });
  it('unknown failure stays failed without leaking its reason', () => {
    expect(assess(failed('secret-url'))).toMatchObject({ outcome: 'MONITOR_FAILURE', ok: false, diagnostic: null });
  });
  it.each([null, 'not json', '{}', '[]', '[{"success":false,"results":[]}]', '[{"success":true}]',
    '[{"success":true,"results":[{},{}]}]'])('fails closed when D1 cannot be read: %s', output => {
    const assessment = read(output);
    expect(assessment).toMatchObject({ outcome: 'CHECK_UNAVAILABLE', ok: false });
    expect(JSON.stringify(assessment)).not.toContain('secret-provider-url');
  });
  it('reads successful D1 envelopes without converting provider failures to success', () => {
    expect(read(JSON.stringify([{ success: true, results: [{ ...good, checked_at: Math.floor(Date.now() / 1000) }] }])))
      .toMatchObject({ outcome: 'OBSERVED', ok: true });
    expect(read(JSON.stringify([{ success: true, results: [failed('MONITOR_HISTORY_UNAVAILABLE:RPC_HTTP_429')] }])))
      .toMatchObject({ outcome: 'PROVIDER_UNAVAILABLE', ok: false });
  });
  it('distinguishes empty successful D1 result from read failure', () => {
    expect(read('[{"success":true,"results":[]}]')).toMatchObject({ outcome: 'MISSING_OBSERVATION', ok: false });
  });
  it('CLI exits nonzero with a fixed annotation and summary when the D1 command fails', () => {
    const dir = mkdtempSync(join(tmpdir(), 'vizier-wallet-check-'));
    const summary = join(dir, 'summary.md');
    try {
      const child = spawnSync(process.execPath, ['scripts/check-wallet-monitor.mjs'], {
        encoding: 'utf8', env: { ...process.env, PATH: dir, GITHUB_STEP_SUMMARY: summary },
      });
      expect(child.status).toBe(1);
      expect(JSON.parse(child.stdout)).toMatchObject({ outcome: 'CHECK_UNAVAILABLE', ok: false });
      expect(child.stderr).toContain('::error title=Wallet observation: CHECK_UNAVAILABLE::');
      expect(readFileSync(summary, 'utf8')).toContain('unknown, not healthy');
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });
  it('separates observation notifications from deployment without hiding failures', () => {
    const deploy = readFileSync('.github/workflows/deploy.yml', 'utf8');
    const monitor = readFileSync('.github/workflows/wallet-observation.yml', 'utf8');
    expect(deploy).not.toContain('scripts/check-wallet-monitor.mjs');
    expect(deploy).toContain('npm run check:deployed');
    expect(monitor).toContain('name: Wallet observation');
    expect(monitor).toContain('cron: "17 4 * * *"');
    expect(monitor).toContain('node scripts/check-wallet-monitor.mjs');
    expect(monitor).not.toMatch(/continue-on-error|npm run deploy|migrations apply|push:/);
  });
});
