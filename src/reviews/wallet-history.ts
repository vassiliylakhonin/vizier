import { z } from "zod";
import { rpc, USDC } from "./financial";

const hash = z.string().regex(/^0x[0-9a-f]{64}$/);
const quantity = z.string().regex(/^0x(?:0|[1-9a-f][0-9a-f]*)$/);
const block = z.object({ number: quantity, hash, timestamp: quantity });
const log = z.object({ address: z.string(), topics: z.array(hash).length(3), data: hash,
  removed: z.literal(false), blockNumber: quantity, logIndex: quantity, transactionHash: hash, blockHash: hash });
const TRANSFER = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
// BlockPI permits 1,024 blocks per public eth_getLogs request. The 45,001-block
// window takes 44 log calls plus four chain/anchor reads: 48 external requests.
// Reserve the last two Workers Free subrequests for transient provider retries.
// Never shorten an incomplete day.
const LOOKBACK_BLOCKS = 45000n;
const LOG_SPAN = 1024n;
// Public RPC rejects rapid six-request bursts from Workers with JSON-RPC
// -32000 rate limits. Pace single-request batches without spending more subrequests.
const LOG_FETCH_CONCURRENCY = 6;
const RPC_PAUSE_MS = 2000;
function pause(): Promise<void> { return new Promise(resolve => setTimeout(resolve, RPC_PAUSE_MS)); }

export interface WalletHistory {
  outgoing: number;
  observedAt: number;
  startBlock: number;
  endBlock: number;
  endBlockHash: string;
}

/** Conservative finalized native-USDC history; never a spending authorization. */
export async function collectWalletHistory(wallet: string, options: { paceRpc?: boolean } = {}): Promise<WalletHistory> {
  const started = Date.now();
  const concurrency = options.paceRpc ? 1 : LOG_FETCH_CONCURRENCY;
  let spareCalls = 2;
  async function historyRpc(method: string, params: unknown[]): Promise<unknown> {
    for (;;) {
      try { return await rpc(method, params); }
      catch (error) {
        const message = error instanceof Error ? error.message : "";
        if (spareCalls === 0 || !/^(Invalid Base RPC envelope|Base RPC HTTP (429|5\d\d))$/.test(message)) throw error;
        spareCalls--;
        if (options.paceRpc) await pause();
      }
    }
  }
  const [chainId, rawAnchor] = await Promise.all([
    historyRpc("eth_chainId", []),
    historyRpc("eth_getBlockByNumber", ["finalized", false]),
  ]);
  if (chainId !== "0x2105") throw new Error("Wrong Base chain");
  const anchor = block.parse(rawAnchor);
  const end = BigInt(anchor.number);
  if (end < LOOKBACK_BLOCKS) throw new Error("Insufficient Base history");
  const first = end - LOOKBACK_BLOCKS;
  const start = block.parse(await historyRpc("eth_getBlockByNumber", ["0x" + first.toString(16), false]));
  const now = Math.floor(Date.now() / 1000);
  const endTime = Number(BigInt(anchor.timestamp));
  if (BigInt(start.number) !== first || !Number.isSafeInteger(endTime) || endTime > now + 60
    || now - endTime > 3600 || BigInt(start.timestamp) > BigInt(endTime - 86400)) {
    throw new Error("Finalized history does not cover a fresh full day");
  }
  const sender = "0x" + wallet.slice(2).padStart(64, "0");
  const seen = new Set<string>();
  let outgoing = 0n;
  const ranges: Array<{ readonly from: bigint; readonly to: bigint }> = [];
  for (let from = first; from <= end; from += LOG_SPAN) {
    ranges.push({ from, to: from + LOG_SPAN - 1n < end ? from + LOG_SPAN - 1n : end });
  }
  for (let offset = 0; offset < ranges.length; offset += concurrency) {
    if (options.paceRpc && offset > 0) await pause();
    if (Date.now() - started > 120000) throw new Error("Base history timed out");
    const batch = ranges.slice(offset, offset + concurrency);
    const responses = await Promise.all(batch.map(({ from, to }) =>
      historyRpc("eth_getLogs", [{ address: USDC, fromBlock: "0x" + from.toString(16),
        toBlock: "0x" + to.toString(16), topics: [TRANSFER, sender] }])));
    for (let index = 0; index < batch.length; index += 1) {
      const range = batch[index];
      const raw = responses[index];
      if (!range || !Array.isArray(raw) || raw.length > 1000) throw new Error("Incomplete Base logs");
      for (const item of raw) {
        const entry = log.parse(item);
        const height = BigInt(entry.blockNumber);
        const key = entry.transactionHash + ":" + entry.logIndex;
        if (entry.address.toLowerCase() !== USDC || entry.topics[0] !== TRANSFER || entry.topics[1] !== sender
          || height < range.from || height > range.to || seen.has(key)) throw new Error("Invalid Base transfer log");
        seen.add(key);
        outgoing += BigInt(entry.data);
        if (outgoing > 1000000000000n) throw new Error("Observed spend exceeds supported budget");
      }
    }
  }
  const confirm = block.parse(await historyRpc("eth_getBlockByNumber", [anchor.number, false]));
  if (confirm.hash !== anchor.hash || BigInt(confirm.number) !== end) throw new Error("Base finality anchor changed");
  return { outgoing: Number(outgoing), observedAt: Math.floor(Date.now() / 1000),
    startBlock: Number(first), endBlock: Number(end), endBlockHash: anchor.hash };
}
