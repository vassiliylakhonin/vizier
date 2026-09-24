import { z } from "zod";
import { rpc, USDC } from "./financial";

const hash = z.string().regex(/^0x[0-9a-f]{64}$/);
const quantity = z.string().regex(/^0x(?:0|[1-9a-f][0-9a-f]*)$/);
const block = z.object({ number: quantity, hash, timestamp: quantity });
const log = z.object({ address: z.string(), topics: z.array(hash).length(3), data: hash,
  removed: z.literal(false), blockNumber: quantity, logIndex: quantity, transactionHash: hash, blockHash: hash });
const TRANSFER = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
// BlockPI permits 1,024 blocks per public eth_getLogs request. The 45,001-block
// window takes 44 log calls plus four chain/anchor reads: 48 external requests
// under the Workers Free limit of 50. Never shorten an incomplete day.
const LOOKBACK_BLOCKS = 45000n;
const LOG_SPAN = 1024n;

export interface WalletHistory {
  outgoing: number;
  observedAt: number;
  startBlock: number;
  endBlock: number;
  endBlockHash: string;
}

/** Conservative finalized native-USDC history; never a spending authorization. */
export async function collectWalletHistory(wallet: string): Promise<WalletHistory> {
  const started = Date.now();
  if (await rpc("eth_chainId", []) !== "0x2105") throw new Error("Wrong Base chain");
  const anchor = block.parse(await rpc("eth_getBlockByNumber", ["finalized", false]));
  const end = BigInt(anchor.number);
  if (end < LOOKBACK_BLOCKS) throw new Error("Insufficient Base history");
  const first = end - LOOKBACK_BLOCKS;
  const start = block.parse(await rpc("eth_getBlockByNumber", ["0x" + first.toString(16), false]));
  const now = Math.floor(Date.now() / 1000);
  const endTime = Number(BigInt(anchor.timestamp));
  if (BigInt(start.number) !== first || !Number.isSafeInteger(endTime) || endTime > now + 60
    || now - endTime > 3600 || BigInt(start.timestamp) > BigInt(endTime - 86400)) {
    throw new Error("Finalized history does not cover a fresh full day");
  }
  const sender = "0x" + wallet.slice(2).padStart(64, "0");
  const seen = new Set<string>();
  let outgoing = 0n;
  for (let from = first; from <= end; from += LOG_SPAN) {
    if (Date.now() - started > 120000) throw new Error("Base history timed out");
    const to = from + LOG_SPAN - 1n < end ? from + LOG_SPAN - 1n : end;
    const raw = await rpc("eth_getLogs", [{ address: USDC, fromBlock: "0x" + from.toString(16),
      toBlock: "0x" + to.toString(16), topics: [TRANSFER, sender] }]);
    if (!Array.isArray(raw) || raw.length > 1000) throw new Error("Incomplete Base logs");
    for (const item of raw) {
      const entry = log.parse(item);
      const height = BigInt(entry.blockNumber);
      const key = entry.transactionHash + ":" + entry.logIndex;
      if (entry.address.toLowerCase() !== USDC || entry.topics[0] !== TRANSFER || entry.topics[1] !== sender
        || height < from || height > to || seen.has(key)) throw new Error("Invalid Base transfer log");
      seen.add(key);
      outgoing += BigInt(entry.data);
      if (outgoing > 1000000000000n) throw new Error("Observed spend exceeds supported budget");
    }
  }
  const confirm = block.parse(await rpc("eth_getBlockByNumber", [anchor.number, false]));
  if (confirm.hash !== anchor.hash || BigInt(confirm.number) !== end) throw new Error("Base finality anchor changed");
  return { outgoing: Number(outgoing), observedAt: Math.floor(Date.now() / 1000),
    startBlock: Number(first), endBlock: Number(end), endBlockHash: anchor.hash };
}
