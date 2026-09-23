import type { KVNamespace } from "@cloudflare/workers-types";
import { z } from "zod";
import { TransportRequestError } from "../transport/shared";

export const OFAC_KV_KEY = "ofac-evm-addresses-v1";
export const OFAC_SOURCE = "https://sanctionslistservice.ofac.treas.gov/api/PublicationPreview/exports/SDN.XML";
const address = z.string().regex(/^0x[0-9a-f]{40}$/);
const snapshotSchema = z.strictObject({
  schema_version: z.literal(1), source: z.literal(OFAC_SOURCE),
  checked_at: z.number().int().positive(), publish_date: z.string().regex(/^\d{4}-\d{2}-\d{2}$/),
  source_sha256: z.string().regex(/^[0-9a-f]{64}$/), record_count: z.number().int().min(10000),
  addresses: z.array(address).min(100).max(10000),
});

/** Exact address match against a recent official SDN snapshot; never a sanctions clearance. */
export async function checkOfacAddresses(kv: KVNamespace | undefined, addresses: readonly string[]): Promise<void> {
  let raw: string | null = null;
  try { raw = await kv?.get(OFAC_KV_KEY) ?? null; } catch { /* unavailable means block */ }
  let snapshot: z.infer<typeof snapshotSchema> | undefined;
  try { snapshot = snapshotSchema.parse(JSON.parse(raw ?? "null")); } catch { /* malformed means block */ }
  const now = Math.floor(Date.now() / 1000);
  if (!snapshot || snapshot.checked_at > now + 300 || now - snapshot.checked_at > 36 * 3600
    || snapshot.addresses.some((value, i) => i > 0 && value <= snapshot!.addresses[i - 1]!)) {
    throw new TransportRequestError(409, "SANCTIONS_DATA_UNAVAILABLE", "A recent official OFAC address snapshot is required for financial review.");
  }
  if (addresses.some(address => snapshot!.addresses.includes(address))) {
    throw new TransportRequestError(409, "SANCTIONS_ADDRESS_MATCH", "A transfer address exactly matches an address in the OFAC SDN snapshot.");
  }
}
