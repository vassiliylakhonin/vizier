// Run against the disposable local server started by scripts/first-block.mjs.
// No tool is executed. --signed requires the source SDK, not npm 0.5.16.
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const { Vizier } = await import(process.env.VIZIER_DEMO_SDK || "@agenda-intelligence/vizier-sdk");
const baseUrl = process.env.VIZIER_BASE_URL;
assert(baseUrl && new URL(baseUrl).hostname === "127.0.0.1", "Use the local demo server only.");
const signed = process.argv.includes("--signed");
const request = JSON.parse(await readFile(new URL("../examples/block.json", import.meta.url), "utf8"));
const options = signed ? { requestReceiptJws: true } : {};
const client = new Vizier({ baseUrl, apiKey: process.env.VIZIER_API_KEY });
const result = await client.verify(globalThis.structuredClone(request), options);
assert.equal(result.decision, "BLOCK");
assert(result.reason_codes.includes("GRANT_REQUIRED"));
if (signed) assert(result.receipt_jws, "Missing signature: this demo requires a signed receipt.");
console.log(`TypeScript: BLOCK (GRANT_REQUIRED), request hash verified${signed ? ", ES256 receipt verified" : " (not a signature)"}`);

// A client-side fault injection, not a compromised server or a real action.
const tampered = new Vizier({
  baseUrl,
  apiKey: process.env.VIZIER_API_KEY,
  fetch: async (url, init) => {
    const response = await fetch(url, init);
    if (!String(url).endsWith("/v1/verify")) return response;
    assert(response.ok, `Unexpected HTTP ${response.status}`);
    const body = await response.json();
    if (signed) body.receipt.id = "vrf_tampered";
    else body.receipt.request_hash = "0".repeat(64);
    return globalThis.Response.json(body);
  },
});
await assert.rejects(
  () => tampered.verify(globalThis.structuredClone(request), options),
  (err) => err.code === (signed ? "RECEIPT_SIGNATURE_INVALID" : "INVALID_RESPONSE"),
);
console.log(`TypeScript: tampered ${signed ? "signed receipt" : "request hash"} rejected; no tool executed`);

if (signed) {
  // A service that silently drops the signature must not be trusted when the
  // caller requires one. requireReceiptJws makes a missing JWS an error.
  const unsigned = new Vizier({
    baseUrl,
    apiKey: process.env.VIZIER_API_KEY,
    fetch: async (url, init) => {
      const response = await fetch(url, init);
      if (!String(url).endsWith("/v1/verify")) return response;
      assert(response.ok, `Unexpected HTTP ${response.status}`);
      const body = await response.json();
      delete body.receipt_jws;
      return globalThis.Response.json(body);
    },
  });
  await assert.rejects(
    () => unsigned.verify(globalThis.structuredClone(request), { requireReceiptJws: true }),
    (err) => err.code === "RECEIPT_SIGNATURE_REQUIRED",
  );
  console.log("TypeScript: missing signed receipt rejected with requireReceiptJws; no tool executed");
}
