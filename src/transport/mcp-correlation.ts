/** Optional, daily-scoped pseudonym. Never affects request authorization. */
export async function mcpCallerCorrelation(
  request: Request,
  encodedKey: string | undefined,
  timestamp: string,
): Promise<{ caller_hash: string | null; correlation_status: "available" | "not_configured" | "no_network_address" | "error" }> {
  // 32 random bytes, unpadded base64url. No static or weak fallback.
  if (!encodedKey || !/^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/.test(encodedKey)) {
    return { caller_hash: null, correlation_status: "not_configured" };
  }
  const ip = request.headers.get("CF-Connecting-IP")?.trim();
  if (!ip || ip.length > 64) return { caller_hash: null, correlation_status: "no_network_address" };
  try {
    const raw = atob(encodedKey.replaceAll("-", "+").replaceAll("_", "/") + "=");
    if (raw.length !== 32) return { caller_hash: null, correlation_status: "not_configured" };
    const key = Uint8Array.from(raw, c => c.charCodeAt(0));
    const imported = await crypto.subtle.importKey("raw", key, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    const agent = (request.headers.get("User-Agent") ?? "").slice(0, 256);
    const input = JSON.stringify(["vizier-mcp-correlation-v1", timestamp.slice(0, 10), ip, agent]);
    const signature = await crypto.subtle.sign("HMAC", imported, new TextEncoder().encode(input));
    const caller_hash = Array.from(new Uint8Array(signature).slice(0, 16), b => b.toString(16).padStart(2, "0")).join("");
    return { caller_hash, correlation_status: "available" };
  } catch {
    return { caller_hash: null, correlation_status: "error" };
  }
}
