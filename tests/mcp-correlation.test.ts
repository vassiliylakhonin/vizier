import { afterEach, describe, expect, it, vi } from "vitest";
import { mcpCallerCorrelation } from "../src/transport/mcp-correlation";
import { handleHttpRequest } from "../src/transport/http";

const KEY = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"; // synthetic 32-byte test key
const req = (ip = "192.0.2.2", agent = "test-agent") => new Request("https://example.test/mcp", {
  headers: { "CF-Connecting-IP": ip, "User-Agent": agent },
});
const DAY = "2026-10-30T03:00:00.000Z";
afterEach(() => vi.restoreAllMocks());

describe("daily MCP correlation", () => {
  it("uses a keyed pseudonym scoped to UTC day and input, without fallback", async () => {
    const a = await mcpCallerCorrelation(req(), KEY, DAY);
    expect(a.correlation_status).toBe("available");
    expect(a.caller_hash).toMatch(/^[0-9a-f]{32}$/);
    expect((await mcpCallerCorrelation(req(), KEY, DAY)).caller_hash).toBe(a.caller_hash);
    expect((await mcpCallerCorrelation(req(), KEY, "2026-10-31T00:00:00.000Z")).caller_hash).not.toBe(a.caller_hash);
    expect((await mcpCallerCorrelation(req("192.0.2.3"), KEY, DAY)).caller_hash).not.toBe(a.caller_hash);
    expect(await mcpCallerCorrelation(req(), undefined, DAY)).toEqual({ caller_hash: null, correlation_status: "not_configured" });
    expect(await mcpCallerCorrelation(req(), "short", DAY)).toEqual({ caller_hash: null, correlation_status: "not_configured" });
    expect(await mcpCallerCorrelation(new Request("https://example.test/mcp"), KEY, DAY)).toEqual({ caller_hash: null, correlation_status: "no_network_address" });
  });

  it("logs known and unknown tool categories without names, arguments, keys or addresses", async () => {
    const log = vi.spyOn(console, "log").mockImplementation(() => {});
    const rows: Record<string, unknown>[] = [];
    for (const name of ["vizier_verify_action", "private-arbitrary-tool"]) {
      log.mockClear();
      const request = new Request("https://example.test/mcp", { method: "POST", headers: {
        "Content-Type": "application/json", "CF-Connecting-IP": "192.0.2.2", "User-Agent": "private-user-agent",
      }, body: JSON.stringify({ jsonrpc: "2.0", id: "private-id", method: "tools/call", params: {
        name, arguments: { prompt: "private-content" },
      } }) });
      await handleHttpRequest(request, { mcpCorrelationKey: KEY });
      const events = log.mock.calls.map(c => { try { return JSON.parse(String(c[0])); } catch { return null; } })
        .filter(e => e?.event === "agenda_service_access");
      expect(events).toHaveLength(1);
      rows.push(events[0]);
    }
    expect(rows[0]).toMatchObject({ mcp_tool: "vizier_verify_action", correlation_status: "available" });
    expect(rows[1]).toMatchObject({ mcp_tool: "unknown", correlation_status: "available" });
    expect(rows[0]?.caller_hash).toBe(rows[1]?.caller_hash);
    const text = JSON.stringify(rows);
    for (const forbidden of ["private-", "192.0.2.2", KEY]) expect(text).not.toContain(forbidden);
  });
});
