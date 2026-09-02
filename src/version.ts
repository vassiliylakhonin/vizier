// One literal for the whole service. It had been copied into nine files and
// asserted in six more, and since 2026-09-02 a tenth consumer sits outside the
// repository entirely: the MCP Registry entry, which changes only when someone
// runs `mcp-publisher publish`. A release that updates some copies and not the
// rest is silent, so `tests/discovery-contracts.test.ts` compares every copy
// against this one.
export const SERVICE_VERSION = "0.2.2";
