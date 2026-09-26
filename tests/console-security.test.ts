// 2026-09-26 round-5 console hardening: no inline handlers, no innerHTML with
// server data, no localStorage persistence of the master key, nonce-based CSP.
import { describe, expect, it } from "vitest";
import { createConsoleHtml } from "../src/console/index";

const NONCE = "test-nonce-123";

describe("security console hardening", () => {
  const html = createConsoleHtml("https://vizier.example", NONCE);

  it("carries the CSP nonce on the only script block and has no inline handlers", () => {
    expect(html).toContain(`<script nonce="${NONCE}">`);
    expect(html.match(/<script/g)?.length).toBe(1);
    expect(html).not.toMatch(/on(click|load|error|submit)=/i);
  });

  it("never persists the API key to web storage", () => {
    expect(html).not.toContain("localStorage");
    expect(html).not.toContain("sessionStorage");
  });

  it("renders server-supplied key fields via textContent, not innerHTML", () => {
    expect(html).not.toContain("tbody.innerHTML");
    expect(html).toContain("textContent");
    expect(html).toContain("addEventListener");
  });

  it("wires the formerly-inline controls by id", () => {
    for (const id of ["saveKeyBtn", "screenEntityBtn", "dlpScanBtn", "lookupProposalBtn",
      "voteApproveBtn", "voteRejectBtn", "createKeyBtn", "refreshKeysBtn"]) {
      expect(html).toContain(`id="${id}"`);
      expect(html).toContain(`getElementById("${id}").addEventListener`);
    }
    expect(html).toContain('data-tab="guardrails"');
    expect(html).not.toContain("showTab('guardrails')");
  });
});
