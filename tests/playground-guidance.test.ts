import { describe, expect, it } from "vitest";
import { handleHttpRequest } from "../src/transport/http";
import vm from "node:vm";

describe("playground guidance in required grant mode", () => {
  it("initializes the editable preset and integration snippet without browser errors", async () => {
    const html = await (await handleHttpRequest(new Request("https://vizier.example/playground"))).text();
    const elements = Object.fromEntries(["requestJson", "snippetBox"].map(id => [id, {value:"",innerText:""}]));
    const context = {document:{getElementById:(id:string) => elements[id]}};
    // The trusted renderer emits exactly one inline script. This extracts that
    // fixture for execution; it is not an HTML sanitizer or an untrusted parser.
    const start = html.indexOf("<script>");
    const end = html.indexOf("</script>", start);
    expect(start).toBeGreaterThan(-1);
    expect(end).toBeGreaterThan(start);
    expect(html.indexOf("<script>", start + 8)).toBe(-1);
    vm.runInNewContext(html.slice(start + 8, end), context);
    expect(JSON.parse(elements.requestJson!.value).action.parameters.amount).toBe(820);
    expect(elements.snippetBox!.innerText).toContain("VizierClient");
  });
  it("does not promise REVIEW and explains a missing grant without weakening BLOCK", async () => {
    const htmlResponse = await handleHttpRequest(new Request("https://vizier.example/playground"), {signedGrantModeSource:"required"});
    const html = await htmlResponse.text();
    expect(html).not.toContain("produces REVIEW");
    expect(html).toContain("GRANT_REQUIRED");
    const response = await handleHttpRequest(new Request("https://vizier.example/v1/verify/evaluate", {
      method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({
        agent:{id:"synthetic-agent",owner:"synthetic-owner"},principal:{id:"synthetic-owner"},
        action:{type:"purchase",target:"supplier.example",parameters:{amount:150,currency:"USD"}},
        authority:{allowed_actions:["purchase"],constraints:{max_amount:1000,currency:"USD"}},
        context:{source:"rest",request_id:"synthetic-playground",timestamp:"2026-10-09T13:18:05Z"}
      })
    }), {signedGrantModeSource:"required"});
    expect(response.status).toBe(200);
    const result = await response.json() as {decision:string;reason_codes:string[];explanation:string};
    expect(result.decision).toBe("BLOCK");
    expect(result.reason_codes).toContain("GRANT_REQUIRED");
    expect(result.explanation).toContain("principal-signed delegation grant");
  });
});
