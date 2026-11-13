import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { mkdtemp, mkdir, writeFile, symlink, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { evaluateArguments, SessionGuard } from "../packages/mcp-proxy/src/session-guard";
import { testPolicy } from "../packages/mcp-proxy/src/policy-cli";

describe("operator-owned argument policy", () => {
  let base: string;
  let root: string;
  beforeEach(async () => { base = await mkdtemp(join(tmpdir(), "vizier-policy-")); root = join(base, "project"); await mkdir(root); await mkdir(join(base,"outside")); await writeFile(join(root,"ok.txt"), "ok"); });
  afterEach(async () => { await rm(base, { recursive: true, force: true }); });
  const policy = (root: string) => ({ tools: { write: { arguments: [{ kind: "path" as const, argument: "path", root }] } } });
  it("allows in-root existing/new file and dot segments without rewriting args", async () => {
    for (const path of ["ok.txt", "new.txt", "./ok.txt", root + "/ok.txt"]) expect(await evaluateArguments(policy(root), "write", {path})).toBeNull();
  });
  it.each(["../outside/new.txt", "%2e%2e/outside/new.txt", "/etc/passwd", "../project-evil/file"])("blocks escape %s", async path => {
    expect((await evaluateArguments(policy(root),"write",{path}))?.code).toBe("PATH_OUTSIDE_ROOT");
  });
  it.each(["%252e%252e/file", "ok%00.txt", "..\\escape", "%GG"])("refuses ambiguous %s", async path => {
    expect((await evaluateArguments(policy(root),"write",{path}))?.code).toBe("ARGUMENT_INVALID");
  });
  it("resolves symlinks, including new file through outside directory; refuses dangling links", async () => {
    await symlink(join(base,"outside"), join(root,"link"));
    await mkdir(join(base,"outside","deep"));
    await symlink(join(base,"outside","deep"), join(root,"nested-link"));
    expect((await evaluateArguments(policy(root),"write",{path:"nested-link/../new.txt"}))?.code).toBe("PATH_OUTSIDE_ROOT");
    await symlink(join(base,"missing"), join(root,"dangling"));
    expect((await evaluateArguments(policy(root),"write",{path:"link/new.txt"}))?.code).toBe("PATH_OUTSIDE_ROOT");
    expect((await evaluateArguments(policy(root),"write",{path:"dangling"}))?.code).toBe("PATH_STATE_UNAVAILABLE");
  });
  it("keeps filesystem case; unavailable roots are not a passing security test", async () => {
    expect((await evaluateArguments(policy(root.toUpperCase()),"write",{path:"ok.txt"}))?.code).toBe("PATH_STATE_UNAVAILABLE");
    const report = await testPolicy(policy(join(base,"missing")));
    expect(report.results.some(r => r.outcome === "unverifiable")).toBe(true);
  });
  it("requires configured fields and rejects unknown operator settings", async () => {
    expect((await evaluateArguments(policy(root),"write",{}))?.code).toBe("ARGUMENT_REQUIRED");
    expect(() => new SessionGuard({ tools: { send: { label: "source:private", extra: true } } } as never)).toThrow();
  });
  it("handles URL case, port, punycode; blocks credentials and lookalikes", async () => {
    const p = { tools: { send: { arguments: [{ kind:"url" as const, argument:"url", origins:["https://EXAMPLE.com", "https://bücher.example"] }] } } };
    for (const url of ["https://example.com:443/x", "https://xn--bcher-kva.example/x"]) expect(await evaluateArguments(p,"send",{url})).toBeNull();
    for (const url of ["https://example.com.evil.invalid", "https://example.com@evil.invalid", "https://еxample.com", "javascript:alert(1)"]) expect(await evaluateArguments(p,"send",{url})).not.toBeNull();
  });
  it("runs same evaluator with explicit controls and reports bypasses rather than hiding them", async () => {
    const report = await testPolicy(policy(root));
    expect(report.bypassed).toBe(0);
    expect(report.results.filter(r => r.outcome === "passed_control")).toHaveLength(1);
    const bypass = await testPolicy({ tools: { send: { arguments: [{kind:"url",argument:"url",origins:["https://vizier-policy-attack.invalid"]}] } } });
    expect(bypass.bypassed).toBeGreaterThan(0);
    expect((await testPolicy({})).cases).toBe(0);
  });
});

describe("session taint", () => {
  it("marks before source forwarding; cannot clear by client metadata or config mutation", async () => {
    const policy = {tools:{read:{label:"source:private" as const},send:{label:"sink:external" as const}}};
    const guard = new SessionGuard(policy);
    expect(await guard.check("send",{})).toBeNull();
    guard.beforeForward("read"); policy.tools.send.label = "source:private" as never;
    expect((await guard.check("send",{session_id:"new", label:"none"}))?.code).toBe("TAINT_PRIVATE_TO_EXTERNAL");
    expect(await guard.check("unlabelled",{})).toBeNull(); // Explicit coverage limit.
    expect(await new SessionGuard().check("send",{})).toBeNull(); // Restart is not durable.
  });
});
