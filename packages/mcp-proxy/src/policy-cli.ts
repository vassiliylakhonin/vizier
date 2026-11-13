#!/usr/bin/env node
import { realpathSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { readFile } from "node:fs/promises";
import { evaluateArguments, guardPolicySchema } from "./session-guard.js";

export async function testPolicy(input: unknown) {
  const policy = guardPolicySchema.parse(input);
  const results: { tool: string; argument: string; case: string; expected: string; outcome: string; code: string | null }[] = [];
  for (const [tool, config] of Object.entries(policy.tools)) {
    // Only one rule at a time, to avoid a missing second field hiding a bypass.
    for (const rule of config.arguments) {
      const attacks = rule.kind === "path" ? [
        ["traversal", "../../etc/passwd"], ["encoded-traversal", "%2e%2e/%2e%2e/etc/passwd"],
        ["double-encoding", "%252e%252e/etc/passwd"], ["absolute-outside", "/etc/passwd"],
        ["windows-separators", "..\\..\\etc\\passwd"], ["nul", "safe%00file"],
      ] : [
        ["external-origin", "https://vizier-policy-attack.invalid/data"],
        ["userinfo-confusion", "https://approved.example@vizier-policy-attack.invalid/data"],
        ["javascript-scheme", "javascript:alert(1)"],
        ["unicode-host", "https://аpproved.example/data"],
        ["double-encoding", "https://%2561pproved.example/data"],
      ];
      const control = rule.kind === "path" ? "vizier-safe-control.txt" : new URL("/control", rule.origins[0]).href;
      const cases = [...attacks.map(([name, value]) => [name!, value!, "block"]), ["control", control, "allow"]];
      for (const [name, value, expected] of cases) {
        const failure = await evaluateArguments({ tools: { [tool]: { arguments: [rule] } } }, tool, { [rule.argument]: value! });
        results.push({ tool, argument: rule.argument, case: name!, expected: expected!,
          outcome: failure?.code === "PATH_STATE_UNAVAILABLE" ? "unverifiable" : expected === "allow" ? (failure ? "false_alarm" : "passed_control") : (failure ? "blocked" : "bypassed"), code: failure?.code ?? null });
      }
    }
  }
  return { evaluation_only: true, cases: results.length, blocked: results.filter(r => r.outcome === "blocked").length,
    bypassed: results.filter(r => r.outcome === "bypassed").length, results,
    not_assessed: ["unconfigured tools/arguments", "live executor behavior", "symlink resolution (requires local fixtures, covered in tests)", "symlink races", "SQL/shell semantics", "loop/taint integration (covered by tests, not this static suite)"],
    warning: "Synthetic local probes, not a security certification. An unavailable root can block every probe without proving containment." };
}
if (process.argv[1] && import.meta.url === pathToFileURL(realpathSync(process.argv[1])).href) {
  if (process.argv[2] !== "test-policy" || !process.argv[3]) {
    console.error("Usage: vizier test-policy <operator-policy.json>"); process.exitCode = 2;
  } else {
    try {
      const report = await testPolicy(JSON.parse(await readFile(process.argv[3], "utf8")));
      console.log(JSON.stringify(report, null, 2));
      if (report.cases === 0 || report.bypassed > 0 || report.results.some(r => ["false_alarm", "unverifiable"].includes(r.outcome))) process.exitCode = 1;
    } catch { console.error("Invalid or unavailable policy file."); process.exitCode = 2; }
  }
}
