#!/usr/bin/env node
import { realpathSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { readFile } from "node:fs/promises";
import { evaluateArguments, guardPolicySchema } from "./session-guard.js";
import { explainDecision, formatExplanation } from "./explain.js";

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
async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) chunks.push(Buffer.from(chunk as Uint8Array));
  return Buffer.concat(chunks).toString("utf8");
}

async function runExplain(args: string[]): Promise<void> {
  const json = args.includes("--json");
  const rest = args.filter(arg => arg !== "--json");
  const codeFlag = rest.indexOf("--code");
  let input: unknown;
  try {
    if (codeFlag >= 0) input = (rest[codeFlag + 1] ?? "").split(",").map(code => code.trim()).filter(Boolean);
    else if (rest[0] === "-") input = JSON.parse(await readStdin());
    else if (rest[0]) input = JSON.parse(await readFile(rest[0], "utf8"));
    else throw new Error("usage");
  } catch {
    console.error("Usage: vizier explain <response.json | -> [--json]\n       vizier explain --code CODE[,CODE] [--json]"); process.exitCode = 2; return;
  }
  const report = explainDecision(input);
  console.log(json ? JSON.stringify(report, null, 2) : formatExplanation(report));
  if (report.unknown_codes.length > 0) process.exitCode = 1;
}

if (process.argv[1] && import.meta.url === pathToFileURL(realpathSync(process.argv[1])).href) {
  if (process.argv[2] === "explain") {
    await runExplain(process.argv.slice(3));
  } else if (process.argv[2] !== "test-policy" || !process.argv[3]) {
    console.error("Usage: vizier test-policy <operator-policy.json>\n       vizier explain <response.json | -> | --code CODE[,CODE]"); process.exitCode = 2;
  } else {
    try {
      const report = await testPolicy(JSON.parse(await readFile(process.argv[3], "utf8")));
      console.log(JSON.stringify(report, null, 2));
      if (report.cases === 0 || report.bypassed > 0 || report.results.some(r => ["false_alarm", "unverifiable"].includes(r.outcome))) process.exitCode = 1;
    } catch { console.error("Invalid or unavailable policy file."); process.exitCode = 2; }
  }
}
