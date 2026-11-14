import { VIZIER_CATALOG_EXAMPLE } from "./a2a";
import { firstMcpCheck } from "./onboarding";

export function createPlaygroundHtml(
  origin: string,
  grantMode: "optional" | "required" | "invalid" = "optional",
  publicOrigin = origin,
): string {
  const firstCheck = firstMcpCheck();
  const escapeExample = (text: string) => text.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;");
  const shellQuote = (text: string) => "'" + text.replaceAll("'", "'\"'\"'") + "'";
  const firstCheckCommand = [
    "curl -sS " + shellQuote(publicOrigin + "/mcp"),
    ...Object.entries(firstCheck.headers).map(([name, value]) => "  -H " + shellQuote(name + ": " + value)),
    "  --data-binary " + shellQuote(JSON.stringify(firstCheck.body)),
  ].join(" " + String.fromCharCode(92, 10));
  const firstCheckExpected = grantMode === "required"
    ? "Expected: BLOCK with GRANT_REQUIRED. The fictional purchase is within its declared limit, but the principal has not signed a grant."
    : "This anonymous check evaluates a fictional purchase and cannot grant ALLOW. The result follows the serving grant policy.";
  const grantNotice = grantMode === "required"
    ? "This deployment requires a valid principal-signed delegation grant. Requests without it return BLOCK with GRANT_REQUIRED, including anonymous evaluations and requests within the declared limit. An API key alone does not replace the grant."
    : grantMode === "invalid"
      ? "The deployment's grant policy is misconfigured. Evaluations fail closed; the operator must repair the configuration."
      : "Anonymous caller-supplied authority cannot authorize ALLOW. Other failed checks can produce BLOCK; unresolved authority or risk requires REVIEW.";
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>AI Agent Action Authorization | Vizier</title>
  <meta name="description" content="Evaluate a proposed AI agent action against delegated authority, target rules and spending limits. Connect Vizier over MCP or use the playground.">
  <link rel="canonical" href="${publicOrigin}/">
  <style>
    :root {
      --bg: #f4f6fa;
      --card: #ffffff;
      --border: #e2e8f0;
      --text: #0f172a;
      --muted: #5c6675;
      --accent: #2563eb;
      --accent-hover: #1d4ed8;
      --accent-soft: #eef3fe;
      --allow: #047857;
      --review: #b45309;
      --block: #b91c1c;
      --code-bg: #f8fafc;
      --code-text: #24334d;
      --radius: 12px;
      --shadow: 0 1px 2px rgba(15, 23, 42, 0.05), 0 4px 14px rgba(15, 23, 42, 0.05);
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.55;
      padding: 32px 24px 56px;
      -webkit-font-smoothing: antialiased;
    }
    a { color: var(--accent); text-decoration: none; }
    a:hover { text-decoration: underline; }
    code {
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      background: var(--code-bg);
      border: 1px solid var(--border);
      border-radius: 4px;
      padding: 1px 5px;
      font-size: 0.85em;
    }
    button { font-family: inherit; }
    button:focus-visible, a:focus-visible, textarea:focus-visible, input:focus-visible, summary:focus-visible {
      outline: 2px solid var(--accent);
      outline-offset: 2px;
    }
    .page { max-width: 1180px; margin: 0 auto; }
    .header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 16px;
      border-bottom: 1px solid var(--border);
      padding-bottom: 20px;
      margin-bottom: 20px;
    }
    .logo-group h1 { font-size: 1.5rem; font-weight: 700; letter-spacing: -0.02em; color: var(--text); }
    .logo-group p { font-size: 0.9rem; color: var(--muted); margin-top: 2px; }
    .links { display: flex; flex-wrap: wrap; gap: 4px 20px; }
    .links a { color: var(--muted); font-size: 0.875rem; font-weight: 500; transition: color 0.15s; }
    .links a:hover { color: var(--accent); text-decoration: none; }
    .note { color: var(--muted); font-size: 0.9rem; margin-bottom: 12px; }
    .status { font-size: 0.9rem; color: var(--text); margin-bottom: 16px; }
    .container {
      display: grid;
      grid-template-columns: minmax(0, 1fr) minmax(0, 1fr);
      gap: 20px;
      align-items: start;
    }
    @media (max-width: 900px) { .container { grid-template-columns: minmax(0, 1fr); } }
    .card {
      min-width: 0;
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      box-shadow: var(--shadow);
      padding: 22px;
      display: flex;
      flex-direction: column;
      gap: 16px;
    }
    section.card { margin-bottom: 20px; }
    .card > button, .card > .preset-btn { align-self: flex-start; }
    .card-title {
      font-size: 1.05rem;
      font-weight: 600;
      letter-spacing: -0.01em;
      color: var(--text);
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 8px;
    }
    section.card h2 { font-size: 1.15rem; font-weight: 600; letter-spacing: -0.01em; }
    section.card h3 { font-size: 0.95rem; font-weight: 600; }
    section.card label { font-size: 0.78rem; font-weight: 600; color: var(--muted); text-transform: uppercase; letter-spacing: 0.05em; }
    section.card input[readonly] {
      padding: 9px 12px;
      border: 1px solid var(--border);
      border-radius: 8px;
      background: var(--code-bg);
      color: var(--code-text);
      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
      font-size: 0.85rem;
    }
    section.card details pre {
      background: var(--code-bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 12px;
      margin-top: 8px;
      font-size: 0.8rem;
      color: var(--code-text);
    }
    .presets { display: flex; gap: 8px; flex-wrap: wrap; }
    .preset-btn {
      background: var(--card);
      border: 1px solid var(--border);
      color: var(--text);
      padding: 7px 13px;
      border-radius: 8px;
      font-size: 0.78rem;
      font-weight: 500;
      cursor: pointer;
      transition: background 0.15s, border-color 0.15s, color 0.15s;
    }
    .preset-btn:hover { background: var(--accent-soft); border-color: var(--accent); color: var(--accent-hover); }
    textarea {
      width: 100%;
      height: 380px;
      background: var(--code-bg);
      border: 1px solid var(--border);
      color: var(--code-text);
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 0.85rem;
      line-height: 1.5;
      padding: 14px;
      border-radius: 8px;
      resize: vertical;
    }
    button.primary {
      align-self: flex-start;
      background: var(--accent);
      color: #fff;
      border: none;
      padding: 11px 22px;
      font-weight: 600;
      font-size: 0.9rem;
      border-radius: 8px;
      cursor: pointer;
      box-shadow: 0 1px 2px rgba(37, 99, 235, 0.35);
      transition: background 0.15s, transform 0.05s;
    }
    button.primary:hover { background: var(--accent-hover); }
    button.primary:active { transform: translateY(1px); }
    button.primary:disabled { opacity: 0.6; cursor: default; }
    .decision-badge {
      display: inline-block;
      padding: 8px 18px;
      border-radius: 8px;
      font-weight: 700;
      font-size: 1.25rem;
      letter-spacing: 0.05em;
      text-align: center;
    }
    .badge-ALLOW { background: #ecfdf5; color: var(--allow); border: 1px solid #6ee7b7; }
    .badge-REVIEW { background: #fffbeb; color: var(--review); border: 1px solid #fcd34d; }
    .badge-BLOCK { background: #fef2f2; color: var(--block); border: 1px solid #fca5a5; }
    .badge-IDLE { background: #f1f5f9; color: var(--muted); border: 1px solid var(--border); }
    .output-box {
      background: var(--code-bg);
      border: 1px solid var(--border);
      padding: 14px;
      border-radius: 8px;
      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
      font-size: 0.8rem;
      line-height: 1.5;
      color: var(--code-text);
      overflow-x: auto;
      max-height: 260px;
    }
    .meta-row {
      display: flex;
      justify-content: space-between;
      gap: 8px;
      font-size: 0.85rem;
      color: var(--muted);
    }
    .meta-val { min-width: 0; overflow-wrap: anywhere; color: var(--text); font-weight: 500; text-align: right; }
    @media (max-width: 900px) {
      body { padding: 20px 16px 40px; }
      .header { align-items: flex-start; flex-direction: column; }
    }
    .code-section {
      min-width: 0;
      grid-column: span 2;
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      box-shadow: var(--shadow);
      padding: 22px;
    }
    @media (max-width: 900px) { .code-section { grid-column: span 1; } }
    .tabs { display: flex; flex-wrap: wrap; gap: 6px; border-bottom: 1px solid var(--border); padding-bottom: 12px; margin-bottom: 14px; }
    .tab {
      background: none;
      border: 1px solid transparent;
      color: var(--muted);
      cursor: pointer;
      font-size: 0.85rem;
      font-weight: 500;
      padding: 6px 10px;
      border-radius: 8px;
      transition: color 0.15s, background 0.15s;
    }
    .tab:hover { color: var(--text); }
    .tab.active { color: var(--accent-hover); background: var(--accent-soft); border-color: var(--border); font-weight: 600; }
    .snippet {
      background: var(--code-bg);
      border: 1px solid var(--border);
      padding: 16px;
      border-radius: 8px;
      font-family: ui-monospace, Menlo, monospace;
      font-size: 0.85rem;
      line-height: 1.55;
      color: var(--code-text);
      white-space: pre;
      overflow-x: auto;
    }
  </style>
</head>
<body>
  <div class="page">
  <div class="header">
    <div class="logo-group">
      <h1>Vizier Action Firewall</h1>
      <p>Evaluate a proposed action against delegated authority and policy before execution.</p>
    </div>
    <div class="links">
      <a href="/docs">Docs (JSON)</a>
      <a href="/openapi.json">OpenAPI 3.1</a>
      <a href="/.well-known/agent-card.json">A2A Card</a>
      <a href="/.well-known/mcp.json">MCP Manifest</a>
      <a href="https://github.com/vassiliylakhonin/vizier" target="_blank">GitHub</a>
    </div>
  </div>

  <p class="note"><button type="button" class="preset-btn" onclick="runGrantExample()">Run the missing-grant example</button> · <a href="#action-example">Edit a policy example</a> · <a href="#connect-mcp">Connect MCP</a></p>
  <p id="grant-example-result" class="status" role="status">Expected: BLOCK. The fictional purchase is within its limit but lacks a principal-signed grant.</p>
  <section class="card" id="connect-mcp" aria-labelledby="connect-mcp-title">
    <h2 id="connect-mcp-title">Connect Vizier over MCP</h2>
    <p>Add this HTTPS address to your MCP client using Streamable HTTP.</p>
    <label for="mcp-url">MCP server URL</label>
    <input id="mcp-url" value="${publicOrigin}/mcp" readonly style="display:block;width:100%;max-width:100%;box-sizing:border-box" onclick="this.select()">
    <button type="button" class="preset-btn" onclick="copyMcpUrl()">Copy MCP URL</button> <span id="mcp-copy-status" role="status"></span>
    <p>Main tool <code>vizier_verify_action</code>. <a href="https://github.com/vassiliylakhonin/vizier/blob/main/docs/AUTHORIZATION_QUICKSTART.md">Connection and request example</a> · <a href="${publicOrigin}/.well-known/agent-card.json">A2A agent card</a> · <a href="${publicOrigin}/openapi.json">OpenAPI</a></p>
    <h3>First MCP check</h3>
    <p>Run one synthetic purchase check after connecting. ${firstCheckExpected}</p>
    <button type="button" class="preset-btn" id="first-mcp-run" onclick="runFirstMcpCheck()">Run synthetic MCP check</button>
    <p id="first-mcp-result" role="status"></p>
    <details><summary>Copy the complete stateless MCP command</summary><pre id="first-mcp-command" style="overflow:auto">${escapeExample(firstCheckCommand)}</pre>
      <p>For an initialized session client, copy only the arguments below into <code>vizier_verify_action</code>. The client supplies its session headers.</p>
      <pre style="overflow:auto">${escapeExample(JSON.stringify(firstCheck.body.params.arguments, null, 2))}</pre>
    </details>
  </section>
  <p class="note">Evaluation playground: caller-supplied authority is unverified. ${grantNotice} No external action is executed. Trusted enforcement requires an authenticated integration and server-side policy.</p>
  <p class="note">The examples compare proposed purchases with declared spending limits and allowed targets.</p>
  <div class="container" id="action-example">
    <!-- Left: Request Simulator -->
    <div class="card">
      <div class="card-title">
        <span>Proposed Action Simulator</span>
      </div>
      <div class="presets">
        <button class="preset-btn" onclick="loadPreset('allow')">🟡 Evaluate: Purchase $820</button>
        <button class="preset-btn" onclick="loadPreset('block_amount')">🔴 Block: Exceeds Limit ($12,000)</button>
        <button class="preset-btn" onclick="loadPreset('block_target')">🔴 Block: Target Denied</button>
        <button class="preset-btn" onclick="loadPreset('review_sensitive')">🟡 Evaluate: Deploy Worker</button>
      </div>
      <div style="display: flex; gap: 8px; align-items: center; background: var(--code-bg); padding: 8px 12px; border-radius: 8px; border: 1px solid var(--border);">
        <input id="apiKeyInput" type="password" placeholder="Optional vz_live_... or master key (in-memory only; evaluates freely if empty)" style="flex: 1; background: transparent; border: none; color: var(--code-text); font-size: 0.75rem; font-family: monospace; outline: none;" autocomplete="off" />
      </div>
      <textarea id="requestJson" spellcheck="false"></textarea>
      <button class="primary" id="verifyBtn" onclick="runVerification()">⚡ Verify Action via Kernel</button>
    </div>

    <!-- Right: Decision & Receipt -->
    <div class="card">
      <div class="card-title">
        <span>Deterministic Decision & Audit</span>
        <span id="latencyBadge" style="font-size: 0.75rem; color: var(--muted);">Latency: --</span>
      </div>
      <div>
        <div id="decisionBadge" class="decision-badge badge-IDLE">READY</div>
      </div>
      <div class="meta-row">
        <span>Explanation:</span>
        <span id="explanationText" class="meta-val">Select a preset or edit JSON and verify.</span>
      </div>
      <div class="meta-row">
        <span>Reason Codes:</span>
        <span id="reasonCodes" class="meta-val">[]</span>
      </div>
      <div class="meta-row">
        <span>Next step:</span>
        <span id="nextStep" class="meta-val">Inspect the returned policy checks. A demo never executes the action.</span>
      </div>
      <a href="https://github.com/vassiliylakhonin/vizier/blob/main/docs/DELEGATION_GRANTS.md">How principal-signed delegation grants work</a>
      <div class="meta-row">
        <span>Receipt Hash (SHA-256):</span>
        <span id="receiptHash" class="meta-val" style="font-family: monospace; font-size: 0.75rem;">--</span>
      </div>
      <div style="font-size: 0.8rem; font-weight: 600; color: var(--text); margin-top: 6px;">Evaluated Policies & Raw Response:</div>
      <pre id="rawResponse" class="output-box">// Response will render here</pre>
    </div>

    <!-- Bottom: Integrations -->
    <div class="code-section">
      <div class="tabs">
        <button class="tab active" onclick="showSnippet('python')">Python (@vizier_guard)</button>
        <button class="tab" onclick="showSnippet('langchain')">LangChain Tool Guard</button>
        <button class="tab" onclick="showSnippet('mcp')">MCP Enforcement Proxy</button>
        <button class="tab" onclick="showSnippet('curl')">cURL</button>
      </div>
      <div id="snippetBox" class="snippet"></div>
    </div>
  </div>
  </div>

  <script>
    async function runFirstMcpCheck() {
      const button = document.getElementById('first-mcp-run');
      const status = document.getElementById('first-mcp-result');
      button.disabled = true;
      status.textContent = 'Running the synthetic MCP check…';
      try {
        const sample = ${JSON.stringify(firstCheck)};
        const response = await fetch('/mcp', {method: 'POST', credentials: 'omit',
          headers: sample.headers, body: JSON.stringify(sample.body)});
        const data = (await response.json())?.result?.structuredContent;
        if (!response.ok || !['BLOCK', 'REVIEW'].includes(data?.decision)) throw new Error('Unexpected result');
        status.textContent = data.decision + (data.reason_codes?.includes('GRANT_REQUIRED')
          ? ' / GRANT_REQUIRED. The principal has not signed a delegation grant.' : '. The action needs further review.');
      } catch {
        status.textContent = 'The MCP example could not complete. Inspect the command and connection guide before retrying.';
      } finally {
        button.disabled = false;
      }
    }

    async function runGrantExample() {
      const status = document.getElementById('grant-example-result');
      status.textContent = 'Evaluating the fictional purchase…';
      try {
        const id = crypto.randomUUID();
        const response = await fetch('/a2a', {
          method: 'POST', credentials: 'omit',
          headers: {'Content-Type': 'application/json', 'A2A-Version': '1.0'},
          body: JSON.stringify({jsonrpc: '2.0', id, method: 'SendMessage', params: {
            message: {messageId: id, role: 'ROLE_USER', parts: [{text: ${JSON.stringify(VIZIER_CATALOG_EXAMPLE)}}]}
          }})
        });
        const data = (await response.json())?.result?.task?.artifacts?.[0]?.parts?.[0]?.data;
        if (!response.ok || data?.decision !== 'BLOCK' || !data.reason_codes?.includes('GRANT_REQUIRED')) throw new Error('Example did not return the expected block');
        status.textContent = 'BLOCK — the purchase is within its declared limit, but the principal did not sign a delegation grant. This example authorizes nothing.';
      } catch {
        status.textContent = 'The example could not be completed. You can still inspect the structured request in the A2A card.';
      }
    }

    async function copyMcpUrl() {
      const input = document.getElementById('mcp-url');
      const status = document.getElementById('mcp-copy-status');
      try {
        await navigator.clipboard.writeText(input.value);
        status.textContent = 'MCP URL copied.';
      } catch {
        input.focus();
        input.select();
        status.textContent = 'Copy the selected address.';
      }
    }
    const presets = {
      allow: {
        agent: { id: "procurement-agent-01", owner: "acme-corp" },
        principal: { id: "acme-corp" },
        action: {
          type: "purchase",
          target: "supplier.example",
          parameters: { amount: 820, currency: "USD" }
        },
        authority: {
          allowed_actions: ["purchase"],
          constraints: { max_amount: 1000, currency: "USD", allowed_targets: ["supplier.example"] }
        },
        context: { request_id: "order-101", timestamp: new Date().toISOString(), source: "rest" }
      },
      block_amount: {
        agent: { id: "procurement-agent-01", owner: "acme-corp" },
        principal: { id: "acme-corp" },
        action: {
          type: "purchase",
          target: "supplier.example",
          parameters: { amount: 12000, currency: "USD" }
        },
        authority: {
          allowed_actions: ["purchase"],
          constraints: { max_amount: 1000, currency: "USD" }
        },
        context: { request_id: "order-102", timestamp: new Date().toISOString(), source: "rest" }
      },
      block_target: {
        agent: { id: "procurement-agent-01", owner: "acme-corp" },
        principal: { id: "acme-corp" },
        action: {
          type: "transfer_funds",
          target: "untrusted-crypto-drainer.eth",
          parameters: { amount: 50, currency: "USD" }
        },
        authority: {
          allowed_actions: ["transfer_funds"],
          constraints: { blocked_targets: ["untrusted-crypto-drainer.eth"] }
        },
        context: { request_id: "tx-201", timestamp: new Date().toISOString(), source: "rest" }
      },
      review_sensitive: {
        agent: { id: "devops-agent-01", owner: "acme-corp" },
        principal: { id: "acme-corp" },
        action: {
          type: "deploy_worker",
          target: "worker:auth-service",
          parameters: { git_commit: "9f8a32b" }
        },
        authority: {
          allowed_actions: ["deploy_worker"],
          constraints: {}
        },
        context: { request_id: "dep-301", timestamp: new Date().toISOString(), source: "rest" }
      }
    };

    function loadPreset(name) {
      document.getElementById('requestJson').value = JSON.stringify(presets[name], null, 2);
    }

    async function runVerification() {
      const btn = document.getElementById('verifyBtn');
      const badge = document.getElementById('decisionBadge');
      const latency = document.getElementById('latencyBadge');
      const explanation = document.getElementById('explanationText');
      const reasons = document.getElementById('reasonCodes');
      const receiptHash = document.getElementById('receiptHash');
      const raw = document.getElementById('rawResponse');
      const nextStep = document.getElementById('nextStep');

      let parsed;
      try {
        parsed = JSON.parse(document.getElementById('requestJson').value);
      } catch (err) {
        alert("Invalid JSON: " + err.message);
        return;
      }

      btn.disabled = true;
      btn.innerText = "Evaluating...";
      badge.className = 'decision-badge badge-IDLE';
      badge.innerText = 'EVALUATING';
      reasons.innerText = '[]';
      receiptHash.innerText = '--';
      nextStep.innerText = 'Waiting for this evaluation.';
      const t0 = performance.now();

      const apiKey = (document.getElementById('apiKeyInput')?.value || '').trim();
      const endpoint = apiKey ? '${origin}/v1/verify' : '${origin}/v1/verify/evaluate';
      const headers = { 'Content-Type': 'application/json' };
      if (apiKey) {
        headers['Authorization'] = 'Bearer ' + apiKey;
      }

      try {
        const res = await fetch(endpoint, {
          method: 'POST',
          headers: headers,
          body: JSON.stringify(parsed)
        });
        const elapsed = (performance.now() - t0).toFixed(1);
        latency.innerText = 'Latency: ' + elapsed + 'ms';

        const data = await res.json();
        raw.innerText = JSON.stringify(data, null, 2);

        if (data.decision) {
          badge.className = 'decision-badge badge-' + data.decision;
          badge.innerText = data.decision;
          explanation.innerText = data.explanation || '--';
          reasons.innerText = JSON.stringify(data.reason_codes || []);
          nextStep.innerText = (data.reason_codes || []).includes('GRANT_REQUIRED')
            ? 'Ask the principal to sign the exact agent and authority, register their public key with the operator, and include the compact JWS as grant. Do not paste private signing keys. Other failed checks must also be resolved.'
            : 'Inspect failed or unresolved policy checks with the action owner before any execution. This playground does not execute or authorize an external action.';
          receiptHash.innerText = data.receipt?.request_hash || '--';
        } else if (data.error) {
          badge.className = 'decision-badge badge-BLOCK';
          badge.innerText = data.error.code || 'ERROR';
          explanation.innerText = data.error.message || 'Request failed';
          reasons.innerText = JSON.stringify(data.error.details || []);
          receiptHash.innerText = '--';
          nextStep.innerText = 'Correct the reported request or service error and evaluate again.';
        }
      } catch (err) {
        badge.className = 'decision-badge badge-BLOCK';
        badge.innerText = 'ERROR';
        explanation.innerText = err.message;
        raw.innerText = err.stack || err.message;
        nextStep.innerText = 'The evaluation did not complete. Resolve the connection or request error before retrying.';
      } finally {
        btn.disabled = false;
        btn.innerText = "⚡ Verify Action via Kernel";
      }
    }

    const snippets = {
      python: \`from vizier import VizierClient, vizier_guard

client = VizierClient(
    base_url="${origin}",
    api_key="vz_live_your_key_here"  # Get from admin /v1/admin/keys
)

@vizier_guard(client=client, action_type="purchase", target="supplier.example")
def execute_order(amount: float, supplier: str):
    return {"status": "success", "amount": amount}\`,

      langchain: \`from vizier import VizierClient
from vizier.integrations.langchain import create_guarded_tool
from langchain_core.tools import tool

client = VizierClient(base_url="${origin}", api_key="vz_live_...")

@tool
def transfer_funds(amount: float, recipient: str) -> str:
    """Transfer funds to recipient."""
    return f"Transferred {amount} to {recipient}"

guarded_tool = create_guarded_tool(
    tool=transfer_funds,
    client=client,
    action_type="transfer_funds",
    target="bank_api"
)\`,

      mcp: \`# Run the HTTP MCP enforcement proxy (Node 24+)
npx @agenda-intelligence/vizier-mcp-proxy \\\\
  --upstream "http://localhost:3000/mcp" \\\\
  --tools "query_db" \\\\
  --vizier "${origin}" \\\\
  --grant-mode required --grant-file /operator/grant.jws
# Set VIZIER_API_KEY in the executor environment before running.\`,

      curl: \`curl -X POST ${origin}/v1/verify \\\\
  -H "Content-Type: application/json" \\\\
  -H "Authorization: Bearer YOUR_KEY" \\\\
  -d '{
    "agent": { "id": "agent-1", "owner": "corp" },
    "principal": { "id": "corp" },
    "action": {
      "type": "purchase",
      "target": "supplier.example",
      "parameters": { "amount": 820, "currency": "USD" }
    },
    "authority": {
      "allowed_actions": ["purchase"],
      "constraints": { "max_amount": 1000, "currency": "USD" }
    },
    "context": { "source": "rest" }
  }'\`
    };

    function showSnippet(type) {
      document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
      event.target.classList.add('active');
      document.getElementById('snippetBox').innerText = snippets[type];
    }

    // Init
    loadPreset('allow');
    document.getElementById('snippetBox').innerText = snippets.python;
  </script>
</body>
</html>`;
}
