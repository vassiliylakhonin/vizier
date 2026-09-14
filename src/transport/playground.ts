export function createPlaygroundHtml(origin: string): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Vizier — Deterministic AI Agent Authorization Playground</title>
  <style>
    :root {
      --bg: #090d16;
      --card: #111827;
      --border: #1f293d;
      --text: #f3f4f6;
      --muted: #9ca3af;
      --accent: #3b82f6;
      --accent-hover: #2563eb;
      --allow: #10b981;
      --review: #f59e0b;
      --block: #ef4444;
      --code-bg: #030712;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.5;
      padding: 24px;
    }
    .header {
      max-width: 1200px;
      margin: 0 auto 24px auto;
      display: flex;
      justify-content: space-between;
      align-items: center;
      border-bottom: 1px solid var(--border);
      padding-bottom: 16px;
    }
    .logo-group h1 { font-size: 1.5rem; font-weight: 700; color: #fff; }
    .logo-group p { font-size: 0.875rem; color: var(--muted); }
    .links a {
      color: var(--muted);
      text-decoration: none;
      font-size: 0.875rem;
      margin-left: 16px;
      transition: color 0.2s;
    }
    .links a:hover { color: var(--accent); }
    .container {
      max-width: 1200px;
      margin: 0 auto;
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 24px;
    }
    @media (max-width: 900px) { .container { grid-template-columns: 1fr; } }
    .card {
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 20px;
      display: flex;
      flex-direction: column;
      gap: 16px;
    }
    .card-title {
      font-size: 1rem;
      font-weight: 600;
      color: #fff;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    .presets {
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
    }
    .preset-btn {
      background: #1f2937;
      border: 1px solid var(--border);
      color: var(--text);
      padding: 6px 12px;
      border-radius: 4px;
      font-size: 0.75rem;
      cursor: pointer;
      transition: all 0.2s;
    }
    .preset-btn:hover { background: #374151; border-color: var(--muted); }
    textarea {
      width: 100%;
      height: 380px;
      background: var(--code-bg);
      border: 1px solid var(--border);
      color: #38bdf8;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 0.85rem;
      padding: 12px;
      border-radius: 6px;
      resize: vertical;
    }
    button.primary {
      background: var(--accent);
      color: #fff;
      border: none;
      padding: 10px 18px;
      font-weight: 600;
      font-size: 0.875rem;
      border-radius: 6px;
      cursor: pointer;
      transition: background 0.2s;
    }
    button.primary:hover { background: var(--accent-hover); }
    .decision-badge {
      display: inline-block;
      padding: 8px 16px;
      border-radius: 6px;
      font-weight: 700;
      font-size: 1.25rem;
      letter-spacing: 0.05em;
      text-align: center;
    }
    .badge-ALLOW { background: rgba(16, 185, 129, 0.15); color: var(--allow); border: 1px solid var(--allow); }
    .badge-REVIEW { background: rgba(245, 158, 11, 0.15); color: var(--review); border: 1px solid var(--review); }
    .badge-BLOCK { background: rgba(239, 68, 68, 0.15); color: var(--block); border: 1px solid var(--block); }
    .badge-IDLE { background: #1f2937; color: var(--muted); border: 1px solid var(--border); }
    .output-box {
      background: var(--code-bg);
      border: 1px solid var(--border);
      padding: 12px;
      border-radius: 6px;
      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
      font-size: 0.8rem;
      color: #e5e7eb;
      overflow-x: auto;
      max-height: 250px;
    }
    .meta-row {
      display: flex;
      justify-content: space-between;
      font-size: 0.8rem;
      color: var(--muted);
    }
    .meta-val { color: #fff; font-weight: 500; }
    .code-section {
      grid-column: span 2;
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 20px;
    }
    @media (max-width: 900px) { .code-section { grid-column: span 1; } }
    .tabs { display: flex; gap: 8px; border-bottom: 1px solid var(--border); padding-bottom: 10px; margin-bottom: 14px; }
    .tab {
      background: none;
      border: none;
      color: var(--muted);
      cursor: pointer;
      font-size: 0.875rem;
      padding: 4px 8px;
      border-radius: 4px;
    }
    .tab.active { color: #fff; background: #1f2937; font-weight: 600; }
    .snippet {
      background: var(--code-bg);
      border: 1px solid var(--border);
      padding: 14px;
      border-radius: 6px;
      font-family: ui-monospace, Menlo, monospace;
      font-size: 0.85rem;
      color: #93c5fd;
      white-space: pre;
      overflow-x: auto;
    }
  </style>
</head>
<body>
  <div class="header">
    <div class="logo-group">
      <h1>Vizier Action Firewall</h1>
      <p>Deterministic authorization before an AI agent causes an external side-effect</p>
    </div>
    <div class="links">
      <a href="/docs">Docs (JSON)</a>
      <a href="/openapi.json">OpenAPI 3.1</a>
      <a href="/.well-known/agent-card.json">A2A Card</a>
      <a href="/.well-known/mcp.json">MCP Manifest</a>
      <a href="https://github.com/vassiliylakhonin/vizier" target="_blank">GitHub</a>
    </div>
  </div>

  <div class="container">
    <!-- Left: Request Simulator -->
    <div class="card">
      <div class="card-title">
        <span>Proposed Action Simulator</span>
      </div>
      <div class="presets">
        <button class="preset-btn" onclick="loadPreset('allow')">🟢 Allow: Purchase $820</button>
        <button class="preset-btn" onclick="loadPreset('block_amount')">🔴 Block: Exceeds Limit ($12,000)</button>
        <button class="preset-btn" onclick="loadPreset('block_target')">🔴 Block: Target Denied</button>
        <button class="preset-btn" onclick="loadPreset('review_sensitive')">🟡 Review: Deploy Worker</button>
      </div>
      <div style="display: flex; gap: 8px; align-items: center; background: #111827; padding: 6px 10px; border-radius: 6px; border: 1px solid var(--border);">
        <input id="apiKeyInput" type="password" placeholder="Optional vz_live_... or master key (in-memory only; evaluates freely if empty)" style="flex: 1; background: transparent; border: none; color: #38bdf8; font-size: 0.75rem; font-family: monospace; outline: none;" autocomplete="off" />
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
        <span>Receipt Hash (SHA-256):</span>
        <span id="receiptHash" class="meta-val" style="font-family: monospace; font-size: 0.75rem;">--</span>
      </div>
      <div style="font-size: 0.8rem; font-weight: 600; color: #fff; margin-top: 6px;">Evaluated Policies & Raw Response:</div>
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

  <script>
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

      let parsed;
      try {
        parsed = JSON.parse(document.getElementById('requestJson').value);
      } catch (err) {
        alert("Invalid JSON: " + err.message);
        return;
      }

      btn.disabled = true;
      btn.innerText = "Evaluating...";
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
          receiptHash.innerText = data.receipt?.request_hash || '--';
        } else if (data.error) {
          badge.className = 'decision-badge badge-BLOCK';
          badge.innerText = data.error.code || 'ERROR';
          explanation.innerText = data.error.message || 'Request failed';
          reasons.innerText = JSON.stringify(data.error.details || []);
          receiptHash.innerText = '--';
        }
      } catch (err) {
        badge.className = 'decision-badge badge-BLOCK';
        badge.innerText = 'ERROR';
        explanation.innerText = err.message;
        raw.innerText = err.stack || err.message;
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
    return f"Transferred \${amount} to {recipient}"

guarded_tool = create_guarded_tool(
    tool=transfer_funds,
    client=client,
    action_type="transfer_funds",
    target="bank_api"
)\`,

      mcp: \`# Run local MCP stdio enforcement proxy
npx @vizier/mcp-proxy \\\\
  --upstream-command "python" \\\\
  --upstream-args "server.py" \\\\
  --vizier-url "${origin}" \\\\
  --vizier-key "vz_live_your_key"\`,

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
