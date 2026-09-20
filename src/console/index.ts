export function createConsoleHtml(origin: string): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Vizier Security Console — AI Agent Governance & Guardrails</title>
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
      max-width: 1280px;
      margin: 0 auto 24px auto;
      display: flex;
      justify-content: space-between;
      align-items: center;
      border-bottom: 1px solid var(--border);
      padding-bottom: 16px;
      flex-wrap: wrap;
      gap: 16px;
    }
    .logo-group h1 { font-size: 1.5rem; font-weight: 700; color: #fff; display: flex; align-items: center; gap: 8px; }
    .badge {
      font-size: 0.75rem;
      padding: 2px 8px;
      border-radius: 9999px;
      font-weight: 600;
      background: rgba(59, 130, 246, 0.2);
      color: #60a5fa;
      border: 1px solid rgba(59, 130, 246, 0.4);
    }
    .badge.live {
      background: rgba(16, 185, 129, 0.2);
      color: #34d399;
      border-color: rgba(16, 185, 129, 0.4);
    }
    .nav-tabs {
      display: flex;
      gap: 8px;
      margin-bottom: 24px;
      max-width: 1280px;
      margin-left: auto;
      margin-right: auto;
      border-bottom: 1px solid var(--border);
      padding-bottom: 8px;
    }
    .tab-btn {
      background: transparent;
      border: none;
      color: var(--muted);
      font-size: 0.9rem;
      font-weight: 600;
      padding: 8px 16px;
      border-radius: 6px;
      cursor: pointer;
      transition: all 0.2s;
    }
    .tab-btn:hover { color: #fff; background: rgba(255, 255, 255, 0.05); }
    .tab-btn.active { color: #fff; background: var(--border); }
    .main-grid {
      max-width: 1280px;
      margin: 0 auto;
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 24px;
    }
    @media (max-width: 900px) { .main-grid { grid-template-columns: 1fr; } }
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
      font-size: 1.1rem;
      font-weight: 600;
      color: #fff;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    label { font-size: 0.85rem; color: var(--muted); display: block; margin-bottom: 4px; }
    input, textarea, select {
      width: 100%;
      background: var(--code-bg);
      border: 1px solid var(--border);
      color: var(--text);
      padding: 8px 12px;
      border-radius: 6px;
      font-size: 0.875rem;
      font-family: inherit;
    }
    input:focus, textarea:focus, select:focus {
      outline: none;
      border-color: var(--accent);
    }
    .btn {
      background: var(--accent);
      color: #fff;
      border: none;
      border-radius: 6px;
      padding: 8px 16px;
      font-size: 0.875rem;
      font-weight: 600;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
      transition: background 0.2s;
    }
    .btn:hover { background: var(--accent-hover); }
    .btn.danger { background: var(--block); }
    .btn.danger:hover { background: #dc2626; }
    .btn.success { background: var(--allow); }
    .btn.success:hover { background: #059669; }
    .btn.secondary { background: var(--border); color: var(--text); }
    .btn.secondary:hover { background: #374151; }
    .output-box {
      background: var(--code-bg);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 12px;
      font-family: monospace;
      font-size: 0.85rem;
      max-height: 280px;
      overflow-y: auto;
      white-space: pre-wrap;
      word-break: break-all;
    }
    .status-pill {
      font-weight: 700;
      padding: 2px 6px;
      border-radius: 4px;
      font-size: 0.75rem;
    }
    .status-ALLOW { background: rgba(16, 185, 129, 0.2); color: var(--allow); }
    .status-BLOCK { background: rgba(239, 68, 68, 0.2); color: var(--block); }
    .status-REVIEW { background: rgba(245, 158, 11, 0.2); color: var(--review); }
    .tab-content { display: none; }
    .tab-content.active { display: block; }
    table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
    th, td { text-align: left; padding: 8px; border-bottom: 1px solid var(--border); }
    th { color: var(--muted); font-weight: 600; }
  </style>
</head>
<body>
  <div class="header">
    <div class="logo-group">
      <h1>🛡️ Vizier Security Console <span class="badge live">Edge Active</span></h1>
      <p style="font-size: 0.85rem; color: var(--muted);">Zero-Trust Governance Kernel for Autonomous AI Agents</p>
    </div>
    <div style="display: flex; gap: 8px; align-items: center;">
      <input id="apiKeyInput" type="password" placeholder="Master or Tenant API Key" style="width: 260px;" />
      <button class="btn secondary" onclick="saveKey()">Set Key</button>
    </div>
  </div>

  <p><a href="/reviews" style="color:inherit">Human review queue →</a></p>
  <div class="nav-tabs">
    <button class="tab-btn active" onclick="showTab('guardrails')">Guardrails Simulator</button>
    <button class="tab-btn" onclick="showTab('quorum')">HITL Quorum Gate (4-Eyes)</button>
    <button class="tab-btn" onclick="showTab('keys')">API Keys & Quotas</button>
    <button class="tab-btn" onclick="showTab('proxy')">Transparent AI Proxy</button>
  </div>

  <!-- TAB 1: Guardrails Simulator -->
  <div id="tab-guardrails" class="tab-content active">
    <div class="main-grid">
      <!-- OFAC 50% Rule Sandbox -->
      <div class="card">
        <div class="card-title">
          <span>🏛️ OFAC 50% Rule & Ownership Graph</span>
          <span class="badge">E.O. 14024</span>
        </div>
        <p style="font-size: 0.85rem; color: var(--muted);">
          Evaluate aggregated beneficial ownership across holding structures. Auto-blocks entities if blocked shareholder percentage &ge; 50%.
        </p>
        <div>
          <label>Target Entity Name</label>
          <input id="entityName" value="Caspian Trade Consortium LLP" />
        </div>
        <div>
          <label>Shareholders JSON (with % stakes)</label>
          <textarea id="shareholdersJson" rows="5">{
  "shareholders": [
    { "name": "Garantex Europe", "percentage": 30.0 },
    { "name": "Tornado Cash", "percentage": 25.0 },
    { "name": "Independent Founder", "percentage": 45.0 }
  ]
}</textarea>
        </div>
        <button class="btn" onclick="runSanctions50Screen()">Screen Entity</button>
        <div>
          <label>Evaluation Output</label>
          <div id="sanctionsOutput" class="output-box">// Results will appear here</div>
        </div>
      </div>

      <!-- DLP Secret Leak Firewall -->
      <div class="card">
        <div class="card-title">
          <span>🔒 DLP Secret Leak Firewall</span>
          <span class="badge">Zero-Egress</span>
        </div>
        <p style="font-size: 0.85rem; color: var(--muted);">
          Scan prompt text or tool arguments for private keys, AWS/OpenAI tokens, credit cards, or high-entropy credentials.
        </p>
        <div>
          <label>Payload / Text to Scan</label>
          <textarea id="dlpInput" rows="5">Please summarize this config:
API_KEY = "sk-proj-1234567890abcdef1234567890abcdef1234567890"
Card = "4111-2222-3333-4444"</textarea>
        </div>
        <button class="btn" onclick="runDlpScan()">Scan for Leaks</button>
        <div>
          <label>DLP Firewall Result</label>
          <div id="dlpOutput" class="output-box">// Scan results will appear here</div>
        </div>
      </div>
    </div>
  </div>

  <!-- TAB 2: Quorum Gate -->
  <div id="tab-quorum" class="tab-content">
    <div class="main-grid">
      <div class="card">
        <div class="card-title">
          <span>👥 Review Pending Quorum Proposal</span>
          <span class="badge">Dual-Control</span>
        </div>
        <div>
          <label>Proposal ID</label>
          <input id="propLookupId" placeholder="prp_..." />
        </div>
        <button class="btn secondary" onclick="lookupProposal()">Query Proposal</button>
        <div>
          <label>Proposal Details</label>
          <div id="propDetails" class="output-box">// Proposal details will appear here</div>
        </div>
      </div>

      <div class="card">
        <div class="card-title">
          <span>✍️ Approve or Reject Action (Supervisor)</span>
        </div>
        <div>
          <label>Approver ID (e.g. security-officer-01)</label>
          <input id="approverId" value="security-officer-01" />
        </div>
        <div>
          <label>Action SHA-256 Hash</label>
          <input id="actionHash" placeholder="Hex SHA-256 hash" />
        </div>
        <div>
          <label>Compliance Notes</label>
          <input id="approvalNotes" value="Manual compliance review complete. Verified." />
        </div>
        <div style="display: flex; gap: 8px;">
          <button class="btn success" style="flex: 1;" onclick="voteQuorum('APPROVE')">Approve (Authorize)</button>
          <button class="btn danger" style="flex: 1;" onclick="voteQuorum('REJECT')">Reject (Veto)</button>
        </div>
        <div id="voteOutput" class="output-box">// Approval receipt will appear here</div>
      </div>
    </div>
  </div>

  <!-- TAB 3: API Keys -->
  <div id="tab-keys" class="tab-content">
    <div class="main-grid">
      <div class="card">
        <div class="card-title">
          <span>🔑 Issue New Tenant API Key</span>
        </div>
        <div>
          <label>Organization ID</label>
          <input id="newOrgId" value="org_default" />
        </div>
        <div>
          <label>Key Name / Description</label>
          <input id="newKeyName" value="Payment Gateway Agent" />
        </div>
        <div>
          <label>Tier</label>
          <select id="newTier">
            <option value="developer">Developer (10,000 req/mo)</option>
            <option value="team">Team (100,000 req/mo)</option>
            <option value="enterprise">Enterprise (1,000,000 req/mo)</option>
          </select>
        </div>
        <button class="btn" onclick="createTenantKey()">Generate Secret Key</button>
        <div id="newKeyResult" class="output-box">// Generated key will appear here</div>
      </div>

      <div class="card">
        <div class="card-title">
          <span>📋 Active API Keys</span>
          <button class="btn secondary" style="padding: 4px 8px; font-size: 0.75rem;" onclick="loadKeys()">Refresh</button>
        </div>
        <div id="keysTableContainer" style="overflow-x: auto;">
          <table>
            <thead>
              <tr><th>Prefix</th><th>Name</th><th>Tier</th><th>Usage</th><th>Action</th></tr>
            </thead>
            <tbody id="keysTableBody">
              <tr><td colspan="5" style="text-align: center; color: var(--muted);">Click Refresh to list keys</td></tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  </div>

  <!-- TAB 4: Transparent AI Proxy -->
  <div id="tab-proxy" class="tab-content">
    <div class="card" style="max-width: 800px; margin: 0 auto;">
      <div class="card-title">
        <span>🚀 Zero-Code Drop-In Proxy Integration</span>
      </div>
      <p style="font-size: 0.9rem; color: var(--muted);">
        Route any existing OpenAI / LangChain / CrewAI agent through Vizier by setting only the base URL.
      </p>
      <div class="output-box" style="color: #60a5fa;"># Python SDK Configuration:
import openai
from vizier.proxy import configure_openai_proxy, VizierProxyConfig

client = openai.OpenAI(
    base_url="${origin}/v1",
    api_key="your_vizier_key"
)

# All prompt storms, secret leaks, and unapproved sensitive tool calls
# will be deterministically blocked at the Cloudflare edge!</div>
    </div>
  </div>

  <script>
    const ORIGIN = "${origin}";

    function getKey() {
      return localStorage.getItem("vizier_api_key") || document.getElementById("apiKeyInput").value;
    }

    function saveKey() {
      const val = document.getElementById("apiKeyInput").value.trim();
      if (val) {
        localStorage.setItem("vizier_api_key", val);
        alert("API Key saved to browser local storage!");
      }
    }

    window.onload = () => {
      const saved = localStorage.getItem("vizier_api_key");
      if (saved) document.getElementById("apiKeyInput").value = saved;
    };

    function showTab(tabId) {
      document.querySelectorAll(".tab-content").forEach(el => el.classList.remove("active"));
      document.querySelectorAll(".tab-btn").forEach(el => el.classList.remove("active"));
      document.getElementById("tab-" + tabId).classList.add("active");
      event.target.classList.add("active");
    }

    async function runSanctions50Screen() {
      const entityName = document.getElementById("entityName").value.trim();
      const rawJson = document.getElementById("shareholdersJson").value;
      const out = document.getElementById("sanctionsOutput");
      out.innerText = "Evaluating OFAC 50% Rule...";
      try {
        const parsed = JSON.parse(rawJson);
        const res = await fetch(ORIGIN + "/v1/sanctions/screen-entity", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-Vizier-Key": getKey()
          },
          body: JSON.stringify({
            entity_name: entityName,
            shareholders: parsed.shareholders || []
          })
        });
        const data = await res.json();
        out.innerText = JSON.stringify(data, null, 2);
      } catch (err) {
        out.innerText = "Error: " + err.message;
      }
    }

    async function runDlpScan() {
      const text = document.getElementById("dlpInput").value;
      const out = document.getElementById("dlpOutput");
      out.innerText = "Scanning for secrets and PII...";
      try {
        const res = await fetch(ORIGIN + "/v1/dlp/scan", {
          method: "POST",
          headers: { "Content-Type": "application/json", "X-Vizier-Key": getKey() },
          body: JSON.stringify({ text })
        });
        const data = await res.json();
        out.innerText = JSON.stringify(data, null, 2);
      } catch (err) {
        out.innerText = "Error: " + err.message;
      }
    }

    async function lookupProposal() {
      const propId = document.getElementById("propLookupId").value.trim();
      const out = document.getElementById("propDetails");
      out.innerText = "Looking up proposal...";
      try {
        const res = await fetch(ORIGIN + "/v1/quorum/proposals/" + encodeURIComponent(propId), {
          headers: { "X-Vizier-Key": getKey() }
        });
        const data = await res.json();
        out.innerText = JSON.stringify(data, null, 2);
        if (data.action_hash) {
          document.getElementById("actionHash").value = data.action_hash;
        }
      } catch (err) {
        out.innerText = "Error: " + err.message;
      }
    }

    async function voteQuorum(decision) {
      const propId = document.getElementById("propLookupId").value.trim();
      const approverId = document.getElementById("approverId").value.trim();
      const actionHash = document.getElementById("actionHash").value.trim();
      const notes = document.getElementById("approvalNotes").value.trim();
      const out = document.getElementById("voteOutput");
      out.innerText = "Submitting decision...";
      try {
        const res = await fetch(ORIGIN + "/v1/quorum/approve", {
          method: "POST",
          headers: { "Content-Type": "application/json", "X-Vizier-Key": getKey() },
          body: JSON.stringify({
            proposal_id: propId,
            approver_id: approverId,
            action_hash: actionHash,
            decision: decision,
            notes: notes
          })
        });
        const data = await res.json();
        out.innerText = JSON.stringify(data, null, 2);
      } catch (err) {
        out.innerText = "Error: " + err.message;
      }
    }

    async function createTenantKey() {
      const org_id = document.getElementById("newOrgId").value.trim();
      const name = document.getElementById("newKeyName").value.trim();
      const tier = document.getElementById("newTier").value;
      const out = document.getElementById("newKeyResult");
      out.innerText = "Generating key...";
      try {
        const res = await fetch(ORIGIN + "/v1/admin/keys", {
          method: "POST",
          headers: { "Content-Type": "application/json", "X-Vizier-Key": getKey() },
          body: JSON.stringify({ org_id, name, tier })
        });
        const data = await res.json();
        out.innerText = JSON.stringify(data, null, 2);
        loadKeys();
      } catch (err) {
        out.innerText = "Error: " + err.message;
      }
    }

    async function loadKeys() {
      const org_id = document.getElementById("newOrgId").value.trim() || "default";
      const tbody = document.getElementById("keysTableBody");
      try {
        const res = await fetch(ORIGIN + "/v1/admin/keys?org_id=" + encodeURIComponent(org_id), {
          headers: { "X-Vizier-Key": getKey() }
        });
        const data = await res.json();
        if (data.keys && data.keys.length > 0) {
          tbody.innerHTML = data.keys.map(k => \`
            <tr>
              <td><code>\${k.key_prefix}...</code></td>
              <td>\${k.name}</td>
              <td><span class="badge">\${k.tier}</span></td>
              <td>\${k.current_usage} / \${k.monthly_quota}</td>
              <td>\${k.revoked_at ? '<span style="color:red">Revoked</span>' : \`<button class="btn danger" style="padding:2px 6px;font-size:0.75rem;" onclick="revokeKey('\${k.id}')">Revoke</button>\`}</td>
            </tr>
          \`).join("");
        } else {
          tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--muted);">No keys found for this organization</td></tr>';
        }
      } catch (err) {
        tbody.innerHTML = '<tr><td colspan="5" style="color: red;">Error: ' + err.message + '</td></tr>';
      }
    }

    async function revokeKey(id) {
      if (!confirm("Are you sure you want to revoke this API key?")) return;
      try {
        await fetch(ORIGIN + "/v1/admin/keys/" + encodeURIComponent(id), {
          method: "DELETE",
          headers: { "X-Vizier-Key": getKey() }
        });
        loadKeys();
      } catch (err) {
        alert("Revoke failed: " + err.message);
      }
    }
  </script>
</body>
</html>`;
}
