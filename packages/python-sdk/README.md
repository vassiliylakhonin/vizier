<!-- mcp-name: io.github.vassiliylakhonin/vizier-guard -->
# Vizier Guard (Python SDK)

Deterministic Authorization & Audit Firewall for AI Agent Actions.

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.9+-green.svg)](pyproject.toml)

Vizier is an ultra-low-latency (sub-2ms) deterministic policy kernel that evaluates proposed AI agent actions before they cause external side-effects (payments, database mutations, external messages, code execution, worker deployments).

---

## Installation

```bash
pip install vizier-guard
```

Zero external dependencies required out of the box (uses Python standard library).

---

## 🛡️ Model Context Protocol (MCP) Server for Claude Desktop & Cursor

`vizier-guard` includes a first-class MCP server that equips **Claude Desktop**, **Cursor**, **Zed**, and **Windsurf** with deterministic authorization and audit tools:

- `vizier_screen_action`: Screens proposed tool calls, shell executions, or writes before execution; returns cryptographic ALLOW / BLOCK receipts.
- `vizier_verify_receipt`: Validates cryptographic JWS receipts and action hash bindings.
- `vizier_check_policy`: Scans inputs/parameters for leaked API keys (DLP), sanctions matches, or loop storms.

### Claude Desktop Configuration (`claude_desktop_config.json`)

Add to `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "vizier": {
      "command": "uvx",
      "args": ["vizier-guard", "mcp"],
      "env": {
        "VIZIER_BASE_URL": "https://vizier.vassiliy-lakhonin.workers.dev",
        "VIZIER_API_KEY": "your-vizier-api-key"
      }
    }
  }
}
```

Or using an existing Python environment:

```json
{
  "mcpServers": {
    "vizier": {
      "command": "python",
      "args": ["-m", "vizier.mcp"],
      "env": {
        "VIZIER_BASE_URL": "https://vizier.vassiliy-lakhonin.workers.dev",
        "VIZIER_API_KEY": "your-vizier-api-key"
      }
    }
  }
}
```

### Cursor Configuration (`.cursor/mcp.json`)

```json
{
  "mcpServers": {
    "vizier": {
      "command": "uvx",
      "args": ["vizier-guard", "mcp"]
    }
  }
}
```

---

## 30-Second Quickstart: `@vizier_guard` Decorator

Wrap any dangerous tool or Python function with deterministic policy rules:

```python
from vizier import VizierClient, vizier_guard

client = VizierClient(
    base_url="https://vizier.vassiliy-lakhonin.workers.dev",
    api_key="your-vizier-api-key"
)

@vizier_guard(
    client=client,
    action_type="purchase",
    max_amount=500.0,
    currency="USD",
    allowed_targets=["approved-hotel.com", "supplier-corp.com"]
)
def book_hotel(amount: float, target: str):
    # This only runs if Vizier returns ALLOW
    print(f"Booking confirmed at {target} for ${amount}")
    return {"status": "booked", "amount": amount}

# Allowed: $350 <= $500 to approved target
book_hotel(amount=350.0, target="approved-hotel.com")

# Blocked: $1200 > $500 (raises ActionBlockedError)
book_hotel(amount=1200.0, target="approved-hotel.com")
```

---

## LangChain Integration

Protect any LangChain `BaseTool` from agent hallucinations or runaway spending:

```python
from vizier import VizierClient
from vizier.integrations.langchain import VizierLangChainToolGuard
from langchain_community.tools import DuckDuckGoSearchRun

client = VizierClient(api_key="...")

# Wrap your tool
safe_search = VizierLangChainToolGuard(
    tool=DuckDuckGoSearchRun(),
    client=client,
    allowed_actions=["search"],
    max_amount=0.0
)

# Pass safe_search into your LangChain or LangGraph agent
agent = create_react_agent(llm, tools=[safe_search])
```

---

## CrewAI Integration

```python
from vizier.integrations.crewai import VizierCrewAIToolGuard

guarded_tool = VizierCrewAIToolGuard(
    tool=my_dangerous_payment_tool,
    max_amount=250.0,
    agent_id="finance_agent"
)
```

---

## Standalone Verification

```python
from vizier import VizierClient

vizier = VizierClient(api_key="...")

decision = vizier.check(
    action_type="deploy_worker",
    target="worker:payment-service",
    parameters={"git_commit": "abcdef123..."},
    allowed_actions=["deploy_worker"]
)

if decision.is_allowed:
    print(f"Action permitted! Receipt ID: {decision.receipt.id}")
else:
    print(f"Action rejected ({decision.decision}): {decision.explanation}")
```

---

## ⚡ Asynchronous Support (`AsyncVizierClient`)

For asynchronous agent runtimes (FastAPI, LangGraph, AutoGen):

```python
from vizier import AsyncVizierClient, vizier_guard

client = AsyncVizierClient(
    base_url="https://vizier.vassiliy-lakhonin.workers.dev",
    api_key="your-api-key"
)

# Protect async coroutine functions
@vizier_guard(client=client, action_type="fetch_data", max_amount=100.0)
async def fetch_async(target: str, amount: float):
    return {"status": "success", "target": target}

# In async context:
result = await fetch_async("api.service", amount=50.0)
```

---

## 🧑‍💼 Human-in-the-Loop (HITL) Approval

When a proposed action returns `REVIEW` (e.g., sensitive operations like money transfers, database drops, or large payments), Vizier can halt and request interactive human approval:

### 1. Telegram Bot (Interactive Buttons)

Send an approval request with **[ Approve ]** and **[ Reject ]** buttons directly to your Telegram:

```python
from vizier import VizierClient, vizier_guard, TelegramHITLHandler

telegram_approver = TelegramHITLHandler(
    bot_token="123456789:ABCdefGHIjklMNOpqrsTUVwxyz",
    chat_id="987654321",
    timeout=60.0  # Wait up to 60s for operator response
)

@vizier_guard(
    action_type="transfer_funds",
    max_amount=1000.0,
    hitl_handler=telegram_approver
)
def transfer(amount: float, target: str):
    # Executes ONLY if operator clicks [Approve] in Telegram
    print(f"Transferred ${amount} to {target}")
```

### 2. Terminal / CLI Prompt

For local development or command-line agent runs:

```python
from vizier import CliHITLHandler

@vizier_guard(
    action_type="delete_table",
    hitl_handler=CliHITLHandler()
)
def drop_database(table: str):
    print(f"Dropped {table}")
```

### 3. Webhook (Slack / Internal Dashboard)

```python
from vizier import WebhookHITLHandler

@vizier_guard(
    action_type="deploy_worker",
    hitl_handler=WebhookHITLHandler("https://hooks.slack.com/services/...")
)
def deploy(service: str):
    print(f"Deployed {service}")
```

---

## 🛑 Agent Circuit Breaker & Loop Killer

AI agents can get stuck in infinite retry loops, repeatedly invoking tools with identical parameters, burning API rate limits, and draining thousands of dollars in LLM tokens.

The Vizier `CircuitBreaker` provides deterministic client-side protection:

### 1. Loop Detection & Budget Capping with `@vizier_guard`

```python
from vizier import CircuitBreaker, vizier_guard

# Trip if called 3 times with identical parameters within 30 seconds,
# or if more than 20 total actions are performed in this session.
breaker = CircuitBreaker(
    max_repeated_calls=3,
    time_window_seconds=30.0,
    max_session_actions=20,
    cool_off_seconds=60.0
)

@vizier_guard(
    action_type="query_database",
    circuit_breaker=breaker
)
def query_db(query: str):
    return db.execute(query)

# Calls with identical query parameters:
query_db(query="SELECT * FROM users")  # 1st: OK
query_db(query="SELECT * FROM users")  # 2nd: OK
query_db(query="SELECT * FROM users")  # 3rd: OK
query_db(query="SELECT * FROM users")  # 4th: Raises CircuitTrippedError (LOOP_DETECTED)
```

### 2. Standalone Circuit Breaker Usage

```python
from vizier import CircuitBreaker, CircuitTrippedError

cb = CircuitBreaker(max_repeated_calls=2, max_session_actions=50)

try:
    cb.check(action_type="api_call", parameters={"endpoint": "/charge"})
    # Perform external action...
except CircuitTrippedError as err:
    print(f"Safety tripped: {err.reason}")  # CIRCUIT_TRIPPED:LOOP_DETECTED
    cb.reset()  # Reset when starting a new agent task
```

---

## 🛡️ Pre-Action Sanctions & Anti-Fraud Gate (OFAC / EU / Crypto)

Prevent autonomous agents from interacting with sanctioned entities, flagged crypto mixers (Tornado Cash, Lazarus, Garantex, SUEX), rogue vendor domains, or blacklisted IBANs.

All screening is evaluated deterministically in sub-2ms edge latency with zero outbound HTTP requests at evaluation time.

### 1. Screening via `@vizier_guard`

```python
from vizier import VizierClient, vizier_guard

client = VizierClient(api_key="your-api-key")

@vizier_guard(
    client=client,
    action_type="crypto_payout",
    sanctions_check=True,
    blocked_entities=["rogue-vendor.com"]  # Optional custom blocked entities
)
def send_crypto(recipient_address: str, amount: float):
    # Safe to execute:
    print(f"Transferring {amount} ETH to {recipient_address}")

# Clean transfer: ALLOW
send_crypto("0x71c6bfb764b85770f4ac626088409617329fe24a", 0.5)

# Sanctioned entity (e.g. Tornado Cash): raises ActionBlockedError with SANCTIONED_ENTITY_MATCH
send_crypto("0xd90e2f925da726b50c4ed8d0fb90ad053324f31b", 10.0)
```

### 2. Pre-flight Screening Queries

```python
result = client.screen_sanctions("garantex.org")
if not result["clean"]:
    print(f"Blocked match: {result['match']['entity_name']} on {result['match']['list']}")
```

---

## 🔒 PII & Secret Leak Firewall (DLP for Tool Calls)

AI agents invoking external tools (Google search, Slack, email, external APIs) risk exfiltrating sensitive credentials or personal data—either via prompt hallucinations or Indirect Prompt Injection attacks.

Vizier provides deterministic, sub-millisecond Data Loss Prevention (DLP) screening for every tool call:

* **API Keys & Secrets:** OpenAI (`sk-...`), Anthropic (`sk-ant-...`), AWS Access & Secret Keys, GitHub PATs, Stripe Live Keys, Slack tokens, Google Cloud keys, Private Key PEM blocks, and JWT tokens.
* **PII:** Payment Cards (validated via Luhn algorithm to prevent false positives), US Social Security Numbers (SSN).
* **Entropy Anomaly Detector:** Shannon entropy analysis for unstructured passwords and raw tokens.
* **Privacy by Design:** Leaked secrets are automatically masked (`sk-p******1234`) in receipts and audit logs.

### 1. Protect Tool Calls with `@vizier_guard(dlp_check=True)`

```python
from vizier import VizierClient, vizier_guard

client = VizierClient(api_key="your-api-key")

@vizier_guard(
    client=client,
    action_type="web_search",
    dlp_check=True,
)
def search_online(query: str):
    # This runs ONLY if no secrets or PII are found in query
    return external_search_api(query)

# Allowed: regular query
search_online("latest AI research papers")

# Blocked: raises ActionBlockedError with SECRET_LEAK_PREVENTED
search_online("debug prompt with sk-proj-1234567890abcdef1234567890")
```

### 2. Standalone DLP Scanner

```python
scan_result = client.scan_dlp(text="Look at this key: AKIAIOSFODNN7EXAMPLE")
if not scan_result["clean"]:
    print(f"Prevented {scan_result['total_leaks_prevented']} secret leak(s):")
    for finding in scan_result["findings"]:
        print(f"  - {finding['category']} ({finding['detector']}): {finding['snippet_masked']}")
```

---

## 👥 Multi-Agent Quorum & Dual-Control Gate (4-Eyes Principle)

Critical AI agent actions (financial transfers, infrastructure mutation, database drops, IAM role modifications) should never rely on a single autonomous agent. Vizier enforces a deterministic "4-eyes" principle requiring consensus and co-signing from independent supervisor or peer agents.

* **Self-Approval Prohibited:** Proposing agent cannot approve its own action (`SELF_APPROVAL_DISALLOWED`).
* **Canonical Action Hash Binding:** Approvals strictly bind to the exact action SHA-256 hash (`QUORUM_ACTION_MISMATCH`).
* **Veto Power:** Any authorized approver casting `REJECT` immediately blocks the action.
* **Both Stateful & Stateless Modes:** Support for Cloudflare KV proposal registry or inline stateless signatures.

### 1. Asynchronous Coordination Workflow (Stateful Edge)

```python
from vizier import VizierClient

client = VizierClient(api_key="your-api-key")

# Step 1: Agent Alpha proposes high-risk deployment
proposal = client.propose_quorum(
    action_type="deploy_worker",
    target="cloudflare_edge",
    parameters={"worker": "payment-api", "version": "v2.0"},
    min_approvals=2,
    allowed_approvers=["security-auditor", "infra-lead"],
)
proposal_id = proposal["proposal_id"]
action_hash = proposal["action_hash"]

# Step 2: Peer Agent (Auditor) approves the proposal
client.approve_quorum(
    proposal_id=proposal_id,
    approver_id="security-auditor",
    action_hash=action_hash,
    decision="APPROVE",
    notes="Security review complete: 0 vulnerabilities found.",
)

# Step 3: Check proposal status
status = client.get_quorum_proposal(proposal_id)
print(f"Current status: {status['status']} (Approvals: {len(status['approvals'])})")
```

### 2. Protect Functions with `@vizier_guard(quorum_min_approvals=...)`

```python
@vizier_guard(
    client=client,
    action_type="transfer_funds",
    target="wire_service",
    quorum_min_approvals=2,
    quorum_allowed_approvers=["treasury-bot", "compliance-bot"],
)
def wire_funds(recipient: str, amount: float):
    # Executes ONLY if quorum requirement is verified by Vizier
    return execute_wire(recipient, amount)
```



