<!-- mcp-name: io.github.vassiliylakhonin/vizier-guard -->
# Vizier Guard (Python SDK)

Python client for Vizier, a deterministic authorization service for AI agent actions. Calls go to a hosted (or self-hosted) Vizier service over HTTPS.

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](../../LICENSE)
[![Python](https://img.shields.io/badge/python-3.9+-green.svg)](pyproject.toml)

Vizier is a deterministic policy kernel that evaluates proposed AI agent actions before they cause external side-effects (payments, database mutations, external messages, code execution, worker deployments). The policy decision itself is local to the service and uses no model; every client call is still a network request to the service, so end-to-end latency includes your network round trip and has not been benchmarked here.

---

## Installation

```bash
pip install vizier-guard==0.3.2
```

Zero external dependencies required out of the box (uses Python standard library).

**Version boundary:** PyPI currently has `0.3.2`. This checkout is `0.3.3`, which
is not yet published. Receipt-JWS verification and the `receipts` extra described
below require installing this checkout with `pip install -e 'packages/python-sdk[receipts]'`
from the repository root. Do not expect `pip install vizier-guard` to provide them.

---

## Model Context Protocol (MCP) Server (Claude Desktop, Cursor: untested examples)

`vizier-guard` includes a first-class MCP server that equips **Claude Desktop**, **Cursor**, **Zed**, and **Windsurf** with deterministic authorization and audit tools. The configurations below are examples and have **not been tested** on each of these clients; only the stdio MCP server itself is covered by this package's tests:

- `vizier_screen_action`: Screens proposed tool calls, shell executions, or writes before execution; returns ALLOW / BLOCK / REVIEW decisions with a receipt. Receipts from `/v1/verify` are unsigned unless the service is configured with a receipt signing key and the request opts in (`X-Vizier-Receipt: jws`).
- `vizier_verify_receipt`: Validates cryptographic JWS receipts and action hash bindings.
- `vizier_check_policy`: Scans inputs/parameters for leaked API keys (DLP), sanctions matches, or loop storms.

### Claude Desktop Configuration (`claude_desktop_config.json`, untested)

Add to `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "vizier": {
      "command": "uvx",
      "args": ["vizier-guard", "mcp"],
      "env": {
        "VIZIER_BASE_URL": "https://vizier.agendamcp.dpdns.org",
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
        "VIZIER_BASE_URL": "https://vizier.agendamcp.dpdns.org",
        "VIZIER_API_KEY": "your-vizier-api-key"
      }
    }
  }
}
```

The local stdio connector uses the initialize-based session lifecycle. It
preserves `2025-11-25`, `2025-06-18`, `2025-03-26` and `2024-11-05`, and
counter-offers `2025-11-25` for an unsupported revision. It does not negotiate
stateless `2026-07-28` through initialize. Use the hosted HTTP endpoint's
`server/discover` sequence when you need that separate protocol era.

### Cursor Configuration (`.cursor/mcp.json`, untested)

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

## First BLOCK, with a checked receipt

Start with the [local TypeScript + Python walkthrough](../../docs/FIRST_BLOCK.md).
It needs no production credential, runs a real local Worker, and checks that an
unsigned request hash or a signed receipt cannot be tampered with undetected.
It never calls a protected tool. Use the published-client path for `0.3.2` and
the source path for `0.3.3` signed-receipt verification.

### Before connecting a real tool

An API key identifies an integration; it does not grant the owner's permission.
In required-grant mode, a request without a valid owner-signed delegation is
`BLOCK` with `GRANT_REQUIRED`, even if the amount and target satisfy the policy.
Use `VizierClient.verify()` or `check(..., grant=...)` with the exact signed
authority after [operator setup](../../docs/DELEGATION_GRANTS.md).

The decorator and framework examples below illustrate policy wiring, not a
complete required-grant integration. The current `vizier_guard` decorator does
not accept or forward a delegation grant. It therefore cannot produce an ALLOW
against the required-grant hosted service. Do not work around this by disabling
grant requirements, and never treat a local HITL callback as an owner-signed grant.

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

### Signed receipts (`receipt_jws`, source 0.3.3 only)

If the service signs its receipt, `verify()` checks the ES256 signature against the published keys (`/.well-known/jwks.json`) and confirms it covers the exact receipt returned. Failure raises `VizierError` with code `RECEIPT_SIGNATURE_INVALID`. A response without `receipt_jws` is accepted as before. Pass `request_receipt_jws=True` to ask the service to sign (`X-Vizier-Receipt: jws`).

This needs `cryptography` (`pip install "vizier-guard[receipts]"`). Without it, a signed response fails closed with `RECEIPT_VERIFICATION_UNAVAILABLE` rather than being trusted unchecked. The base package stays dependency-free.

---

## ⚡ Asynchronous Support (`AsyncVizierClient`)

For asynchronous agent runtimes (FastAPI, LangGraph, AutoGen):

```python
from vizier import AsyncVizierClient, vizier_guard

client = AsyncVizierClient(
    base_url="https://vizier.agendamcp.dpdns.org",
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

## Pre-Action Sanctions & Anti-Fraud Gate (snapshot-based, not a clearance)

Reduce the chance that autonomous agents interact with sanctioned entities, flagged crypto mixers (Tornado Cash, Lazarus, Garantex, SUEX), rogue vendor domains, or blacklisted IBANs.

Screening is deterministic and runs inside the Vizier service with no outbound lookup at decision time. It matches against a built-in static list plus, where enabled, a periodically synced snapshot of the OFAC SDN list; it is not a live feed. The built-in list is small and hand-picked (one EU entry, a few dozen OFAC entries) and does not cover the EU or UN lists in full, so a clean result is not a sanctions clearance. Check the service's snapshot date and coverage before relying on it for compliance. The Python client itself makes an HTTPS request for each screen.

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

Vizier provides deterministic pattern-based Data Loss Prevention (DLP) screening for tool calls:

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



