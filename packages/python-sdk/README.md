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

