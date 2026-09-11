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
