#!/usr/bin/env python3
"""
Vizier End-to-End Showcase: Protecting an Autonomous AI Agent in Python.
Demonstrates how @vizier_guard intercepts runaway spending and forbidden targets
before any external side-effect is committed.
"""

import sys
import os

# Add package to path for local execution
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "packages", "python-sdk", "src"))

from vizier import VizierClient, vizier_guard, ActionBlockedError

def main():
    print("=================================================================")
    print("  VIZIER AGENTIC ACTION FIREWALL — END-TO-END DEMO")
    print("=================================================================\n")

    # In local testing or against production edge
    vizier_url = os.environ.get("VIZIER_BASE_URL", "https://vizier.vassiliy-lakhonin.workers.dev")
    api_key = os.environ.get("VIZIER_API_KEY")

    client = VizierClient(base_url=vizier_url, api_key=api_key)
    print(f"[*] Connected to Vizier Kernel: {vizier_url}")
    print(f"[*] Mode: {'Authenticated (Enforcement)' if api_key else 'Public / Evaluation (Review/Block on unauthenticated)'}\n")

    # Guard a simulated financial execution tool
    @vizier_guard(
        client=client,
        action_type="purchase",
        max_amount=1000.0,
        currency="USD",
        allowed_targets=["approved-supplier.com", "authorized-cloud.io"],
        agent_id="procurement-agent-alpha",
        principal_id="acme-finance-dept",
    )
    def execute_payment(amount: float, target: str):
        print(f"  --> [PAYMENT COMMITTED]: ${amount:.2f} sent to {target}!")
        return {"status": "success", "amount": amount, "target": target}

    # Scenario 1: Autonomous agent attempts a valid purchase within limits
    print("--- Scenario 1: Valid Purchase within constraints ---")
    print("Agent requests: Purchase $450.00 from 'approved-supplier.com' (Limit: $1000.00)")
    try:
        res = execute_payment(450.0, target="approved-supplier.com")
        print(f"Result: {res}\n")
    except ActionBlockedError as err:
        print(f"BLOCKED: {err}\n")

    # Scenario 2: Agent experiences hallucination or runaway loop, attempts $15,000
    print("--- Scenario 2: Runaway Budget / Hallucination ($15,000 > $1,000) ---")
    print("Agent requests: Purchase $15,000.00 from 'approved-supplier.com'")
    try:
        execute_payment(15000.0, target="approved-supplier.com")
    except ActionBlockedError as err:
        print(f"  [!] INTERCEPTED BY VIZIER!")
        print(f"      Decision: {err.response.decision}")
        print(f"      Explanation: {err.response.explanation}")
        print(f"      Reason codes: {err.response.reason_codes}")
        print(f"      Receipt ID: {err.response.receipt.id}\n")

    # Scenario 3: Agent attempts to send money to an unapproved destination
    print("--- Scenario 3: Target Not in Allowed List ---")
    print("Agent requests: Purchase $50.00 from 'unauthorized-hacker-vendor.xyz'")
    try:
        execute_payment(50.0, target="unauthorized-hacker-vendor.xyz")
    except ActionBlockedError as err:
        print(f"  [!] INTERCEPTED BY VIZIER!")
        print(f"      Decision: {err.response.decision}")
        print(f"      Explanation: {err.response.explanation}")
        print(f"      Reason codes: {err.response.reason_codes}\n")

    print("[SUCCESS] All scenarios evaluated deterministically by Vizier.")

if __name__ == "__main__":
    main()
