"""Required-grant mode: wrappers must forward the owner-signed grant."""
import asyncio
import json
from unittest.mock import patch

import pytest

from vizier import VizierClient, AsyncVizierClient, vizier_guard
from vizier.canonical import sha256_canonical_json
from vizier.integrations.langchain import VizierLangChainToolGuard
from vizier.integrations.crewai import VizierCrewAIToolGuard

GRANT = "eyJhbGciOiJFUzI1NiJ9.eyJqdGkiOiJnMSJ9.c2ln"


def fake_service(seen, require_grant=True):
    """Echo a service in required-grant mode: ALLOW only with a grant."""

    def _request(path, data, extra=None):
        seen.append(json.loads(json.dumps(data)))
        allowed = (not require_grant) or bool(data.get("grant"))
        decision = "ALLOW" if allowed else "BLOCK"
        receipt = {
            "id": "vrf_1", "created_at": "2026-01-01T00:00:00Z",
            "request_hash": sha256_canonical_json(data), "decision": decision,
            "risk_score": 0, "policy_rule_ids": [],
            "reason_codes": [] if allowed else ["GRANT_REQUIRED"],
            "authority_provenance": "unverified",
        }
        return {"decision": decision, "risk_score": 0,
                "reason_codes": receipt["reason_codes"], "explanation": "",
                "policy_results": [], "receipt": receipt}

    return _request


class Tool:
    name = "send_money"
    description = "d"

    def __init__(self):
        self.calls = 0

    def run(self, *a, **k):
        self.calls += 1
        return "ran"

    async def arun(self, *a, **k):
        self.calls += 1
        return "ran"

    _run = run


def client():
    return VizierClient(base_url="https://example.test")


def test_decorator_without_grant_is_blocked_by_required_grant_service():
    seen, c = [], client()
    ran = []

    @vizier_guard(client=c, action_type="pay")
    def pay(target="x"):
        ran.append(1)

    with patch.object(c, "_request", side_effect=fake_service(seen)):
        with pytest.raises(Exception):
            pay()
    assert not ran and "grant" not in seen[0]


def test_decorator_forwards_static_grant_and_allows():
    seen, c = [], client()

    @vizier_guard(client=c, action_type="pay", grant=GRANT)
    def pay(target="x"):
        return "paid"

    with patch.object(c, "_request", side_effect=fake_service(seen)):
        assert pay() == "paid"
    assert seen[0]["grant"] == GRANT


def test_decorator_callable_grant_receives_call_args():
    seen, c = [], client()

    @vizier_guard(client=c, action_type="pay", grant=lambda target, **kw: f"g-{target}")
    def pay(target="x"):
        return "paid"

    with patch.object(c, "_request", side_effect=fake_service(seen, require_grant=False)):
        pay(target="acct1")
    assert seen[0]["grant"] == "g-acct1"


def test_async_decorator_forwards_grant():
    seen = []
    c = AsyncVizierClient(base_url="https://example.test")

    @vizier_guard(client=c, action_type="pay", grant=GRANT)
    async def pay(target="x"):
        return "paid"

    with patch.object(c._sync_client, "_request", side_effect=fake_service(seen)):
        assert asyncio.run(pay()) == "paid"
    assert seen[0]["grant"] == GRANT


def test_decorator_ignores_grant_in_tool_parameters():
    """A grant must come from integration config, never from agent-controlled params."""
    seen, c = [], client()

    @vizier_guard(client=c, action_type="pay")
    def pay(target="x", grant=None):
        return "paid"

    with patch.object(c, "_request", side_effect=fake_service(seen, require_grant=False)):
        pay(grant="forged")
    assert "grant" not in seen[0]


def test_langchain_guard_forwards_grant_sync_and_async():
    seen, c = [], client()
    tool = Tool()
    g = VizierLangChainToolGuard(tool, client=c, grant=GRANT)
    with patch.object(c, "_request", side_effect=fake_service(seen)), \
         patch.object(g.async_client._sync_client, "_request", side_effect=fake_service(seen)):
        assert g.run({"target": "a"}) == "ran"
        assert asyncio.run(g.arun({"target": "a"})) == "ran"
    assert [r["grant"] for r in seen] == [GRANT, GRANT]


def test_langchain_guard_without_grant_blocks_and_does_not_run():
    seen, c = [], client()
    tool = Tool()
    g = VizierLangChainToolGuard(tool, client=c)
    with patch.object(c, "_request", side_effect=fake_service(seen)):
        out = g.run({"target": "a"})
    assert "blocked" in out and tool.calls == 0


def test_langchain_callable_grant():
    seen, c = [], client()
    g = VizierLangChainToolGuard(Tool(), client=c, grant=lambda inp: "g-" + inp["target"])
    with patch.object(c, "_request", side_effect=fake_service(seen)):
        g.run({"target": "z"})
    assert seen[0]["grant"] == "g-z"


def test_crewai_guard_forwards_grant():
    seen, c = [], client()
    tool = Tool()
    g = VizierCrewAIToolGuard(tool, client=c, grant=GRANT)
    with patch.object(c, "_request", side_effect=fake_service(seen)):
        assert g._run(target="a") == "ran"
    assert seen[0]["grant"] == GRANT
    bad = VizierCrewAIToolGuard(Tool(), client=c)
    with patch.object(c, "_request", side_effect=fake_service(seen)):
        assert "blocked" in bad._run(target="a").lower()
