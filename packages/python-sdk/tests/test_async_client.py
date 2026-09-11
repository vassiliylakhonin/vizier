import asyncio
from unittest.mock import MagicMock

from vizier import AsyncVizierClient, vizier_guard, ActionBlockedError
from vizier.models import VerificationResponse, Receipt, Decision
from vizier.integrations.langchain import VizierLangChainToolGuard

def mock_response(decision: str = "ALLOW", explanation: str = "ok") -> VerificationResponse:
    return VerificationResponse(
        decision=decision,
        risk_score=0.0,
        reason_codes=[],
        explanation=explanation,
        policy_results=[],
        receipt=Receipt(
            id="vrf_test",
            created_at="2026-09-11T12:00:00.000Z",
            request_hash="abcd",
            decision=decision,
            risk_score=0.0,
            policy_rule_ids=[],
            reason_codes=[],
            authority_provenance="trusted_integration",
        ),
    )

def test_async_client_check():
    async def _test():
        client = AsyncVizierClient(api_key="test-key")
        client._sync_client.check = MagicMock(return_value=mock_response("ALLOW"))

        resp = await client.check(
            action_type="query_db",
            target="users_table",
            parameters={"limit": 10},
        )
        assert resp.is_allowed
        assert resp.decision == "ALLOW"
        client._sync_client.check.assert_called_once()

    asyncio.run(_test())

def test_async_vizier_guard_allow():
    async def _test():
        client = AsyncVizierClient(api_key="test-key")
        client._sync_client.check = MagicMock(return_value=mock_response("ALLOW"))

        @vizier_guard(client=client, action_type="fetch_data", max_amount=100.0)
        async def fetch_async(target: str, amount: float):
            return f"fetched from {target} for {amount}"

        result = await fetch_async("api.service", amount=50.0)
        assert result == "fetched from api.service for 50.0"

    asyncio.run(_test())

def test_async_vizier_guard_block():
    async def _test():
        client = AsyncVizierClient(api_key="test-key")
        client._sync_client.check = MagicMock(
            return_value=mock_response("BLOCK", "Authority limit exceeded")
        )

        @vizier_guard(client=client, action_type="fetch_data")
        async def fetch_async(target: str):
            return "should not run"

        try:
            await fetch_async("untrusted.target")
            assert False, "Should have raised ActionBlockedError"
        except ActionBlockedError as exc:
            assert exc.response.decision == "BLOCK"

    asyncio.run(_test())

def test_async_langchain_tool_guard():
    async def _test():
        mock_tool = MagicMock()
        mock_tool.name = "calc_tool"
        mock_tool.description = "calculates things"
        mock_tool.arun = MagicMock()

        async def fake_arun(*args, **kwargs):
            return "42"

        mock_tool.arun.side_effect = fake_arun

        client = AsyncVizierClient(api_key="test-key")
        client._sync_client.check = MagicMock(return_value=mock_response("ALLOW"))

        guarded = VizierLangChainToolGuard(tool=mock_tool, client=client)
        res = await guarded.arun(expr="6*7")
        assert res == "42"

    asyncio.run(_test())
