import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock

from vizier import (
    VizierClient,
    AsyncVizierClient,
    vizier_guard,
    ActionBlockedError,
    VerificationRequest,
    VerificationResponse,
    Agent,
    Action,
    Authority,
    AuthorityConstraints,
)
from vizier.models import Receipt, PolicyResult

def make_dlp_blocked_response():
    return VerificationResponse(
        decision="BLOCK",
        risk_score=1.0,
        reason_codes=["SECRET_LEAK_PREVENTED"],
        explanation="The proposed action violates the supplied delegated authority or constraints.",
        policy_results=[
            PolicyResult(
                rule_id="security.dlp",
                result="FAIL",
                reason_code="SECRET_LEAK_PREVENTED",
                details={
                    "findings": [
                        {
                            "category": "api_key",
                            "detector": "openai_api_key",
                            "path": "action.parameters.query",
                            "snippet_masked": "sk-p******1234",
                        }
                    ],
                    "total_leaks_prevented": 1,
                },
            )
        ],
        receipt=Receipt(
            id="vrf_dlp_test",
            created_at="2026-09-11T00:00:00Z",
            request_hash="c" * 64,
            decision="BLOCK",
            risk_score=1.0,
            policy_rule_ids=["security.dlp"],
            reason_codes=["SECRET_LEAK_PREVENTED"],
            authority_provenance="trusted_integration",
        ),
    )

def test_dlp_authority_constraints_serialization():
    req = VerificationRequest(
        agent=Agent(id="agent-1"),
        principal=None,
        action=Action(type="search", target="google.com", parameters={"query": "test"}),
        authority=Authority(
            allowed_actions=["search"],
            constraints=AuthorityConstraints(
                dlp_screening=True,
                allowed_dlp_categories=["payment_card"],
            ),
        ),
    )
    d = req.to_dict()
    assert d["authority"]["constraints"]["dlp_screening"] is True
    assert d["authority"]["constraints"]["allowed_dlp_categories"] == ["payment_card"]

def test_client_scan_dlp():
    client = VizierClient(api_key="test-key")
    client._request = MagicMock(return_value={
        "clean": False,
        "total_leaks_prevented": 1,
        "findings": [{"category": "api_key", "detector": "openai_api_key"}]
    })

    res = client.scan_dlp(text="sk-proj-1234567890abcdef1234")
    assert res["clean"] is False
    assert res["total_leaks_prevented"] == 1
    client._request.assert_called_once_with(
        "/v1/dlp/scan",
        {"text": "sk-proj-1234567890abcdef1234"}
    )

def test_async_client_scan_dlp():
    async def _test():
        client = AsyncVizierClient(api_key="test-key")
        client._sync_client.scan_dlp = MagicMock(return_value={
            "clean": True,
            "total_leaks_prevented": 0,
            "findings": []
        })

        res = await client.scan_dlp(text="clean query without secrets")
        assert res["clean"] is True
        client._sync_client.scan_dlp.assert_called_once_with(
            text="clean query without secrets",
            parameters=None,
            allowed_categories=None,
        )

    asyncio.run(_test())

def test_guard_with_dlp_check():
    mock_client = MagicMock()
    mock_client.check.return_value = make_dlp_blocked_response()

    @vizier_guard(
        client=mock_client,
        action_type="web_search",
        dlp_check=True,
    )
    def search_web(query: str):
        return f"results for {query}"

    with pytest.raises(ActionBlockedError) as exc_info:
        search_web("search using api key sk-proj-1234567890abcdef1234")

    assert exc_info.value.response.decision == "BLOCK"
    assert "SECRET_LEAK_PREVENTED" in exc_info.value.response.reason_codes
    kwargs = mock_client.check.call_args[1]
    assert kwargs["dlp_screening"] is True

def test_async_guard_with_dlp_check():
    async def _test():
        mock_async_client = AsyncMock()
        mock_async_client.check.return_value = make_dlp_blocked_response()

        @vizier_guard(
            client=mock_async_client,
            action_type="web_search",
            dlp_check=True,
        )
        async def async_search_web(query: str):
            return f"results for {query}"

        with pytest.raises(ActionBlockedError) as exc_info:
            await async_search_web("search using api key sk-proj-1234567890abcdef1234")

        assert exc_info.value.response.decision == "BLOCK"
        kwargs = mock_async_client.check.call_args[1]
        assert kwargs["dlp_screening"] is True

    asyncio.run(_test())
