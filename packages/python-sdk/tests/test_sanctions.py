import asyncio
import pytest
from unittest.mock import MagicMock

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

def make_sanctions_blocked_response():
    return VerificationResponse(
        decision="BLOCK",
        risk_score=1.0,
        reason_codes=["SANCTIONED_ENTITY_MATCH"],
        explanation="The proposed action violates the supplied delegated authority or constraints.",
        policy_results=[
            PolicyResult(
                rule_id="compliance.sanctions",
                result="FAIL",
                reason_code="SANCTIONED_ENTITY_MATCH",
                details={"entity_name": "Tornado Cash", "list": "OFAC_SDN"},
            )
        ],
        receipt=Receipt(
            id="vrf_sanctions_test",
            created_at="2026-09-11T00:00:00Z",
            request_hash="b" * 64,
            decision="BLOCK",
            risk_score=1.0,
            policy_rule_ids=["compliance.sanctions"],
            reason_codes=["SANCTIONED_ENTITY_MATCH"],
            authority_provenance="trusted_integration",
        ),
    )

def test_authority_constraints_serialization():
    req = VerificationRequest(
        agent=Agent(id="agent-1"),
        principal=None,
        action=Action(type="transfer", target="0xd90e2f925da726b50c4ed8d0fb90ad053324f31b"),
        authority=Authority(
            allowed_actions=["transfer"],
            constraints=AuthorityConstraints(
                sanctions_screening=True,
                blocked_entities=["0xd90e2f925da726b50c4ed8d0fb90ad053324f31b", "garantex.org"],
            ),
        ),
    )
    d = req.to_dict()
    assert d["authority"]["constraints"]["sanctions_screening"] is True
    assert d["authority"]["constraints"]["blocked_entities"] == [
        "0xd90e2f925da726b50c4ed8d0fb90ad053324f31b",
        "garantex.org",
    ]

def test_client_screen_sanctions():
    client = VizierClient(api_key="test-key")
    client._request = MagicMock(return_value={
        "query": "garantex.org",
        "clean": False,
        "match": {"entity_name": "Garantex Exchange", "list": "OFAC_SDN"}
    })

    res = client.screen_sanctions("garantex.org")
    assert res["clean"] is False
    assert res["match"]["entity_name"] == "Garantex Exchange"
    client._request.assert_called_once_with("/v1/sanctions/screen", {"query": "garantex.org"})

def test_async_client_screen_sanctions():
    async def _test():
        client = AsyncVizierClient(api_key="test-key")
        client._sync_client.screen_sanctions = MagicMock(return_value={
            "query": "stripe.com",
            "clean": True,
        })

        res = await client.screen_sanctions("stripe.com")
        assert res["clean"] is True
        client._sync_client.screen_sanctions.assert_called_once_with(query="stripe.com")

    asyncio.run(_test())

def test_guard_with_sanctions_check():
    mock_client = MagicMock()
    mock_client.check.return_value = make_sanctions_blocked_response()

    @vizier_guard(
        client=mock_client,
        action_type="crypto_payout",
        sanctions_check=True,
        blocked_entities=["0xevil"],
    )
    def send_payout(recipient: str, amount: float):
        return f"sent {amount} to {recipient}"

    with pytest.raises(ActionBlockedError) as exc_info:
        send_payout("0xd90e2f925da726b50c4ed8d0fb90ad053324f31b", 50.0)

    assert exc_info.value.response.decision == "BLOCK"
    assert "SANCTIONED_ENTITY_MATCH" in exc_info.value.response.reason_codes
    kwargs = mock_client.check.call_args[1]
    assert kwargs["sanctions_screening"] is True
    assert kwargs["blocked_entities"] == ["0xevil"]

def test_async_guard_with_sanctions_check():
    async def _test():
        from unittest.mock import AsyncMock
        mock_async_client = AsyncMock()
        mock_async_client.check.return_value = make_sanctions_blocked_response()

        @vizier_guard(
            client=mock_async_client,
            action_type="crypto_payout",
            sanctions_check=True,
        )
        async def async_send_payout(recipient: str, amount: float):
            return f"sent {amount} to {recipient}"

        with pytest.raises(ActionBlockedError) as exc_info:
            await async_send_payout("0xd90e2f925da726b50c4ed8d0fb90ad053324f31b", 10.0)

        assert exc_info.value.response.decision == "BLOCK"
        kwargs = mock_async_client.check.call_args[1]
        assert kwargs["sanctions_screening"] is True

    asyncio.run(_test())
