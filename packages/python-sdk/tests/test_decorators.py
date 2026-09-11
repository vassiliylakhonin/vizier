import pytest
from unittest.mock import MagicMock

from vizier import vizier_guard, ActionBlockedError, VerificationResponse
from vizier.models import Receipt, PolicyResult

def make_mock_response(decision: str, explanation: str = "ok"):
    return VerificationResponse(
        decision=decision,
        risk_score=0.0 if decision == "ALLOW" else 0.8,
        reason_codes=[] if decision == "ALLOW" else ["AMOUNT_LIMIT_EXCEEDED"],
        explanation=explanation,
        policy_results=[
            PolicyResult(rule_id="amount.limit", result="PASS" if decision == "ALLOW" else "FAIL", reason_code=None)
        ],
        receipt=Receipt(
            id="vrf_test_123",
            created_at="2026-09-11T00:00:00Z",
            request_hash="a" * 64,
            decision=decision,
            risk_score=0.0,
            policy_rule_ids=["amount.limit"],
            reason_codes=[],
            authority_provenance="trusted_integration",
        ),
    )

def test_decorator_allows_valid_action():
    mock_client = MagicMock()
    mock_client.check.return_value = make_mock_response("ALLOW")

    @vizier_guard(client=mock_client, action_type="test_action", max_amount=100.0)
    def do_work(amount: float, target: str):
        return f"worked on {target} with {amount}"

    result = do_work(50.0, target="server-1")
    assert result == "worked on server-1 with 50.0"
    assert mock_client.check.called
    kwargs = mock_client.check.call_args[1]
    assert kwargs["action_type"] == "test_action"
    assert kwargs["target"] == "server-1"
    assert kwargs["max_amount"] == 100.0

def test_decorator_blocks_invalid_action():
    mock_client = MagicMock()
    mock_client.check.return_value = make_mock_response("BLOCK", explanation="Amount exceeded limit")

    @vizier_guard(client=mock_client, action_type="transfer", max_amount=100.0)
    def transfer(amount: float, target: str):
        return "transferred"

    with pytest.raises(ActionBlockedError) as exc_info:
        transfer(500.0, target="untrusted_account")

    assert "blocked by Vizier (BLOCK)" in str(exc_info.value)
    assert exc_info.value.response.decision == "BLOCK"

def test_decorator_callback_mode():
    mock_client = MagicMock()
    mock_client.check.return_value = make_mock_response("REVIEW", explanation="Manual approval required")

    def handle_block(resp):
        return {"status": "paused_for_human", "decision": resp.decision}

    @vizier_guard(
        client=mock_client,
        action_type="delete_db",
        on_block="callback",
        on_block_callback=handle_block
    )
    def delete_data(db_name: str):
        return "deleted"

    res = delete_data("prod_users")
    assert res == {"status": "paused_for_human", "decision": "REVIEW"}
