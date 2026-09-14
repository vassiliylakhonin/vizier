import asyncio
from unittest.mock import MagicMock, patch

from vizier import (
    VizierClient,
    AsyncVizierClient,
    vizier_guard,
    ActionBlockedError,
    CliHITLHandler,
    TelegramHITLHandler,
    WebhookHITLHandler,
    HITLApprovalResult,
)
from vizier.models import VerificationResponse, Receipt

def mock_review_response() -> VerificationResponse:
    return VerificationResponse(
        decision="REVIEW",
        risk_score=0.3,
        reason_codes=["SENSITIVE_ACTION_REVIEW"],
        explanation="Sensitive action requires human approval",
        policy_results=[],
        receipt=Receipt(
            id="vrf_review_1",
            created_at="2026-09-11T12:00:00.000Z",
            request_hash="abcd1234",
            decision="REVIEW",
            risk_score=0.3,
            policy_rule_ids=["sensitive.action"],
            reason_codes=["SENSITIVE_ACTION_REVIEW"],
            authority_provenance="trusted_integration",
        ),
    )

def test_cli_hitl_handler_approval():
    handler = CliHITLHandler()
    review = mock_review_response()

    with patch("sys.stdin.readline", return_value="y\n"):
        res = handler.request_approval("transfer", "bank.corp", {"amount": 500}, review)
        assert res.approved
        assert res.operator_id == "cli_operator"

    with patch("sys.stdin.readline", return_value="n\n"):
        res = handler.request_approval("transfer", "bank.corp", {"amount": 500}, review)
        assert not res.approved

def test_webhook_hitl_handler():
    handler = WebhookHITLHandler(webhook_url="https://hooks.example/approval")
    review = mock_review_response()

    mock_resp = MagicMock()
    mock_resp.__enter__.return_value = mock_resp
    mock_resp.read.return_value = b'{"approved": true, "operator_id": "manager_bob"}'

    with patch("urllib.request.urlopen", return_value=mock_resp):
        res = handler.request_approval("transfer", "bank.corp", {"amount": 500}, review)
        assert res.approved
        assert res.operator_id == "manager_bob"

def test_webhook_hitl_handler_non_json_fails_closed():
    handler = WebhookHITLHandler(webhook_url="https://hooks.example/approval")
    review = mock_review_response()

    mock_resp = MagicMock()
    mock_resp.__enter__.return_value = mock_resp
    mock_resp.read.return_value = b"<html><body>502 Bad Gateway</body></html>"
    mock_resp.status = 200

    with patch("urllib.request.urlopen", return_value=mock_resp):
        res = handler.request_approval("transfer", "bank.corp", {"amount": 500}, review)
        assert not res.approved
        assert "non-JSON" in res.reason

def test_webhook_hitl_handler_invalid_structure_fails_closed():
    handler = WebhookHITLHandler(webhook_url="https://hooks.example/approval")
    review = mock_review_response()

    mock_resp = MagicMock()
    mock_resp.__enter__.return_value = mock_resp
    mock_resp.read.return_value = b'["not", "an", "object"]'
    mock_resp.status = 200

    with patch("urllib.request.urlopen", return_value=mock_resp):
        res = handler.request_approval("transfer", "bank.corp", {"amount": 500}, review)
        assert not res.approved
        assert "non-object" in res.reason

def test_webhook_hitl_handler_missing_approved_field_defaults_to_false():
    handler = WebhookHITLHandler(webhook_url="https://hooks.example/approval")
    review = mock_review_response()

    mock_resp = MagicMock()
    mock_resp.__enter__.return_value = mock_resp
    mock_resp.read.return_value = b'{"status": "ok", "message": "acknowledged"}'

    with patch("urllib.request.urlopen", return_value=mock_resp):
        res = handler.request_approval("transfer", "bank.corp", {"amount": 500}, review)
        assert not res.approved
        assert "Rejected" in res.reason

def test_telegram_hitl_handler():
    handler = TelegramHITLHandler(bot_token="123456:ABC-DEF", chat_id="100200300", timeout=5.0)
    review = mock_review_response()

    with patch.object(handler, "_api_call") as mock_call:
        mock_call.side_effect = [
            {"ok": True, "result": {"message_id": 999}},
            {
                "ok": True,
                "result": [
                    {
                        "update_id": 1,
                        "callback_query": {
                            "id": "cb_1",
                            "data": "vz_app_nonces12",
                            "from": {"username": "alice"},
                        },
                    }
                ],
            },
            {"ok": True},
            {"ok": True},
        ]
        with patch("uuid.uuid4") as mock_uuid:
            mock_uuid.return_value.hex = "nonces1234"
            res = handler.request_approval("transfer", "bank.corp", {"amount": 500}, review)
            assert res.approved
            assert res.operator_id == "telegram:alice"

def test_vizier_guard_sync_with_hitl_approval():
    mock_client = MagicMock()
    mock_client.check.return_value = mock_review_response()

    mock_hitl = MagicMock()
    mock_hitl.request_approval.return_value = HITLApprovalResult(
        approved=True, reason="Approved by admin"
    )

    @vizier_guard(client=mock_client, action_type="deploy_worker", hitl_handler=mock_hitl)
    def deploy_worker(name: str):
        return f"worker {name} deployed successfully"

    result = deploy_worker("auth-service")
    assert result == "worker auth-service deployed successfully"
    mock_hitl.request_approval.assert_called_once()

def test_vizier_guard_sync_with_hitl_rejection():
    mock_client = MagicMock()
    mock_client.check.return_value = mock_review_response()

    mock_hitl = MagicMock()
    mock_hitl.request_approval.return_value = HITLApprovalResult(
        approved=False, reason="Rejected by admin"
    )

    @vizier_guard(client=mock_client, action_type="deploy_worker", hitl_handler=mock_hitl)
    def deploy_worker(name: str):
        return "should not execute"

    try:
        deploy_worker("auth-service")
        assert False, "Should have raised ActionBlockedError"
    except ActionBlockedError:
        pass

def test_vizier_guard_async_with_hitl_approval():
    async def _test():
        mock_client = MagicMock()

        async def fake_check(*args, **kwargs):
            return mock_review_response()

        mock_client.check.side_effect = fake_check

        mock_hitl = MagicMock()

        async def fake_approval(*args, **kwargs):
            return HITLApprovalResult(approved=True, reason="Approved via async HITL")

        mock_hitl.arequest_approval.side_effect = fake_approval

        @vizier_guard(client=mock_client, action_type="delete_table", hitl_handler=mock_hitl)
        async def delete_table(table_name: str):
            return f"table {table_name} deleted"

        res = await delete_table("audit_logs")
        assert res == "table audit_logs deleted"
        mock_hitl.arequest_approval.assert_called_once()

    asyncio.run(_test())
