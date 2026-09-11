import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

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
    Context,
    QuorumConstraints,
    QuorumApproval,
    QuorumProposal,
)
from vizier.models import Receipt, PolicyResult

def make_quorum_blocked_response(reason_code="QUORUM_NOT_MET"):
    return VerificationResponse(
        decision="BLOCK",
        risk_score=0.9,
        reason_codes=[reason_code],
        explanation="The proposed action violates the supplied delegated authority or constraints.",
        policy_results=[
            PolicyResult(
                rule_id="governance.quorum",
                result="FAIL",
                reason_code=reason_code,
                details={
                    "required_approvals": 2,
                    "current_approvals": 0,
                    "missing": 2,
                },
            )
        ],
        receipt=Receipt(
            id="vrf_quorum_test",
            created_at="2026-09-11T00:00:00Z",
            request_hash="q" * 64,
            decision="BLOCK",
            risk_score=0.9,
            policy_rule_ids=["governance.quorum"],
            reason_codes=[reason_code],
            authority_provenance="trusted_integration",
        ),
    )

def make_quorum_allowed_response():
    return VerificationResponse(
        decision="ALLOW",
        risk_score=0.1,
        reason_codes=[],
        explanation="The proposed action is within the supplied delegated authority and constraints.",
        policy_results=[
            PolicyResult(
                rule_id="governance.quorum",
                result="PASS",
                reason_code=None,
                details={
                    "required_approvals": 2,
                    "current_approvals": 2,
                    "approvers": ["auditor-1", "auditor-2"],
                },
            )
        ],
        receipt=Receipt(
            id="vrf_quorum_allowed",
            created_at="2026-09-11T00:00:00Z",
            request_hash="a" * 64,
            decision="ALLOW",
            risk_score=0.1,
            policy_rule_ids=["governance.quorum"],
            reason_codes=[],
            authority_provenance="trusted_integration",
        ),
    )

def test_quorum_models_serialization():
    qc = QuorumConstraints(
        min_approvals=2,
        allowed_approvers=["agent-2", "agent-3"],
        require_distinct_owners=True,
        max_age_seconds=600,
    )
    d = qc.to_dict()
    assert d["min_approvals"] == 2
    assert d["allowed_approvers"] == ["agent-2", "agent-3"]
    assert d["require_distinct_owners"] is True
    assert d["max_age_seconds"] == 600

    qa = QuorumApproval(
        approver_id="agent-2",
        action_hash="a" * 64,
        timestamp="2026-09-11T12:00:00Z",
        decision="APPROVE",
        notes="Looks good",
    )
    ad = qa.to_dict()
    assert ad["approver_id"] == "agent-2"
    assert ad["decision"] == "APPROVE"
    assert ad["notes"] == "Looks good"

    req = VerificationRequest(
        agent=Agent(id="initiator"),
        principal=None,
        action=Action(type="transfer", target="bank", parameters={"amount": 100}),
        authority=Authority(
            allowed_actions=["transfer"],
            constraints=AuthorityConstraints(quorum=qc),
        ),
        context=Context(
            proposal_id="prp_12345",
            approvals=[qa],
        ),
    )
    req_d = req.to_dict()
    assert req_d["authority"]["constraints"]["quorum"]["min_approvals"] == 2
    assert req_d["context"]["proposal_id"] == "prp_12345"
    assert len(req_d["context"]["approvals"]) == 1
    assert req_d["context"]["approvals"][0]["approver_id"] == "agent-2"

def test_client_quorum_endpoints_mock():
    client = VizierClient(api_key="test-key")
    client._request = MagicMock(return_value={"proposal_id": "prp_mock_1", "status": "PENDING"})

    # Propose
    res = client.propose_quorum(
        action_type="transfer_funds",
        target="bank",
        parameters={"amount": 1000},
        min_approvals=2,
        allowed_approvers=["auditor-1", "auditor-2"],
    )
    assert res["proposal_id"] == "prp_mock_1"
    client._request.assert_called_with(
        "/v1/quorum/propose",
        {
            "proposer": {"id": "agent", "owner": None},
            "action": {
                "type": "transfer_funds",
                "target": "bank",
                "parameters": {"amount": 1000},
            },
            "constraints": {
                "min_approvals": 2,
                "allowed_approvers": ["auditor-1", "auditor-2"],
            },
        },
    )

    # Approve
    client._request = MagicMock(return_value={"proposal_id": "prp_mock_1", "status": "APPROVED"})
    app_res = client.approve_quorum(
        proposal_id="prp_mock_1",
        approver_id="auditor-1",
        action_hash="a" * 64,
        decision="APPROVE",
        notes="LGTM",
        timestamp="2026-09-11T12:00:00Z",
    )
    assert app_res["status"] == "APPROVED"
    client._request.assert_called_with(
        "/v1/quorum/approve",
        {
            "proposal_id": "prp_mock_1",
            "approval": {
                "approver_id": "auditor-1",
                "action_hash": "a" * 64,
                "timestamp": "2026-09-11T12:00:00Z",
                "decision": "APPROVE",
                "notes": "LGTM",
            },
        },
    )

def test_async_client_quorum_endpoints_mock():
    async def _test():
        async_client = AsyncVizierClient(api_key="test-key")
        async_client._sync_client.propose_quorum = MagicMock(return_value={"proposal_id": "prp_async", "status": "PENDING"})
        async_client._sync_client.approve_quorum = MagicMock(return_value={"proposal_id": "prp_async", "status": "APPROVED"})
        async_client._sync_client.get_quorum_proposal = MagicMock(return_value={"proposal_id": "prp_async", "status": "APPROVED"})

        res = await async_client.propose_quorum(action_type="deploy", target="edge", min_approvals=2)
        assert res["proposal_id"] == "prp_async"

        app_res = await async_client.approve_quorum(
            proposal_id="prp_async",
            approver_id="supervisor",
            action_hash="b" * 64,
        )
        assert app_res["status"] == "APPROVED"

        get_res = await async_client.get_quorum_proposal("prp_async")
        assert get_res["status"] == "APPROVED"

    asyncio.run(_test())

def test_decorator_quorum_blocking():
    client = VizierClient()
    client.verify = MagicMock(return_value=make_quorum_blocked_response("QUORUM_NOT_MET"))

    @vizier_guard(
        client=client,
        action_type="transfer_funds",
        target="wire_api",
        quorum_min_approvals=2,
    )
    def do_transfer(amount: int):
        return f"Transferred {amount}"

    with pytest.raises(ActionBlockedError) as exc_info:
        do_transfer(5000)

    assert "QUORUM_NOT_MET" in exc_info.value.response.reason_codes

def test_decorator_quorum_allowed():
    client = VizierClient()
    client.verify = MagicMock(return_value=make_quorum_allowed_response())

    @vizier_guard(
        client=client,
        action_type="transfer_funds",
        target="wire_api",
        quorum_min_approvals=2,
        quorum_proposal_id="prp_approved_123",
    )
    def do_transfer(amount: int):
        return f"Transferred {amount}"

    res = do_transfer(5000)
    assert res == "Transferred 5000"
    client.verify.assert_called_once()
    sent_req = client.verify.call_args[0][0]
    assert sent_req.authority.constraints.quorum == {"min_approvals": 2}
    assert sent_req.context.proposal_id == "prp_approved_123"
