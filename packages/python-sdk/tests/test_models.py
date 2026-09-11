import pytest
from vizier.models import (
    Agent, Principal, Action, Authority, AuthorityConstraints,
    VerificationRequest, VerificationResponse
)

def test_verification_request_to_dict():
    req = VerificationRequest(
        agent=Agent(id="ag_1", owner="corp"),
        principal=Principal(id="corp"),
        action=Action(type="deploy", target="worker:1", parameters={"v": 2}),
        authority=Authority(
            allowed_actions=["deploy"],
            constraints=AuthorityConstraints(max_amount=50.0, currency="USD", allowed_targets=["worker:1"])
        )
    )
    d = req.to_dict()
    assert d["agent"] == {"id": "ag_1", "owner": "corp"}
    assert d["principal"] == {"id": "corp"}
    assert d["action"]["type"] == "deploy"
    assert d["authority"]["allowed_actions"] == ["deploy"]
    assert d["authority"]["constraints"]["max_amount"] == 50.0
    assert d["authority"]["constraints"]["allowed_targets"] == ["worker:1"]
    assert d["context"]["source"] == "rest"

def test_verification_response_from_dict():
    raw = {
        "decision": "ALLOW",
        "risk_score": 0.0,
        "reason_codes": [],
        "explanation": "Action allowed",
        "policy_results": [
            {"rule_id": "rule.1", "result": "PASS", "reason_code": None, "details": {}}
        ],
        "receipt": {
            "id": "vrf_1",
            "created_at": "2026-09-11T00:00:00Z",
            "request_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "decision": "ALLOW",
            "risk_score": 0.0,
            "policy_rule_ids": ["rule.1"],
            "reason_codes": [],
            "authority_provenance": "principal_signed",
            "grant": {
                "jti": "g_1",
                "issuer": "corp",
                "subject": "ag_1",
                "key_id": "k_1",
                "expires_at": "2026-09-12T00:00:00Z"
            }
        }
    }
    resp = VerificationResponse.from_dict(raw)
    assert resp.is_allowed is True
    assert resp.is_blocked is False
    assert resp.receipt.id == "vrf_1"
    assert resp.receipt.grant is not None
    assert resp.receipt.grant.key_id == "k_1"
    assert resp.policy_results[0].rule_id == "rule.1"
