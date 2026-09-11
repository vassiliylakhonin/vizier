from __future__ import annotations
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Literal, Optional, Union

Decision = Literal["ALLOW", "REVIEW", "BLOCK"]
Source = Literal["a2a", "mcp", "rest", "internal", "unknown"]
AuthorityProvenance = Literal["principal_signed", "trusted_integration", "unverified"]

@dataclass
class Agent:
    id: str
    owner: Optional[str] = None

@dataclass
class Principal:
    id: str

@dataclass
class Action:
    type: str
    target: str
    parameters: Dict[str, Any] = field(default_factory=dict)
    is_reversible: Optional[bool] = None

@dataclass
class AuthorityConstraints:
    max_amount: Optional[float] = None
    currency: Optional[str] = None
    allowed_targets: Optional[List[str]] = None
    blocked_targets: Optional[List[str]] = None
    allowed_sensitive_actions: Optional[List[str]] = None
    require_review_for_irreversible: Optional[bool] = None

@dataclass
class Authority:
    allowed_actions: List[str] = field(default_factory=list)
    constraints: AuthorityConstraints = field(default_factory=AuthorityConstraints)

@dataclass
class Context:
    request_id: Optional[str] = None
    timestamp: Optional[str] = None
    source: Source = "rest"

@dataclass
class VerificationRequest:
    agent: Agent
    principal: Optional[Principal]
    action: Action
    authority: Authority
    context: Context = field(default_factory=Context)
    grant: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "agent": {"id": self.agent.id, "owner": self.agent.owner},
            "principal": {"id": self.principal.id} if self.principal else None,
            "action": {
                "type": self.action.type,
                "target": self.action.target,
                "parameters": self.action.parameters,
            },
            "authority": {
                "allowed_actions": self.authority.allowed_actions,
                "constraints": {},
            },
            "context": {
                "request_id": self.context.request_id,
                "timestamp": self.context.timestamp,
                "source": self.context.source,
            },
        }
        if self.action.is_reversible is not None:
            d["action"]["is_reversible"] = self.action.is_reversible

        c = self.authority.constraints
        cd = d["authority"]["constraints"]
        if c.max_amount is not None:
            cd["max_amount"] = c.max_amount
        if c.currency is not None:
            cd["currency"] = c.currency
        if c.allowed_targets is not None:
            cd["allowed_targets"] = c.allowed_targets
        if c.blocked_targets is not None:
            cd["blocked_targets"] = c.blocked_targets
        if c.allowed_sensitive_actions is not None:
            cd["allowed_sensitive_actions"] = c.allowed_sensitive_actions
        if c.require_review_for_irreversible is not None:
            cd["require_review_for_irreversible"] = c.require_review_for_irreversible

        if self.grant is not None:
            d["grant"] = self.grant
        return d

@dataclass
class PolicyResult:
    rule_id: str
    result: Literal["PASS", "REVIEW", "FAIL"]
    reason_code: Optional[str]
    details: Dict[str, Any] = field(default_factory=dict)

@dataclass
class ReceiptGrant:
    jti: str
    issuer: str
    subject: str
    key_id: str
    expires_at: str

@dataclass
class Receipt:
    id: str
    created_at: str
    request_hash: str
    decision: Decision
    risk_score: float
    policy_rule_ids: List[str]
    reason_codes: List[str]
    authority_provenance: AuthorityProvenance
    grant: Optional[ReceiptGrant] = None

@dataclass
class VerificationResponse:
    decision: Decision
    risk_score: float
    reason_codes: List[str]
    explanation: str
    policy_results: List[PolicyResult]
    receipt: Receipt

    @property
    def is_allowed(self) -> bool:
        return self.decision == "ALLOW"

    @property
    def is_blocked(self) -> bool:
        return self.decision == "BLOCK"

    @property
    def requires_review(self) -> bool:
        return self.decision == "REVIEW"

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> VerificationResponse:
        results = [
            PolicyResult(
                rule_id=r["rule_id"],
                result=r["result"],
                reason_code=r.get("reason_code"),
                details=r.get("details", {}),
            )
            for r in data.get("policy_results", [])
        ]
        rc = data["receipt"]
        grant_data = rc.get("grant")
        grant = ReceiptGrant(**grant_data) if grant_data else None

        receipt = Receipt(
            id=rc["id"],
            created_at=rc["created_at"],
            request_hash=rc["request_hash"],
            decision=rc["decision"],
            risk_score=float(rc["risk_score"]),
            policy_rule_ids=list(rc.get("policy_rule_ids", [])),
            reason_codes=list(rc.get("reason_codes", [])),
            authority_provenance=rc.get("authority_provenance", "unverified"),
            grant=grant,
        )

        return cls(
            decision=data["decision"],
            risk_score=float(data["risk_score"]),
            reason_codes=list(data.get("reason_codes", [])),
            explanation=data.get("explanation", ""),
            policy_results=results,
            receipt=receipt,
        )
