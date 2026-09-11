from __future__ import annotations
import json
import urllib.request
import urllib.error
from typing import Any, Dict, Optional

from .base import BaseHITLHandler, HITLApprovalResult
from ..models import VerificationResponse

class WebhookHITLHandler(BaseHITLHandler):
    """
    Generic HTTP Webhook Human-in-the-Loop handler.
    POSTs action review details to an external endpoint (Slack incoming webhook, internal dashboard, etc.).
    If the endpoint responds with JSON {"approved": true/false}, returns the operator verdict.
    """

    def __init__(
        self,
        webhook_url: str,
        auth_header: Optional[str] = None,
        timeout: float = 30.0,
    ):
        self.webhook_url = webhook_url
        self.auth_header = auth_header
        self.timeout = timeout

    def request_approval(
        self,
        action_type: str,
        target: str,
        parameters: Dict[str, Any],
        verification: VerificationResponse,
    ) -> HITLApprovalResult:
        payload = {
            "event": "vizier.hitl.review_requested",
            "action": {
                "type": action_type,
                "target": target,
                "parameters": parameters,
            },
            "decision": verification.decision,
            "risk_score": verification.risk_score,
            "explanation": verification.explanation,
            "reason_codes": verification.reason_codes,
            "receipt": {
                "id": verification.receipt.id,
                "request_hash": verification.receipt.request_hash,
            },
        }

        headers = {"Content-Type": "application/json"}
        if self.auth_header:
            headers["Authorization"] = self.auth_header

        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(self.webhook_url, data=data, headers=headers, method="POST")

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                body = resp.read().decode("utf-8")
                try:
                    res_json = json.loads(body)
                    approved = bool(res_json.get("approved", False))
                    reason = (
                        res_json.get("reason", "Approved via webhook")
                        if approved
                        else res_json.get("reason", "Rejected via webhook")
                    )
                    return HITLApprovalResult(
                        approved=approved,
                        reason=reason,
                        operator_id=res_json.get("operator_id", "webhook_operator"),
                        grant=res_json.get("grant"),
                    )
                except Exception:
                    return HITLApprovalResult(
                        approved=True,
                        reason=f"Webhook acknowledged with HTTP {resp.status}",
                        operator_id="webhook",
                    )
        except Exception as err:
            return HITLApprovalResult(
                approved=False,
                reason=f"Webhook request failed: {err}",
            )
