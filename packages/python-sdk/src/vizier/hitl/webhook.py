from __future__ import annotations
import json
import urllib.request
import urllib.error
from typing import Any, Dict, Optional

from .base import BaseHITLHandler, HITLApprovalResult
from ..models import VerificationResponse

class _DisallowRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, f"HTTP redirect to '{newurl}' is disallowed", headers, fp)

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
        self._opener = urllib.request.build_opener(_DisallowRedirects())

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
            with self._opener.open(req, timeout=self.timeout) as resp:
                content_type = resp.headers.get_content_type()
                if content_type != "application/json":
                    return HITLApprovalResult(
                        approved=False,
                        reason=f"Webhook returned invalid Content-Type '{content_type}'; expected 'application/json'",
                        operator_id="webhook",
                    )
                body = resp.read().decode("utf-8")
                try:
                    res_json = json.loads(body)
                    if not isinstance(res_json, dict):
                        return HITLApprovalResult(
                            approved=False,
                            reason="Webhook returned invalid non-object JSON payload",
                            operator_id="webhook",
                        )
                    approved_val = res_json.get("approved")
                    if type(approved_val) is not bool:
                        return HITLApprovalResult(
                            approved=False,
                            reason=f"Webhook 'approved' field must be a strict boolean (true/false), got {type(approved_val).__name__}",
                            operator_id="webhook",
                        )
                    approved = approved_val
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
                except Exception as parse_err:
                    return HITLApprovalResult(
                        approved=False,
                        reason=f"Webhook returned non-JSON or invalid payload: {parse_err}",
                        operator_id="webhook",
                    )
        except Exception as err:
            return HITLApprovalResult(
                approved=False,
                reason=f"Webhook request failed: {err}",
            )
