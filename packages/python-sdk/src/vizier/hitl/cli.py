from __future__ import annotations
import json
import sys
from typing import Any, Dict

from .base import BaseHITLHandler, HITLApprovalResult
from ..models import VerificationResponse

class CliHITLHandler(BaseHITLHandler):
    """
    Terminal / CLI interactive human approval handler.
    Presents action details, explanation, and reason codes in terminal,
    prompting operator for explicit [y/N] confirmation.
    """

    def __init__(self, prompt_prefix: str = "⚡ [Vizier HITL]"):
        self.prompt_prefix = prompt_prefix

    def request_approval(
        self,
        action_type: str,
        target: str,
        parameters: Dict[str, Any],
        verification: VerificationResponse,
    ) -> HITLApprovalResult:
        banner = (
            f"\n{'='*55}\n"
            f"⚠️  {self.prompt_prefix} ACTION REVIEW REQUIRED\n"
            f"{'-'*55}\n"
            f"Action:       {action_type}\n"
            f"Target:       {target}\n"
            f"Parameters:   {json.dumps(parameters, default=str)}\n"
            f"Decision:     {verification.decision}\n"
            f"Risk Score:   {verification.risk_score}\n"
            f"Explanation:  {verification.explanation}\n"
            f"Reason Codes: {verification.reason_codes}\n"
            f"{'='*55}\n"
            f"Approve this action? [y/N]: "
        )
        sys.stdout.write(banner)
        sys.stdout.flush()

        try:
            choice = sys.stdin.readline().strip().lower()
        except Exception:
            choice = "n"

        if choice in ("y", "yes"):
            return HITLApprovalResult(
                approved=True,
                reason="Approved by human operator via CLI prompt.",
                operator_id="cli_operator",
            )

        return HITLApprovalResult(
            approved=False,
            reason="Action rejected or unconfirmed by operator via CLI prompt.",
            operator_id="cli_operator",
        )
