from __future__ import annotations
import abc
import asyncio
from dataclasses import dataclass
from typing import Any, Dict, Optional

from ..models import VerificationResponse

@dataclass
class HITLApprovalResult:
    """Represents the human operator's decision for a reviewed action."""
    approved: bool
    reason: str = ""
    operator_id: Optional[str] = None
    grant: Optional[str] = None

class BaseHITLHandler(abc.ABC):
    """
    Abstract Base Class for Human-in-the-Loop (HITL) approval handlers.
    Triggered when Vizier authorization evaluates an action as REVIEW,
    or for sensitive actions requiring interactive human sign-off.
    """

    @abc.abstractmethod
    def request_approval(
        self,
        action_type: str,
        target: str,
        parameters: Dict[str, Any],
        verification: VerificationResponse,
    ) -> HITLApprovalResult:
        """Prompt a human operator for approval synchronously."""
        pass

    async def arequest_approval(
        self,
        action_type: str,
        target: str,
        parameters: Dict[str, Any],
        verification: VerificationResponse,
    ) -> HITLApprovalResult:
        """Prompt a human operator for approval asynchronously without blocking the event loop."""
        return await asyncio.to_thread(
            self.request_approval,
            action_type,
            target,
            parameters,
            verification,
        )
