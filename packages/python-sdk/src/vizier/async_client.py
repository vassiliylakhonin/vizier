from __future__ import annotations
import asyncio
from typing import Any, Dict, List, Optional, Union

from .client import VizierClient, VizierError
from .models import (
    VerificationRequest,
    VerificationResponse,
    Agent,
    Principal,
    Action,
    Authority,
    AuthorityConstraints,
)

class AsyncVizierClient:
    """
    Asynchronous Vizier Authorization & Governance Client for AI Agents.
    Zero external dependencies required (uses Python asyncio and standard library).
    Designed for async agent runtimes: LangGraph, FastAPI, AutoGen, LlamaIndex.
    """

    def __init__(
        self,
        base_url: str = "https://vizier.vassiliy-lakhonin.workers.dev",
        api_key: Optional[str] = None,
        timeout: float = 5.0,
    ):
        self._sync_client = VizierClient(
            base_url=base_url,
            api_key=api_key,
            timeout=timeout,
        )
        self.base_url = self._sync_client.base_url
        self.api_key = self._sync_client.api_key
        self.timeout = self._sync_client.timeout

    async def verify(
        self,
        request: Union[VerificationRequest, Dict[str, Any]],
        verify_receipt_hash: bool = True,
    ) -> VerificationResponse:
        """
        Asynchronously submit a proposed agent action to Vizier for deterministic authorization.
        Returns VerificationResponse with decision: ALLOW, REVIEW, or BLOCK.
        """
        return await asyncio.to_thread(
            self._sync_client.verify,
            request,
            verify_receipt_hash,
        )

    async def check(
        self,
        action_type: str,
        target: str,
        parameters: Optional[Dict[str, Any]] = None,
        allowed_actions: Optional[List[str]] = None,
        max_amount: Optional[float] = None,
        currency: Optional[str] = None,
        allowed_targets: Optional[List[str]] = None,
        blocked_targets: Optional[List[str]] = None,
        agent_id: str = "agent",
        principal_id: str = "principal",
        is_reversible: Optional[bool] = None,
        grant: Optional[str] = None,
    ) -> VerificationResponse:
        """
        Asynchronously verify an action in a single line of code without blocking the event loop.
        """
        return await asyncio.to_thread(
            self._sync_client.check,
            action_type=action_type,
            target=target,
            parameters=parameters,
            allowed_actions=allowed_actions,
            max_amount=max_amount,
            currency=currency,
            allowed_targets=allowed_targets,
            blocked_targets=blocked_targets,
            agent_id=agent_id,
            principal_id=principal_id,
            is_reversible=is_reversible,
            grant=grant,
        )
