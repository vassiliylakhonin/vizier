from __future__ import annotations
import asyncio
from typing import Any, Dict, List, Optional, Union

from .client import VizierClient, VizierError
from .models import (
    Action,
    Agent,
    Authority,
    AuthorityConstraints,
    Principal,
    QuorumApproval,
    QuorumConstraints,
    QuorumProposal,
    VerificationRequest,
    VerificationResponse,
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

    async def screen_sanctions(
        self,
        query: str,
    ) -> Dict[str, Any]:
        """
        Asynchronously screen an entity, domain, crypto address, or IBAN against sanctions lists.
        """
        return await asyncio.to_thread(
            self._sync_client.screen_sanctions,
            query=query,
        )

    async def scan_dlp(
        self,
        text: Optional[str] = None,
        parameters: Optional[Dict[str, Any]] = None,
        allowed_categories: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Asynchronously scan text or parameters for secrets and PII.
        """
        return await asyncio.to_thread(
            self._sync_client.scan_dlp,
            text=text,
            parameters=parameters,
            allowed_categories=allowed_categories,
        )

    async def propose_quorum(
        self,
        action_type: str,
        target: str,
        parameters: Optional[Dict[str, Any]] = None,
        min_approvals: int = 1,
        allowed_approvers: Optional[List[str]] = None,
        require_distinct_owners: Optional[bool] = None,
        proposer_id: str = "agent",
        proposer_owner: Optional[str] = None,
        ttl_seconds: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Asynchronously propose a critical action for multi-agent quorum review.
        """
        return await asyncio.to_thread(
            self._sync_client.propose_quorum,
            action_type=action_type,
            target=target,
            parameters=parameters,
            min_approvals=min_approvals,
            allowed_approvers=allowed_approvers,
            require_distinct_owners=require_distinct_owners,
            proposer_id=proposer_id,
            proposer_owner=proposer_owner,
            ttl_seconds=ttl_seconds,
        )

    async def approve_quorum(
        self,
        proposal_id: str,
        approver_id: str,
        action_hash: str,
        decision: str = "APPROVE",
        approver_owner: Optional[str] = None,
        notes: Optional[str] = None,
        timestamp: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Asynchronously approve or reject a pending quorum proposal.
        """
        return await asyncio.to_thread(
            self._sync_client.approve_quorum,
            proposal_id=proposal_id,
            approver_id=approver_id,
            action_hash=action_hash,
            decision=decision,
            approver_owner=approver_owner,
            notes=notes,
            timestamp=timestamp,
        )

    async def get_quorum_proposal(self, proposal_id: str) -> Dict[str, Any]:
        """
        Asynchronously query status and approval records for a quorum proposal.
        """
        return await asyncio.to_thread(
            self._sync_client.get_quorum_proposal,
            proposal_id=proposal_id,
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
        session_id: Optional[str] = None,
        is_reversible: Optional[bool] = None,
        grant: Optional[str] = None,
        sanctions_screening: Optional[bool] = None,
        blocked_entities: Optional[List[str]] = None,
        dlp_screening: Optional[bool] = None,
        allowed_dlp_categories: Optional[List[str]] = None,
        proposal_id: Optional[str] = None,
        approvals: Optional[List[Union[QuorumApproval, Dict[str, Any]]]] = None,
        quorum: Optional[Union[QuorumConstraints, Dict[str, Any]]] = None,
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
            session_id=session_id,
            is_reversible=is_reversible,
            grant=grant,
            sanctions_screening=sanctions_screening,
            blocked_entities=blocked_entities,
            dlp_screening=dlp_screening,
            allowed_dlp_categories=allowed_dlp_categories,
            proposal_id=proposal_id,
            approvals=approvals,
            quorum=quorum,
        )

