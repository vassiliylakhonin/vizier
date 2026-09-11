from __future__ import annotations
from typing import Any, Callable, Dict, List, Optional, Union

from ..client import VizierClient
from ..async_client import AsyncVizierClient
from ..decorators import ActionBlockedError
from ..models import VerificationResponse
from ..hitl.base import BaseHITLHandler

class VizierLangChainToolGuard:
    """
    Enterprise authorization wrapper for LangChain BaseTool instances.
    Intercepts tool calls, verifies with Vizier deterministic kernel,
    and supports Human-in-the-Loop approval for REVIEW decisions.
    """

    def __init__(
        self,
        tool: Any,
        client: Optional[Union[VizierClient, AsyncVizierClient]] = None,
        allowed_actions: Optional[List[str]] = None,
        max_amount: Optional[float] = None,
        currency: Optional[str] = None,
        allowed_targets: Optional[List[str]] = None,
        blocked_targets: Optional[List[str]] = None,
        agent_id: str = "langchain_agent",
        principal_id: str = "principal",
        hitl_handler: Optional[BaseHITLHandler] = None,
    ):
        self.tool = tool
        if isinstance(client, AsyncVizierClient):
            self.async_client = client
            self.client = client._sync_client
        elif isinstance(client, VizierClient):
            self.client = client
            self.async_client = AsyncVizierClient(base_url=client.base_url, api_key=client.api_key, timeout=client.timeout)
        else:
            self.client = VizierClient()
            self.async_client = AsyncVizierClient()

        self.allowed_actions = allowed_actions or [getattr(tool, "name", "tool")]
        self.max_amount = max_amount
        self.currency = currency
        self.allowed_targets = allowed_targets
        self.blocked_targets = blocked_targets
        self.agent_id = agent_id
        self.principal_id = principal_id
        self.hitl_handler = hitl_handler

        # Preserve LangChain tool metadata
        self.name = getattr(tool, "name", "guarded_tool")
        self.description = getattr(tool, "description", "")
        self.args_schema = getattr(tool, "args_schema", None)

    def _prepare_params(self, tool_input: Any) -> tuple[Dict[str, Any], str]:
        if isinstance(tool_input, dict):
            params = dict(tool_input)
        else:
            params = {"input": tool_input}

        if self.currency and "currency" not in params:
            params["currency"] = self.currency

        target = str(params.get("target") or params.get("destination") or self.name)
        return params, target

    def _verify(self, tool_input: Any) -> tuple[VerificationResponse, Dict[str, Any], str]:
        params, target = self._prepare_params(tool_input)
        res = self.client.check(
            action_type=self.name,
            target=target,
            parameters=params,
            allowed_actions=self.allowed_actions,
            max_amount=self.max_amount,
            currency=self.currency,
            allowed_targets=self.allowed_targets,
            blocked_targets=self.blocked_targets,
            agent_id=self.agent_id,
            principal_id=self.principal_id,
        )
        return res, params, target

    async def _averify(self, tool_input: Any) -> tuple[VerificationResponse, Dict[str, Any], str]:
        params, target = self._prepare_params(tool_input)
        res = await self.async_client.check(
            action_type=self.name,
            target=target,
            parameters=params,
            allowed_actions=self.allowed_actions,
            max_amount=self.max_amount,
            currency=self.currency,
            allowed_targets=self.allowed_targets,
            blocked_targets=self.blocked_targets,
            agent_id=self.agent_id,
            principal_id=self.principal_id,
        )
        return res, params, target

    def run(self, *args: Any, **kwargs: Any) -> Any:
        tool_input = kwargs if kwargs else (args[0] if args else {})
        res, params, target = self._verify(tool_input)

        if res.decision == "REVIEW" and self.hitl_handler:
            approval = self.hitl_handler.request_approval(self.name, target, params, res)
            if approval.approved:
                return self.tool.run(*args, **kwargs)

        if not res.is_allowed:
            return f"Error: Tool execution blocked by security policy ({res.decision}): {res.explanation}"

        return self.tool.run(*args, **kwargs)

    async def arun(self, *args: Any, **kwargs: Any) -> Any:
        tool_input = kwargs if kwargs else (args[0] if args else {})
        res, params, target = await self._averify(tool_input)

        if res.decision == "REVIEW" and self.hitl_handler:
            approval = await self.hitl_handler.arequest_approval(self.name, target, params, res)
            if approval.approved:
                return await self.tool.arun(*args, **kwargs)

        if not res.is_allowed:
            return f"Error: Tool execution blocked by security policy ({res.decision}): {res.explanation}"

        return await self.tool.arun(*args, **kwargs)

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        return self.run(*args, **kwargs)
