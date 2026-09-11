from __future__ import annotations
from typing import Any, Callable, Dict, List, Optional

from ..client import VizierClient
from ..decorators import ActionBlockedError
from ..models import VerificationResponse

class VizierLangChainToolGuard:
    """
    Wrapper for LangChain BaseTool instances.
    Intercepts tool calls, verifies with Vizier, and blocks execution on BLOCK or REVIEW.
    """

    def __init__(
        self,
        tool: Any,
        client: Optional[VizierClient] = None,
        allowed_actions: Optional[List[str]] = None,
        max_amount: Optional[float] = None,
        currency: Optional[str] = None,
        allowed_targets: Optional[List[str]] = None,
        blocked_targets: Optional[List[str]] = None,
        agent_id: str = "langchain_agent",
        principal_id: str = "principal",
    ):
        self.tool = tool
        self.client = client or VizierClient()
        self.allowed_actions = allowed_actions or [getattr(tool, "name", "tool")]
        self.max_amount = max_amount
        self.currency = currency
        self.allowed_targets = allowed_targets
        self.blocked_targets = blocked_targets
        self.agent_id = agent_id
        self.principal_id = principal_id

        # Preserve LangChain tool metadata
        self.name = getattr(tool, "name", "guarded_tool")
        self.description = getattr(tool, "description", "")
        self.args_schema = getattr(tool, "args_schema", None)

    def _verify(self, tool_input: Any) -> VerificationResponse:
        params: Dict[str, Any]
        if isinstance(tool_input, dict):
            params = tool_input
        else:
            params = {"input": tool_input}

        target = str(params.get("target") or params.get("destination") or self.name)
        return self.client.check(
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

    def run(self, *args: Any, **kwargs: Any) -> Any:
        tool_input = kwargs if kwargs else (args[0] if args else {})
        res = self._verify(tool_input)
        if not res.is_allowed:
            return f"Error: Tool execution blocked by security policy ({res.decision}): {res.explanation}"
        return self.tool.run(*args, **kwargs)

    async def arun(self, *args: Any, **kwargs: Any) -> Any:
        tool_input = kwargs if kwargs else (args[0] if args else {})
        res = self._verify(tool_input)
        if not res.is_allowed:
            return f"Error: Tool execution blocked by security policy ({res.decision}): {res.explanation}"
        return await self.tool.arun(*args, **kwargs)

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        return self.run(*args, **kwargs)
