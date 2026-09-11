from __future__ import annotations
from typing import Any, Callable, Dict, List, Optional

from ..client import VizierClient
from ..models import VerificationResponse

class VizierCrewAIToolGuard:
    """
    CrewAI Tool wrapper. Protects agents in CrewAI from unauthorized or out-of-budget actions.
    """

    def __init__(
        self,
        tool: Any,
        client: Optional[VizierClient] = None,
        max_amount: Optional[float] = None,
        allowed_targets: Optional[List[str]] = None,
        agent_id: str = "crewai_agent",
        principal_id: str = "principal",
    ):
        self.tool = tool
        self.client = client or VizierClient()
        self.max_amount = max_amount
        self.allowed_targets = allowed_targets
        self.agent_id = agent_id
        self.principal_id = principal_id

        self.name = getattr(tool, "name", "guarded_tool")
        self.description = getattr(tool, "description", "")

    def _run(self, *args: Any, **kwargs: Any) -> Any:
        params: Dict[str, Any] = kwargs if kwargs else (args[0] if args and isinstance(args[0], dict) else {"input": args})
        target = str(params.get("target") or self.name)

        res = self.client.check(
            action_type=self.name,
            target=target,
            parameters=params,
            allowed_actions=[self.name],
            max_amount=self.max_amount,
            allowed_targets=self.allowed_targets,
            agent_id=self.agent_id,
            principal_id=self.principal_id,
        )

        if not res.is_allowed:
            return f"Action blocked by Vizier ({res.decision}): {res.explanation}. Reason codes: {res.reason_codes}"

        if hasattr(self.tool, "_run"):
            return self.tool._run(*args, **kwargs)
        if callable(self.tool):
            return self.tool(*args, **kwargs)
        return "Tool executed"
