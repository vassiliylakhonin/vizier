from __future__ import annotations
import functools
import inspect
from typing import Any, Callable, Dict, List, Optional, Union

from .client import VizierClient
from .models import VerificationResponse

class ActionBlockedError(Exception):
    def __init__(self, response: VerificationResponse):
        super().__init__(
            f"Action blocked by Vizier ({response.decision}): {response.explanation}. Reason codes: {response.reason_codes}"
        )
        self.response = response

def vizier_guard(
    client: Optional[VizierClient] = None,
    action_type: Optional[str] = None,
    target: Optional[Union[str, Callable[..., str]]] = None,
    allowed_actions: Optional[List[str]] = None,
    max_amount: Optional[Union[float, Callable[..., Optional[float]]]] = None,
    currency: Optional[str] = None,
    allowed_targets: Optional[List[str]] = None,
    blocked_targets: Optional[List[str]] = None,
    agent_id: str = "agent",
    principal_id: str = "principal",
    on_block: str = "raise", # "raise" or "callback"
    on_block_callback: Optional[Callable[[VerificationResponse], Any]] = None,
):
    """
    Decorator to protect any Python function / agent tool with Vizier deterministic authorization.
    Before the function executes, Vizier checks the proposed action, parameters, and constraints.
    If ALLOW, the function executes.
    If BLOCK or REVIEW, execution is halted immediately.
    """
    viz_client = client or VizierClient()

    def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
        act_type = action_type or fn.__name__

        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            # Bind arguments to function signature
            sig = inspect.signature(fn)
            bound = sig.bind(*args, **kwargs)
            bound.apply_defaults()
            params = dict(bound.arguments)

            # Resolve target
            if callable(target):
                resolved_target = target(*args, **kwargs)
            elif isinstance(target, str):
                resolved_target = target
            else:
                resolved_target = params.get("target") or params.get("destination") or "default_target"

            # Resolve max amount if dynamic
            resolved_max_amount: Optional[float]
            if callable(max_amount):
                resolved_max_amount = max_amount(*args, **kwargs)
            else:
                resolved_max_amount = max_amount

            # Check if amount and currency are inside parameters
            amount = params.get("amount") or params.get("price")
            curr = params.get("currency") or currency
            if curr and "currency" not in params:
                params["currency"] = curr

            verification = viz_client.check(
                action_type=act_type,
                target=str(resolved_target),
                parameters=params,
                allowed_actions=allowed_actions or [act_type],
                max_amount=resolved_max_amount,
                currency=curr,
                allowed_targets=allowed_targets,
                blocked_targets=blocked_targets,
                agent_id=agent_id,
                principal_id=principal_id,
            )

            if not verification.is_allowed:
                if on_block == "callback" and on_block_callback:
                    return on_block_callback(verification)
                raise ActionBlockedError(verification)

            # Store the receipt in a context attribute if possible
            result = fn(*args, **kwargs)
            return result

        # Attach reference to verification check on the wrapper
        wrapper.__vizier_client__ = viz_client  # type: ignore
        return wrapper

    return decorator
