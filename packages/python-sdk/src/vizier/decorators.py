from __future__ import annotations
import functools
import inspect
from typing import Any, Callable, Dict, List, Optional, Union

from .client import VizierClient
from .async_client import AsyncVizierClient
from .models import VerificationResponse
from .hitl.base import BaseHITLHandler, HITLApprovalResult

class ActionBlockedError(Exception):
    def __init__(self, response: VerificationResponse):
        super().__init__(
            f"Action blocked by Vizier ({response.decision}): {response.explanation}. Reason codes: {response.reason_codes}"
        )
        self.response = response

def vizier_guard(
    client: Optional[Union[VizierClient, AsyncVizierClient]] = None,
    action_type: Optional[str] = None,
    target: Optional[Union[str, Callable[..., str]]] = None,
    allowed_actions: Optional[List[str]] = None,
    max_amount: Optional[Union[float, Callable[..., Optional[float]]]] = None,
    currency: Optional[str] = None,
    allowed_targets: Optional[List[str]] = None,
    blocked_targets: Optional[List[str]] = None,
    agent_id: str = "agent",
    principal_id: str = "principal",
    on_block: str = "raise",  # "raise" or "callback"
    on_block_callback: Optional[Callable[[VerificationResponse], Any]] = None,
    hitl_handler: Optional[BaseHITLHandler] = None,
):
    """
    Decorator to protect any Python function / agent tool with Vizier deterministic authorization.
    Supports BOTH synchronous (def) and asynchronous (async def) functions seamlessly.

    Before the function executes, Vizier checks the proposed action, parameters, and constraints.
    - If ALLOW: executes immediately.
    - If REVIEW and hitl_handler is configured: requests human operator approval (CLI / Telegram / Webhook).
    - If BLOCK: halts execution immediately with ActionBlockedError.
    """

    def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
        act_type = action_type or fn.__name__
        is_async = inspect.iscoroutinefunction(fn)

        def _prepare_args(args: Any, kwargs: Any) -> tuple[Dict[str, Any], str, Optional[float], Optional[str]]:
            sig = inspect.signature(fn)
            bound = sig.bind(*args, **kwargs)
            bound.apply_defaults()
            params = dict(bound.arguments)

            if callable(target):
                resolved_target = target(*args, **kwargs)
            elif isinstance(target, str):
                resolved_target = target
            else:
                resolved_target = params.get("target") or params.get("destination") or "default_target"

            if callable(max_amount):
                resolved_max_amount = max_amount(*args, **kwargs)
            else:
                resolved_max_amount = max_amount

            curr = params.get("currency") or currency
            if curr and "currency" not in params:
                params["currency"] = curr

            return params, str(resolved_target), resolved_max_amount, curr

        if is_async:
            if isinstance(client, AsyncVizierClient):
                async_cli = client
            elif isinstance(client, VizierClient):
                async_cli = AsyncVizierClient(base_url=client.base_url, api_key=client.api_key, timeout=client.timeout)
            elif client is not None:
                async_cli = client
            else:
                async_cli = AsyncVizierClient()

            @functools.wraps(fn)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                params, resolved_target, resolved_max_amount, curr = _prepare_args(args, kwargs)

                verification = await async_cli.check(
                    action_type=act_type,
                    target=resolved_target,
                    parameters=params,
                    allowed_actions=allowed_actions or [act_type],
                    max_amount=resolved_max_amount,
                    currency=curr,
                    allowed_targets=allowed_targets,
                    blocked_targets=blocked_targets,
                    agent_id=agent_id,
                    principal_id=principal_id,
                )

                if verification.decision == "REVIEW" and hitl_handler:
                    approval = await hitl_handler.arequest_approval(
                        act_type, resolved_target, params, verification
                    )
                    if approval.approved:
                        return await fn(*args, **kwargs)

                if not verification.is_allowed:
                    if on_block == "callback" and on_block_callback:
                        return on_block_callback(verification)
                    raise ActionBlockedError(verification)

                return await fn(*args, **kwargs)

            async_wrapper.__vizier_client__ = async_cli  # type: ignore
            return async_wrapper

        else:
            if isinstance(client, AsyncVizierClient):
                sync_cli = client._sync_client
            elif client is not None:
                sync_cli = client
            else:
                sync_cli = VizierClient()

            @functools.wraps(fn)
            def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
                params, resolved_target, resolved_max_amount, curr = _prepare_args(args, kwargs)

                verification = sync_cli.check(
                    action_type=act_type,
                    target=resolved_target,
                    parameters=params,
                    allowed_actions=allowed_actions or [act_type],
                    max_amount=resolved_max_amount,
                    currency=curr,
                    allowed_targets=allowed_targets,
                    blocked_targets=blocked_targets,
                    agent_id=agent_id,
                    principal_id=principal_id,
                )

                if verification.decision == "REVIEW" and hitl_handler:
                    approval = hitl_handler.request_approval(
                        act_type, resolved_target, params, verification
                    )
                    if approval.approved:
                        return fn(*args, **kwargs)

                if not verification.is_allowed:
                    if on_block == "callback" and on_block_callback:
                        return on_block_callback(verification)
                    raise ActionBlockedError(verification)

                return fn(*args, **kwargs)

            sync_wrapper.__vizier_client__ = sync_cli  # type: ignore
            return sync_wrapper

    return decorator
