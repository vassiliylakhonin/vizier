from __future__ import annotations
import functools
import inspect
from typing import Any, Callable, Dict, List, Optional, Union

from .client import VizierClient
from .async_client import AsyncVizierClient
from .models import VerificationResponse
from .hitl.base import BaseHITLHandler, HITLApprovalResult
from .circuit_breaker import CircuitBreaker, CircuitTrippedError

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
    session_id: Optional[Union[str, Callable[..., str]]] = None,
    on_block: str = "raise",  # "raise" or "callback"
    on_block_callback: Optional[Callable[[Union[VerificationResponse, CircuitTrippedError]], Any]] = None,
    hitl_handler: Optional[BaseHITLHandler] = None,
    circuit_breaker: Optional[Union[CircuitBreaker, bool]] = None,
    sanctions_check: bool = False,
    blocked_entities: Optional[List[str]] = None,
    dlp_check: bool = False,
    allowed_dlp_categories: Optional[List[str]] = None,
    quorum_min_approvals: Optional[int] = None,
    quorum_allowed_approvers: Optional[List[str]] = None,
    quorum_require_distinct_owners: Optional[bool] = None,
    quorum_proposal_id: Optional[Union[str, Callable[..., str]]] = None,
    quorum_approvals: Optional[Union[List[Any], Callable[..., List[Any]]]] = None,
):
    """
    Decorator to protect any Python function / agent tool with Vizier deterministic authorization,
    Pre-Action Sanctions Screening, PII & Secret Leak Firewall (DLP), Circuit Breaker loop prevention,
    and Human-in-the-Loop review.
    Supports BOTH synchronous (def) and asynchronous (async def) functions seamlessly.
    """
    breaker: Optional[CircuitBreaker]
    if isinstance(circuit_breaker, CircuitBreaker):
        breaker = circuit_breaker
    elif circuit_breaker is True:
        breaker = CircuitBreaker()
    else:
        breaker = None

    def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
        act_type = action_type or fn.__name__
        is_async = inspect.iscoroutinefunction(fn)

        def _prepare_args(args: Any, kwargs: Any) -> tuple[Dict[str, Any], str, Optional[float], Optional[str], str]:
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

            if callable(session_id):
                resolved_session_id = session_id(*args, **kwargs)
            elif session_id:
                resolved_session_id = session_id
            else:
                resolved_session_id = params.get("session_id") or agent_id

            if callable(quorum_proposal_id):
                resolved_proposal_id = quorum_proposal_id(*args, **kwargs)
            else:
                resolved_proposal_id = quorum_proposal_id or params.get("proposal_id")

            if callable(quorum_approvals):
                resolved_approvals = quorum_approvals(*args, **kwargs)
            else:
                resolved_approvals = quorum_approvals or params.get("approvals")

            resolved_quorum = None
            if quorum_min_approvals is not None:
                resolved_quorum = {
                    "min_approvals": quorum_min_approvals,
                }
                if quorum_allowed_approvers is not None:
                    resolved_quorum["allowed_approvers"] = quorum_allowed_approvers
                if quorum_require_distinct_owners is not None:
                    resolved_quorum["require_distinct_owners"] = quorum_require_distinct_owners

            return params, str(resolved_target), resolved_max_amount, curr, str(resolved_session_id), resolved_proposal_id, resolved_approvals, resolved_quorum

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
                params, resolved_target, resolved_max_amount, curr, resolved_session_id, resolved_proposal_id, resolved_approvals, resolved_quorum = _prepare_args(args, kwargs)

                # 1. Circuit Breaker check
                if breaker:
                    cb_status = breaker.check_and_record(act_type, resolved_target, params, session_id=resolved_session_id)
                    if cb_status.tripped:
                        err = CircuitTrippedError(
                            code=cb_status.code or "CIRCUIT_TRIPPED",
                            message=cb_status.message or "Agent circuit breaker tripped.",
                            details={
                                "action_type": act_type,
                                "target": resolved_target,
                                "session_id": resolved_session_id,
                                "repeats": cb_status.consecutive_repeats,
                                "session_calls": cb_status.session_calls_count,
                            },
                        )
                        if on_block == "callback" and on_block_callback:
                            return on_block_callback(err)
                        raise err

                # 2. Kernel verification
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
                    session_id=resolved_session_id,
                    sanctions_screening=True if sanctions_check else None,
                    blocked_entities=blocked_entities,
                    dlp_screening=True if dlp_check else None,
                    allowed_dlp_categories=allowed_dlp_categories,
                    proposal_id=resolved_proposal_id,
                    approvals=resolved_approvals,
                    quorum=resolved_quorum,
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
            async_wrapper.__circuit_breaker__ = breaker  # type: ignore
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
                params, resolved_target, resolved_max_amount, curr, resolved_session_id, resolved_proposal_id, resolved_approvals, resolved_quorum = _prepare_args(args, kwargs)

                # 1. Circuit Breaker check
                if breaker:
                    cb_status = breaker.check_and_record(act_type, resolved_target, params, session_id=resolved_session_id)
                    if cb_status.tripped:
                        err = CircuitTrippedError(
                            code=cb_status.code or "CIRCUIT_TRIPPED",
                            message=cb_status.message or "Agent circuit breaker tripped.",
                            details={
                                "action_type": act_type,
                                "target": resolved_target,
                                "session_id": resolved_session_id,
                                "repeats": cb_status.consecutive_repeats,
                                "session_calls": cb_status.session_calls_count,
                            },
                        )
                        if on_block == "callback" and on_block_callback:
                            return on_block_callback(err)
                        raise err

                # 2. Kernel verification
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
                    session_id=resolved_session_id,
                    sanctions_screening=True if sanctions_check else None,
                    blocked_entities=blocked_entities,
                    dlp_screening=True if dlp_check else None,
                    allowed_dlp_categories=allowed_dlp_categories,
                    proposal_id=resolved_proposal_id,
                    approvals=resolved_approvals,
                    quorum=resolved_quorum,
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
            sync_wrapper.__circuit_breaker__ = breaker  # type: ignore
            return sync_wrapper

    return decorator
