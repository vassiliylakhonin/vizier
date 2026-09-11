"""
Vizier: Deterministic Authorization & Audit Kernel for AI Agents.
"""

from .canonical import canonicalize, sha256_canonical_json
from .client import VizierClient, VizierError
from .async_client import AsyncVizierClient
from .circuit_breaker import CircuitBreaker, CircuitTrippedError, CircuitStatus
from .decorators import vizier_guard, ActionBlockedError
from .hitl import (
    BaseHITLHandler,
    HITLApprovalResult,
    CliHITLHandler,
    TelegramHITLHandler,
    WebhookHITLHandler,
)
from .models import (
    Action,
    Agent,
    Authority,
    AuthorityConstraints,
    Context,
    Decision,
    PolicyResult,
    Principal,
    Receipt,
    ReceiptGrant,
    QuorumConstraints,
    QuorumApproval,
    QuorumProposal,
    VerificationRequest,
    VerificationResponse,
)

__version__ = "0.3.0"
__all__ = [
    "VizierClient",
    "AsyncVizierClient",
    "VizierError",
    "vizier_guard",
    "ActionBlockedError",
    "VerificationRequest",
    "VerificationResponse",
    "Decision",
    "Agent",
    "Principal",
    "Action",
    "Authority",
    "AuthorityConstraints",
    "Context",
    "QuorumConstraints",
    "QuorumApproval",
    "QuorumProposal",
    "PolicyResult",
    "Receipt",
    "ReceiptGrant",
    "canonicalize",
    "sha256_canonical_json",
    "BaseHITLHandler",
    "HITLApprovalResult",
    "CliHITLHandler",
    "TelegramHITLHandler",
    "WebhookHITLHandler",
    "CircuitBreaker",
    "CircuitTrippedError",
    "CircuitStatus",
]
