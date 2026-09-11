"""
Vizier: Deterministic Authorization & Audit Kernel for AI Agents.
"""

from .canonical import canonicalize, sha256_canonical_json
from .client import VizierClient, VizierError
from .decorators import vizier_guard, ActionBlockedError
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
    VerificationRequest,
    VerificationResponse,
)

__version__ = "0.3.0"
__all__ = [
    "VizierClient",
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
    "PolicyResult",
    "Receipt",
    "ReceiptGrant",
    "canonicalize",
    "sha256_canonical_json",
]
