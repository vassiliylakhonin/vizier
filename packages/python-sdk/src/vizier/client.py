from __future__ import annotations
import json
import urllib.request
import urllib.error
from typing import Any, Dict, List, Optional, Union

from .models import (
    Action,
    Agent,
    Authority,
    AuthorityConstraints,
    Context,
    Principal,
    VerificationRequest,
    VerificationResponse,
)
from .canonical import sha256_canonical_json

class VizierError(Exception):
    def __init__(self, message: str, status: int = 0, code: str = "ERROR", details: Any = None):
        super().__init__(f"[{code}] {message} (HTTP {status})")
        self.message = message
        self.status = status
        self.code = code
        self.details = details

class VizierClient:
    """
    Official Vizier Authorization & Governance Client for AI Agents.
    Zero external dependencies required (uses Python standard library).
    """

    def __init__(
        self,
        base_url: str = "https://vizier.vassiliy-lakhonin.workers.dev",
        api_key: Optional[str] = None,
        timeout: float = 5.0,
    ):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout

    def _request(self, path: str, data: Dict[str, Any]) -> Dict[str, Any]:
        url = f"{self.base_url}{path}"
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "vizier-guard-python/0.3.0",
        }
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        payload_bytes = json.dumps(data).encode("utf-8")
        req = urllib.request.Request(url, data=payload_bytes, headers=headers, method="POST")

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                body = response.read().decode("utf-8")
                return json.loads(body)
        except urllib.error.HTTPError as err:
            try:
                body = err.read().decode("utf-8")
                err_data = json.loads(body)
                err_info = err_data.get("error", {})
                msg = err_info.get("message", "Request failed")
                code = err_info.get("code", "REQUEST_FAILED")
                details = err_info.get("details")
            except Exception:
                msg = err.reason
                code = "HTTP_ERROR"
                details = None
            raise VizierError(message=msg, status=err.code, code=code, details=details) from err
        except urllib.error.URLError as err:
            raise VizierError(message=str(err.reason), status=0, code="CONNECTION_FAILED") from err
        except Exception as err:
            raise VizierError(message=str(err), status=0, code="UNKNOWN_ERROR") from err

    def verify(
        self,
        request: Union[VerificationRequest, Dict[str, Any]],
        verify_receipt_hash: bool = True,
    ) -> VerificationResponse:
        """
        Submit a proposed agent action to Vizier for deterministic authorization.
        Returns VerificationResponse with decision: ALLOW, REVIEW, or BLOCK.
        """
        payload: Dict[str, Any]
        if isinstance(request, VerificationRequest):
            payload = request.to_dict()
        elif isinstance(request, dict):
            payload = request
        else:
            raise TypeError("request must be VerificationRequest or dict")

        # Force source="rest" for client calls
        if "context" not in payload or payload["context"] is None:
            payload["context"] = {"source": "rest"}
        else:
            payload["context"]["source"] = "rest"

        raw_response = self._request("/v1/verify", payload)
        resp = VerificationResponse.from_dict(raw_response)

        # Non-repudiation integrity check
        if verify_receipt_hash:
            expected_hash = sha256_canonical_json(payload)
            if resp.receipt.request_hash != expected_hash:
                raise VizierError(
                    message=f"Receipt hash mismatch: expected {expected_hash}, got {resp.receipt.request_hash}",
                    status=200,
                    code="HASH_MISMATCH",
                )

        return resp

    def screen_sanctions(
        self,
        query: str,
    ) -> Dict[str, Any]:
        """
        Screen an entity, domain, crypto address, or IBAN against built-in and custom sanctions lists.
        Returns a dict with 'query', 'clean' (bool), and optional 'match' dict.
        """
        return self._request("/v1/sanctions/screen", {"query": query})

    def check(
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
        sanctions_screening: Optional[bool] = None,
        blocked_entities: Optional[List[str]] = None,
    ) -> VerificationResponse:
        """
        Convenience method: verify an action in a single line of code.
        """
        req = VerificationRequest(
            agent=Agent(id=agent_id),
            principal=Principal(id=principal_id),
            action=Action(
                type=action_type,
                target=target,
                parameters=parameters or {},
                is_reversible=is_reversible,
            ),
            authority=Authority(
                allowed_actions=allowed_actions or [action_type],
                constraints=AuthorityConstraints(
                    max_amount=max_amount,
                    currency=currency,
                    allowed_targets=allowed_targets,
                    blocked_targets=blocked_targets,
                    sanctions_screening=sanctions_screening,
                    blocked_entities=blocked_entities,
                ),
            ),
            grant=grant,
        )
        return self.verify(req)

