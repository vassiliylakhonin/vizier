"""Verification of the signed ``receipt_jws`` returned by ``/v1/verify``.

Requires the optional ``cryptography`` package (``pip install vizier-guard[receipts]``).
"""
from __future__ import annotations

import base64
import json
from typing import Any, Dict

from .canonical import canonicalize

RECEIPT_JWS_TYPE = "application/vizier-receipt+jwt"
RECEIPT_ISSUER = "vizier-action-firewall"


class ReceiptCryptoUnavailable(Exception):
    """Raised when ``cryptography`` is not installed."""


def _b64url_decode(part: str) -> bytes:
    return base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))


def verify_receipt_jws(token: Any, receipt: Any, jwks: Any) -> bool:
    """True only if ``token`` is a valid ES256 signature, by a key in ``jwks``,
    over a payload whose ``receipt`` equals the exact ``receipt`` returned.
    Raises ReceiptCryptoUnavailable if ``cryptography`` is missing."""
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
    except ImportError as err:  # pragma: no cover
        raise ReceiptCryptoUnavailable(
            "Verifying receipt_jws requires the 'cryptography' package: pip install vizier-guard[receipts]"
        ) from err

    try:
        if not isinstance(token, str):
            return False
        parts = token.split(".")
        if len(parts) != 3 or not all(parts):
            return False
        header = json.loads(_b64url_decode(parts[0]).decode("utf-8"))
        payload = json.loads(_b64url_decode(parts[1]).decode("utf-8"))
        if (
            not isinstance(header, dict)
            or header.get("alg") != "ES256"
            or header.get("typ") != RECEIPT_JWS_TYPE
            or not isinstance(header.get("kid"), str)
            or not isinstance(payload, dict)
            or payload.get("iss") != RECEIPT_ISSUER
            or payload.get("engine") != "vizier_verify"
            or canonicalize(payload.get("receipt")) != canonicalize(receipt)
        ):
            return False
        keys = jwks.get("keys", []) if isinstance(jwks, dict) else []
        key: Dict[str, Any] = next(
            (k for k in keys if isinstance(k, dict) and k.get("kid") == header["kid"]), {}
        )
        if key.get("kty") != "EC" or key.get("crv") != "P-256":
            return False
        public = ec.EllipticCurvePublicNumbers(
            int.from_bytes(_b64url_decode(key["x"]), "big"),
            int.from_bytes(_b64url_decode(key["y"]), "big"),
            ec.SECP256R1(),
        ).public_key()
        sig = _b64url_decode(parts[2])
        if len(sig) != 64:
            return False
        der = encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big"))
        public.verify(der, f"{parts[0]}.{parts[1]}".encode("ascii"), ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError, KeyError, TypeError):
        return False
