import base64
import json
from unittest.mock import patch

import pytest

cryptography = pytest.importorskip("cryptography")
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from vizier import VizierClient, VizierError
from vizier.canonical import sha256_canonical_json
from vizier.receipt_jws import verify_receipt_jws


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def make_key(kid="receipt-1"):
    priv = ec.generate_private_key(ec.SECP256R1())
    n = priv.public_key().public_numbers()
    jwk = {"kty": "EC", "crv": "P-256", "kid": kid, "alg": "ES256", "use": "sig",
           "x": b64(n.x.to_bytes(32, "big")), "y": b64(n.y.to_bytes(32, "big"))}
    return priv, {"keys": [jwk]}


def sign(priv, receipt, kid="receipt-1", typ="application/vizier-receipt+jwt"):
    h = b64(json.dumps({"alg": "ES256", "typ": typ, "kid": kid}).encode())
    p = b64(json.dumps({"iss": "vizier-action-firewall", "iat": 1, "engine": "vizier_verify",
                        "receipt": receipt}).encode())
    r, s = decode_dss_signature(priv.sign(f"{h}.{p}".encode(), ec.ECDSA(hashes.SHA256())))
    return f"{h}.{p}.{b64(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))}"


REQ = {"agent": {"id": "a"}, "principal": {"id": "p"},
       "action": {"type": "t", "target": "x", "parameters": {}},
       "authority": {"allowed_actions": ["t"]}}


def service_body(req, jws_for=None):
    payload = dict(req, context={"source": "rest"})
    receipt = {"id": "vrf_1", "created_at": "2026-01-01T00:00:00Z",
               "request_hash": sha256_canonical_json(payload), "decision": "ALLOW",
               "risk_score": 0, "policy_rule_ids": [], "reason_codes": [],
               "authority_provenance": "unverified"}
    body = {"decision": "ALLOW", "risk_score": 0, "reason_codes": [], "explanation": "",
            "policy_results": [], "receipt": receipt}
    return body, receipt


def run(body, jwks, headers_seen=None, **verify_kwargs):
    client = VizierClient(base_url="https://example.test")

    def fake_request(path, data, extra=None):
        if headers_seen is not None:
            headers_seen.append(extra)
        return body(data) if callable(body) else body

    with patch.object(client, "_request", side_effect=fake_request), \
         patch.object(client, "_fetch_jwks", return_value=jwks):
        return client.verify(json.loads(json.dumps(REQ)), **({"request_receipt_jws": True} | verify_kwargs))


def test_valid_receipt_jws_verifies_and_header_requested():
    priv, jwks = make_key()
    seen = []

    def body(data):
        b, receipt = service_body(REQ)
        b["receipt_jws"] = sign(priv, receipt)
        return b

    resp = run(body, jwks, seen)
    assert resp.is_allowed and resp.receipt_jws
    assert seen == [{"X-Vizier-Receipt": "jws"}]


def test_absent_receipt_jws_is_tolerated():
    _, jwks = make_key()
    resp = run(lambda d: service_body(REQ)[0], jwks)
    assert resp.receipt_jws is None


@pytest.mark.parametrize("tamper", ["receipt", "key", "typ"])
def test_invalid_receipt_jws_rejected(tamper):
    priv, jwks = make_key()
    other, _ = make_key()

    def body(data):
        b, receipt = service_body(REQ)
        if tamper == "key":
            b["receipt_jws"] = sign(other, receipt)
        elif tamper == "typ":
            b["receipt_jws"] = sign(priv, receipt, typ="JWT")
        else:
            b["receipt_jws"] = sign(priv, receipt)
            b["receipt"]["id"] = "vrf_tampered"
        return b

    with pytest.raises(VizierError) as e:
        run(body, jwks)
    assert e.value.code == "RECEIPT_SIGNATURE_INVALID"


def test_unknown_kid_and_garbage_rejected():
    priv, jwks = make_key()
    _, receipt = service_body(REQ)
    assert not verify_receipt_jws(sign(priv, receipt, kid="nope"), receipt, jwks)
    assert not verify_receipt_jws("a.b", receipt, jwks)
    assert not verify_receipt_jws(None, receipt, jwks)


def test_require_receipt_jws_refuses_missing_signature():
    _, jwks = make_key()
    seen = []
    with pytest.raises(VizierError) as e:
        run(lambda d: service_body(REQ)[0], jwks, seen,
            request_receipt_jws=False, require_receipt_jws=True)
    assert e.value.code == "RECEIPT_SIGNATURE_REQUIRED"
    # require implies asking the service to sign
    assert seen == [{"X-Vizier-Receipt": "jws"}]


def test_require_receipt_jws_accepts_valid_signature():
    priv, jwks = make_key()

    def body(data):
        b, receipt = service_body(REQ)
        b["receipt_jws"] = sign(priv, receipt)
        return b

    resp = run(body, jwks, request_receipt_jws=False, require_receipt_jws=True)
    assert resp.is_allowed and resp.receipt_jws


def test_require_receipt_jws_still_rejects_tampered_signature():
    priv, jwks = make_key()

    def body(data):
        b, receipt = service_body(REQ)
        b["receipt_jws"] = sign(priv, receipt)
        b["receipt"]["id"] = "vrf_tampered"
        return b

    with pytest.raises(VizierError) as e:
        run(body, jwks, request_receipt_jws=False, require_receipt_jws=True)
    assert e.value.code == "RECEIPT_SIGNATURE_INVALID"


def test_async_client_forwards_require_receipt_jws():
    import asyncio
    from vizier.async_client import AsyncVizierClient

    client = AsyncVizierClient(base_url="https://example.test")
    with patch.object(client._sync_client, "verify", return_value="ok") as m:
        asyncio.run(client.verify(REQ, require_receipt_jws=True))
    assert m.call_args.args[-1] is True
