"""Side-effect-free demo; uses the installed package, never a hidden sys.path override."""
import copy
import json
import os
import sys
from pathlib import Path
from urllib.parse import urlsplit

from vizier import VizierClient, VizierError


def main():
    base_url = os.environ["VIZIER_BASE_URL"]
    if urlsplit(base_url).hostname != "127.0.0.1":
        raise RuntimeError("Use the local demo server only.")
    signed = "--signed" in sys.argv
    request = json.loads((Path(__file__).parent / "block.json").read_text())
    options = {"require_receipt_jws": True} if signed else {}
    client = VizierClient(base_url=base_url, api_key=os.environ["VIZIER_API_KEY"])
    result = client.verify(copy.deepcopy(request), **options)
    if result.decision != "BLOCK" or "GRANT_REQUIRED" not in result.reason_codes:
        raise RuntimeError("Expected BLOCK with GRANT_REQUIRED")
    if signed and not result.receipt_jws:
        raise RuntimeError("Missing signature: this demo requires a signed receipt.")
    print("Python: BLOCK (GRANT_REQUIRED), request hash verified" +
          (", ES256 receipt verified" if signed else " (not a signature)"))

    class TamperedClient(VizierClient):
        def _request(self, *args, **kwargs):
            body = super()._request(*args, **kwargs)
            if signed:
                body["receipt"]["id"] = "vrf_tampered"
            else:
                body["receipt"]["request_hash"] = "0" * 64
            return body

    tampered = TamperedClient(base_url=base_url, api_key=os.environ["VIZIER_API_KEY"])
    try:
        tampered.verify(copy.deepcopy(request), **options)
    except VizierError as err:
        expected = "RECEIPT_SIGNATURE_INVALID" if signed else "HASH_MISMATCH"
        if err.code != expected:
            raise
    else:
        raise RuntimeError("Tampered receipt was accepted")
    print("Python: tampered " + ("signed receipt" if signed else "request hash") +
          " rejected; no tool executed")

    if signed:
        class MissingSignatureClient(VizierClient):
            def _request(self, *args, **kwargs):
                body = super()._request(*args, **kwargs)
                body.pop("receipt_jws", None)
                return body

        missing = MissingSignatureClient(base_url=base_url, api_key=os.environ["VIZIER_API_KEY"])
        try:
            missing.verify(copy.deepcopy(request), require_receipt_jws=True)
        except VizierError as err:
            if err.code != "RECEIPT_SIGNATURE_REQUIRED":
                raise
        else:
            raise RuntimeError("Missing signed receipt was accepted")
        print("Python: missing signed receipt rejected with require_receipt_jws; no tool executed")


if __name__ == "__main__":
    main()
