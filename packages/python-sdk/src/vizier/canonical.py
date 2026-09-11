import hashlib
import json
from typing import Any

def canonicalize(value: Any) -> str:
    """
    RFC 8785-like deterministic JSON canonicalization matching Vizier TS kernel:
    - Booleans, strings, nulls, and numbers are serialized cleanly
    - Float values with integral value format without trailing .0 (matching ECMAScript JSON.stringify)
    - Arrays preserve order with canonical elements
    - Dictionaries sort keys lexicographically
    """
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        # ECMAScript JSON.stringify formats integral numbers without .0
        if isinstance(value, float) and value.is_integer():
            return str(int(value))
        return json.dumps(value, separators=(",", ":"))
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(canonicalize(item) for item in value) + "]"
    if isinstance(value, dict):
        sorted_keys = sorted(value.keys())
        items = [f"{json.dumps(k, ensure_ascii=False)}:{canonicalize(value[k])}" for k in sorted_keys]
        return "{" + ",".join(items) + "}"
    raise TypeError(f"Value of type {type(value)} is not canonicalizable JSON.")

def sha256_canonical_json(value: Any) -> str:
    """Compute SHA-256 hex digest of canonicalized JSON."""
    raw = canonicalize(value).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()
