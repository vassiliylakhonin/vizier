import pytest
from vizier.canonical import canonicalize, sha256_canonical_json

def test_primitives():
    assert canonicalize(None) == "null"
    assert canonicalize(True) == "true"
    assert canonicalize(False) == "false"
    assert canonicalize(42) == "42"
    assert canonicalize("hello") == '"hello"'

def test_dict_key_sorting():
    d1 = {"z": 1, "a": 2, "m": 3}
    d2 = {"a": 2, "m": 3, "z": 1}
    assert canonicalize(d1) == '{"a":2,"m":3,"z":1}'
    assert canonicalize(d1) == canonicalize(d2)
    assert sha256_canonical_json(d1) == sha256_canonical_json(d2)

def test_nested_structures():
    data = {
        "user": {"name": "alice", "id": 1},
        "tags": ["prod", "agent"],
        "active": True
    }
    expected = '{"active":true,"tags":["prod","agent"],"user":{"id":1,"name":"alice"}}'
    assert canonicalize(data) == expected

def test_hash_consistency():
    obj = {"action": "purchase", "amount": 100}
    h = sha256_canonical_json(obj)
    assert len(h) == 64
    assert h == sha256_canonical_json({"amount": 100, "action": "purchase"})
