import asyncio
from unittest.mock import MagicMock
import pytest

from vizier import (
    VizierClient,
    AsyncVizierClient,
    vizier_guard,
    CircuitBreaker,
    CircuitTrippedError,
)
from vizier.models import VerificationResponse, Receipt

def mock_allow_response() -> VerificationResponse:
    return VerificationResponse(
        decision="ALLOW",
        risk_score=0.0,
        reason_codes=[],
        explanation="ok",
        policy_results=[],
        receipt=Receipt(
            id="vrf_cb_test",
            created_at="2026-09-11T12:00:00.000Z",
            request_hash="abcd",
            decision="ALLOW",
            risk_score=0.0,
            policy_rule_ids=[],
            reason_codes=[],
            authority_provenance="trusted_integration",
        ),
    )

def test_circuit_breaker_loop_detection():
    cb = CircuitBreaker(max_repeated_calls=3, time_window_seconds=10.0)

    # Call 1: OK
    s1 = cb.check_and_record("query_db", "users", {"id": 42}, session_id="sess_1")
    assert not s1.tripped
    assert s1.consecutive_repeats == 1

    # Call 2: OK
    s2 = cb.check_and_record("query_db", "users", {"id": 42}, session_id="sess_1")
    assert not s2.tripped
    assert s2.consecutive_repeats == 2

    # Call 3: Tripped! (Loop detected)
    s3 = cb.check_and_record("query_db", "users", {"id": 42}, session_id="sess_1")
    assert s3.tripped
    assert s3.code == "CIRCUIT_TRIPPED:LOOP_DETECTED"
    assert "infinite tool-calling loop detected" in s3.message

def test_circuit_breaker_budget_exceeded():
    cb = CircuitBreaker(max_session_calls=3)

    s1 = cb.check_and_record("action", "target", {"step": 1}, session_id="task_1")
    assert not s1.tripped

    s2 = cb.check_and_record("action", "target", {"step": 2}, session_id="task_1")
    assert not s2.tripped

    s3 = cb.check_and_record("action", "target", {"step": 3}, session_id="task_1")
    assert not s3.tripped

    # 4th call exceeds budget
    s4 = cb.check_and_record("action", "target", {"step": 4}, session_id="task_1")
    assert s4.tripped
    assert s4.code == "CIRCUIT_TRIPPED:BUDGET_EXCEEDED"

def test_circuit_breaker_different_parameters_no_loop():
    cb = CircuitBreaker(max_repeated_calls=3)

    for i in range(5):
        st = cb.check_and_record("search", "google", {"query": f"query_{i}"})
        assert not st.tripped

def test_circuit_breaker_reset():
    cb = CircuitBreaker(max_repeated_calls=2)

    cb.check_and_record("action", "target", {"k": "v"}, session_id="s1")
    st = cb.check_and_record("action", "target", {"k": "v"}, session_id="s1")
    assert st.tripped

    cb.reset("s1")
    st_after = cb.check_and_record("action", "target", {"k": "v"}, session_id="s1")
    assert not st_after.tripped

def test_vizier_guard_sync_with_circuit_breaker():
    mock_client = MagicMock()
    mock_client.check.return_value = mock_allow_response()

    cb = CircuitBreaker(max_repeated_calls=3)

    @vizier_guard(client=mock_client, action_type="read_file", circuit_breaker=cb)
    def read_file(path: str):
        return f"content of {path}"

    # First 2 calls succeed
    assert read_file("doc.txt") == "content of doc.txt"
    assert read_file("doc.txt") == "content of doc.txt"

    # 3rd identical call trips the circuit breaker!
    with pytest.raises(CircuitTrippedError) as exc_info:
        read_file("doc.txt")

    assert exc_info.value.code == "CIRCUIT_TRIPPED:LOOP_DETECTED"
    assert "infinite tool-calling loop detected" in str(exc_info.value)

def test_vizier_guard_async_with_circuit_breaker():
    async def _test():
        mock_client = MagicMock()

        async def fake_check(*args, **kwargs):
            return mock_allow_response()

        mock_client.check.side_effect = fake_check
        cb = CircuitBreaker(max_repeated_calls=2)

        @vizier_guard(client=mock_client, action_type="fetch_url", circuit_breaker=cb)
        async def fetch_url(url: str):
            return f"data from {url}"

        # 1st call OK
        assert await fetch_url("https://example.com") == "data from https://example.com"

        # 2nd identical call trips
        with pytest.raises(CircuitTrippedError) as exc_info:
            await fetch_url("https://example.com")

        assert exc_info.value.code == "CIRCUIT_TRIPPED:LOOP_DETECTED"

    asyncio.run(_test())
