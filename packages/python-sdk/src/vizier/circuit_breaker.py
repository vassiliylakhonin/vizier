from __future__ import annotations
import collections
import dataclasses
import time
from typing import Any, Dict, Optional, Tuple

from .canonical import sha256_canonical_json

class CircuitTrippedError(Exception):
    """
    Raised when the Agent Circuit Breaker trips due to an infinite loop,
    runaway tool-calling retry storm, or exceeded session budget.
    """

    def __init__(self, code: str, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(f"[{code}] {message}")
        self.code = code
        self.message = message
        self.details = details or {}

@dataclasses.dataclass
class CircuitStatus:
    """Status report returned by CircuitBreaker evaluation."""
    tripped: bool
    code: Optional[str] = None
    message: Optional[str] = None
    consecutive_repeats: int = 0
    session_calls_count: int = 0

class CircuitBreaker:
    """
    Agent Circuit Breaker & Loop Killer.
    Protects against infinite tool-calling loops, runaway LLM retries,
    and unexpected API/LLM token bills.
    """

    def __init__(
        self,
        max_repeated_calls: int = 3,
        time_window_seconds: float = 30.0,
        max_session_calls: int = 25,
        cool_off_seconds: float = 60.0,
        max_session_actions: Optional[int] = None,
    ):
        self.max_repeated_calls = max_repeated_calls
        self.time_window_seconds = time_window_seconds
        self.max_session_calls = max_session_actions if max_session_actions is not None else max_session_calls
        self.cool_off_seconds = cool_off_seconds

        self._history: Dict[str, collections.deque[Tuple[float, str]]] = collections.defaultdict(
            lambda: collections.deque(maxlen=100)
        )
        self._session_totals: Dict[str, int] = collections.defaultdict(int)
        self._tripped_sessions: Dict[str, Tuple[float, str, str]] = {}

    def _signature(self, action_type: str, target: str, parameters: Dict[str, Any]) -> str:
        param_hash = sha256_canonical_json(parameters)
        return f"{action_type}:{target}:{param_hash}"

    def check_and_record(
        self,
        action_type: str,
        target: str,
        parameters: Dict[str, Any],
        session_id: str = "default_session",
    ) -> CircuitStatus:
        now = time.time()

        # 1. Check if session is currently in active cool-off
        if session_id in self._tripped_sessions:
            trip_time, code, msg = self._tripped_sessions[session_id]
            if now - trip_time < self.cool_off_seconds:
                remaining = int(self.cool_off_seconds - (now - trip_time))
                return CircuitStatus(
                    tripped=True,
                    code=code,
                    message=f"Circuit breaker active for session '{session_id}'. Cool-off remaining: {remaining}s. ({msg})",
                    session_calls_count=self._session_totals[session_id],
                )
            else:
                del self._tripped_sessions[session_id]

        # 2. Check total session action budget
        total = self._session_totals[session_id] + 1
        if total > self.max_session_calls:
            code = "CIRCUIT_TRIPPED:BUDGET_EXCEEDED"
            msg = (
                f"Session action budget exceeded (limit: {self.max_session_calls} actions). "
                f"Execution halted to prevent runaway costs."
            )
            self._tripped_sessions[session_id] = (now, code, msg)
            return CircuitStatus(tripped=True, code=code, message=msg, session_calls_count=total)

        # 3. Check repeated identical calls within sliding time window
        sig = self._signature(action_type, target, parameters)
        history = self._history[session_id]

        cutoff = now - self.time_window_seconds
        while history and history[0][0] < cutoff:
            history.popleft()

        consecutive = 0
        for _, prev_sig in reversed(history):
            if prev_sig == sig:
                consecutive += 1
            else:
                break

        history.append((now, sig))
        self._session_totals[session_id] = total

        if consecutive + 1 >= self.max_repeated_calls:
            code = "CIRCUIT_TRIPPED:LOOP_DETECTED"
            msg = (
                f"Potential infinite tool-calling loop detected: action '{action_type}' "
                f"called {consecutive + 1} times with identical parameters within {int(self.time_window_seconds)}s. "
                f"Execution halted."
            )
            self._tripped_sessions[session_id] = (now, code, msg)
            return CircuitStatus(
                tripped=True,
                code=code,
                message=msg,
                consecutive_repeats=consecutive + 1,
                session_calls_count=total,
            )

        return CircuitStatus(
            tripped=False,
            consecutive_repeats=consecutive + 1,
            session_calls_count=total,
        )

    def reset(self, session_id: Optional[str] = None) -> None:
        if session_id is None:
            self._history.clear()
            self._session_totals.clear()
            self._tripped_sessions.clear()
        else:
            self._history.pop(session_id, None)
            self._session_totals.pop(session_id, None)
            self._tripped_sessions.pop(session_id, None)
