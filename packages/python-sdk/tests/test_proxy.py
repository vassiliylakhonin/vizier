from __future__ import annotations

import os
from vizier import VizierProxyConfig, configure_openai_proxy


def test_vizier_proxy_config_defaults():
    config = VizierProxyConfig(
        base_url="https://vizier.example.com/v1",
        vizier_api_key="v-key-123",
        openai_api_key="sk-test-456",
        session_id="session-789",
    )
    headers = config.get_headers()
    assert headers["X-Vizier-Key"] == "v-key-123"
    assert headers["X-Session-Id"] == "session-789"

    kwargs = config.as_openai_kwargs()
    assert kwargs["base_url"] == "https://vizier.example.com/v1"
    assert kwargs["api_key"] == "sk-test-456"
    assert kwargs["default_headers"]["X-Vizier-Key"] == "v-key-123"


def test_configure_openai_proxy_helper():
    kwargs = configure_openai_proxy(
        base_url="https://vizier.vassiliy-lakhonin.workers.dev/v1",
        vizier_api_key="vz-secret",
        session_id="agent-loop-test",
        quorum_actions=["transfer_funds", "delete_db"],
    )
    assert kwargs["base_url"] == "https://vizier.vassiliy-lakhonin.workers.dev/v1"
    assert kwargs["default_headers"]["X-Vizier-Key"] == "vz-secret"
    assert kwargs["default_headers"]["X-Session-Id"] == "agent-loop-test"
    assert kwargs["default_headers"]["X-Quorum-Actions"] == "transfer_funds,delete_db"
    assert kwargs["api_key"] == "vz-secret"
