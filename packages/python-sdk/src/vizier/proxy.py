from __future__ import annotations

import os
from typing import Any, Dict, Optional


class VizierProxyConfig:
    """
    Configuration helper for routing AI Agent SDKs (OpenAI, LangChain, LiteLLM)
    through the Vizier Transparent Edge Proxy.
    """

    def __init__(
        self,
        base_url: str = "https://vizier.vassiliy-lakhonin.workers.dev/v1",
        vizier_api_key: Optional[str] = None,
        openai_api_key: Optional[str] = None,
        session_id: Optional[str] = None,
        upstream_url: Optional[str] = None,
        quorum_actions: Optional[list[str]] = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.vizier_api_key = vizier_api_key or os.environ.get("VIZIER_API_KEY")
        self.openai_api_key = openai_api_key or os.environ.get("OPENAI_API_KEY")
        self.session_id = session_id
        self.upstream_url = upstream_url
        self.quorum_actions = quorum_actions or []

    def get_headers(self) -> Dict[str, str]:
        headers: Dict[str, str] = {}
        if self.vizier_api_key:
            headers["X-Vizier-Key"] = self.vizier_api_key
        if self.session_id:
            headers["X-Session-Id"] = self.session_id
        if self.upstream_url:
            headers["X-Upstream-Url"] = self.upstream_url
        if self.quorum_actions:
            headers["X-Quorum-Actions"] = ",".join(self.quorum_actions)
        return headers

    def as_openai_kwargs(self) -> Dict[str, Any]:
        """
        Returns keyword arguments suitable for instantiating openai.OpenAI(...)
        or passing to LangChain / CrewAI LLM configurations.
        """
        kwargs: Dict[str, Any] = {
            "base_url": self.base_url,
            "default_headers": self.get_headers(),
        }
        if self.openai_api_key:
            kwargs["api_key"] = self.openai_api_key
        elif self.vizier_api_key:
            kwargs["api_key"] = self.vizier_api_key
        return kwargs


def configure_openai_proxy(
    base_url: str = "https://vizier.vassiliy-lakhonin.workers.dev/v1",
    vizier_api_key: Optional[str] = None,
    openai_api_key: Optional[str] = None,
    session_id: Optional[str] = None,
    upstream_url: Optional[str] = None,
    quorum_actions: Optional[list[str]] = None,
) -> Dict[str, Any]:
    """
    Convenience function returning OpenAI constructor arguments configured
    to route through the Vizier AI Proxy.

    Example:
    ```python
    from openai import OpenAI
    from vizier import configure_openai_proxy

    client = OpenAI(**configure_openai_proxy(session_id="agent-01"))
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": "Hello world"}]
    )
    ```
    """
    config = VizierProxyConfig(
        base_url=base_url,
        vizier_api_key=vizier_api_key,
        openai_api_key=openai_api_key,
        session_id=session_id,
        upstream_url=upstream_url,
        quorum_actions=quorum_actions,
    )
    return config.as_openai_kwargs()
