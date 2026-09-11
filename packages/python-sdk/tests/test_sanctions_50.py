import pytest
from unittest.mock import MagicMock
from vizier.client import VizierClient
from vizier.async_client import AsyncVizierClient

def test_screen_sanctions_entity_sync():
    client = VizierClient(base_url="https://vizier.local", api_key="test-key")
    client._request = MagicMock(return_value={
        "clean": False,
        "violation": True,
        "entity_name": "Silk Road Trading Ltd",
        "aggregate_blocked_percentage": 55.0,
        "threshold_percentage": 50.0,
        "blocked_shareholders": [
            {"name": "Garantex Europe", "direct_percentage": 30.0},
            {"name": "Tornado Cash", "direct_percentage": 25.0}
        ],
        "reason_codes": ["SANCTIONS_50_RULE_VIOLATION"]
    })

    res = client.screen_sanctions_entity(
        entity_name="Silk Road Trading Ltd",
        shareholders=[
            {"name": "Garantex Europe", "percentage": 30.0},
            {"name": "Tornado Cash", "percentage": 25.0}
        ],
        threshold_percentage=50.0
    )

    assert res["clean"] is False
    assert res["violation"] is True
    assert res["aggregate_blocked_percentage"] == 55.0
    assert "SANCTIONS_50_RULE_VIOLATION" in res["reason_codes"]
    client._request.assert_called_once_with("/v1/sanctions/screen-entity", {
        "entity_name": "Silk Road Trading Ltd",
        "shareholders": [
            {"name": "Garantex Europe", "percentage": 30.0},
            {"name": "Tornado Cash", "percentage": 25.0}
        ],
        "threshold_percentage": 50.0
    })

def test_screen_sanctions_entity_async():
    async def _test():
        async_client = AsyncVizierClient(base_url="https://vizier.local", api_key="test-key")
        async_client._sync_client.screen_sanctions_entity = MagicMock(return_value={
            "clean": True,
            "violation": False,
            "entity_name": "Clean Corp",
            "aggregate_blocked_percentage": 10.0,
            "reason_codes": []
        })

        res = await async_client.screen_sanctions_entity(
            entity_name="Clean Corp",
            shareholders=[{"name": "Partner", "percentage": 100.0}]
        )

        assert res["clean"] is True
        assert res["violation"] is False
        assert res["aggregate_blocked_percentage"] == 10.0

    import asyncio
    asyncio.run(_test())
