import asyncio
from unittest.mock import MagicMock
import pytest
from vizier import VizierClient, AsyncVizierClient, AuthorityConstraints, Authority, VerificationRequest, Agent, Action

@pytest.mark.parametrize("text,parameters,payload", [
    ("Target: $100", None, {"text": "Target: $100"}),
    (None, {}, {"parameters": {}}),
    ("", {"body": "Target: $90"}, {"text": "", "parameters": {"body": "Target: $90"}}),
])
def test_scan(text, parameters, payload):
    client = VizierClient()
    result = {"consistent": True, "findings": [], "mentions_count": 0, "receipt": "opaque"}
    client._request = MagicMock(return_value=result)
    assert client.scan_numeric_consistency(text=text, parameters=parameters) == result
    client._request.assert_called_once_with("/v1/numeric-consistency/scan", payload)

def test_missing_input():
    with pytest.raises(ValueError):
        VizierClient().scan_numeric_consistency()

def test_async_scan():
    client = AsyncVizierClient()
    client._sync_client.scan_numeric_consistency = MagicMock(return_value={"consistent": False})
    assert asyncio.run(client.scan_numeric_consistency(text="x")) == {"consistent": False}
    client._sync_client.scan_numeric_consistency.assert_called_once_with(text="x", parameters=None)

@pytest.mark.parametrize("enabled", [True, False, None])
def test_opt_in_serialization(enabled):
    request = VerificationRequest(agent=Agent(id="a"), principal=None,
        action=Action(type="send", target="b", parameters={}),
        authority=Authority(constraints=AuthorityConstraints(numeric_consistency=enabled)))
    constraints = request.to_dict()["authority"]["constraints"]
    if enabled is None:
        assert "numeric_consistency" not in constraints
    else:
        assert constraints["numeric_consistency"] is enabled

def test_check_passes_constraint():
    client = VizierClient()
    client.verify = MagicMock(return_value="verified")
    assert client.check("send", "b", numeric_consistency=True) == "verified"
    assert client.verify.call_args.args[0].authority.constraints.numeric_consistency is True

def test_async_check_passes_constraint():
    client = AsyncVizierClient()
    client._sync_client.check = MagicMock(return_value="verified")
    assert asyncio.run(client.check("send", "b", numeric_consistency=True)) == "verified"
    assert client._sync_client.check.call_args.kwargs["numeric_consistency"] is True
