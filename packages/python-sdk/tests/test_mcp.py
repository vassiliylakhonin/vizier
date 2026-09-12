import base64
import io
import json
import time
import pytest

from vizier.mcp import VizierMCPServer, run_mcp_server, TOOLS_METADATA


@pytest.fixture
def mcp_server():
    return VizierMCPServer(offline=True)


def test_tools_metadata_structure():
    assert len(TOOLS_METADATA) == 3
    tool_names = [t["name"] for t in TOOLS_METADATA]
    assert "vizier_screen_action" in tool_names
    assert "vizier_verify_receipt" in tool_names
    assert "vizier_check_policy" in tool_names

    for tool in TOOLS_METADATA:
        assert "description" in tool
        assert "inputSchema" in tool
        assert tool["inputSchema"]["type"] == "object"
        assert "required" in tool["inputSchema"]
        assert tool["annotations"]["readOnlyHint"] is True


def test_initialize_handshake(mcp_server):
    req = json.dumps({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "clientInfo": {"name": "claude-desktop", "version": "0.1.0"}
        }
    })
    resp_raw = mcp_server.handle_request(req)
    assert resp_raw is not None
    resp = json.loads(resp_raw)

    assert resp["jsonrpc"] == "2.0"
    assert resp["id"] == 1
    assert resp["result"]["protocolVersion"] == "2024-11-05"
    assert resp["result"]["serverInfo"]["name"] == "vizier-guard"
    assert resp["result"]["serverInfo"]["version"] == "0.3.1"
    assert resp["result"]["capabilities"]["tools"]["listChanged"] is False
    assert "deterministic authorization" in resp["result"]["instructions"].lower()


def test_notifications_initialized_returns_none(mcp_server):
    req = json.dumps({
        "jsonrpc": "2.0",
        "method": "notifications/initialized"
    })
    resp = mcp_server.handle_request(req)
    assert resp is None


def test_ping(mcp_server):
    req = json.dumps({
        "jsonrpc": "2.0",
        "id": "ping-123",
        "method": "ping"
    })
    resp = json.loads(mcp_server.handle_request(req))
    assert resp["id"] == "ping-123"
    assert resp["result"] == {}


def test_tools_list(mcp_server):
    req = json.dumps({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list"
    })
    resp = json.loads(mcp_server.handle_request(req))
    assert resp["id"] == 2
    tools = resp["result"]["tools"]
    assert len(tools) == 3
    assert {t["name"] for t in tools} == {
        "vizier_screen_action",
        "vizier_verify_receipt",
        "vizier_check_policy",
    }


def test_screen_action_allow(mcp_server):
    req = json.dumps({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "vizier_screen_action",
            "arguments": {
                "action_type": "tool_call",
                "target": "mcp://github/create_issue",
                "parameters": {"title": "Bug fix", "body": "Standard bug report"}
            }
        }
    })
    resp = json.loads(mcp_server.handle_request(req))
    assert resp["id"] == 3
    result = resp["result"]
    assert result["isError"] is False
    assert "Decision: ALLOW" in result["content"][0]["text"]
    assert result["structuredContent"]["decision"] == "ALLOW"
    assert result["structuredContent"]["receipt_id"] is not None
    assert result["structuredContent"]["receipt"]["valid"] is True


def test_screen_action_block_dangerous_command(mcp_server):
    req = json.dumps({
        "jsonrpc": "2.0",
        "id": 4,
        "method": "tools/call",
        "params": {
            "name": "vizier_screen_action",
            "arguments": {
                "action_type": "shell_command",
                "target": "bash://rm -rf /",
                "parameters": {}
            }
        }
    })
    resp = json.loads(mcp_server.handle_request(req))
    assert resp["id"] == 4
    result = resp["result"]
    assert result["isError"] is True
    assert "Decision: BLOCK" in result["content"][0]["text"]
    assert result["structuredContent"]["decision"] == "BLOCK"
    assert "DANGEROUS_COMMAND_BLOCKED" in result["structuredContent"]["reason_codes"]


def test_screen_action_block_dlp_secret(mcp_server):
    req = json.dumps({
        "jsonrpc": "2.0",
        "id": 5,
        "method": "tools/call",
        "params": {
            "name": "vizier_screen_action",
            "arguments": {
                "action_type": "external_api",
                "target": "https://api.example.com/deploy",
                "parameters": {
                    "env": "production",
                    "aws_secret": "AKIAIOSFODNN7EXAMPLE"
                }
            }
        }
    })
    resp = json.loads(mcp_server.handle_request(req))
    assert resp["id"] == 5
    result = resp["result"]
    assert result["isError"] is True
    assert result["structuredContent"]["decision"] == "BLOCK"
    assert "DLP_VIOLATION:SECRET_DETECTED" in result["structuredContent"]["reason_codes"]


def test_verify_receipt_valid_json(mcp_server):
    receipt_data = {
        "id": "rcpt-12345",
        "decision": "ALLOW",
        "valid": True,
        "issuer": "vizier"
    }
    req = json.dumps({
        "jsonrpc": "2.0",
        "id": 6,
        "method": "tools/call",
        "params": {
            "name": "vizier_verify_receipt",
            "arguments": {
                "receipt": json.dumps(receipt_data)
            }
        }
    })
    resp = json.loads(mcp_server.handle_request(req))
    assert resp["id"] == 6
    result = resp["result"]
    assert result["isError"] is False
    assert result["structuredContent"]["valid"] is True
    assert result["structuredContent"]["status"] == "VALID"


def test_verify_receipt_expired_jws(mcp_server):
    header = base64.urlsafe_b64encode(b'{"alg":"ES256","typ":"JWT"}').decode().rstrip("=")
    # Expired timestamp (1 hour ago)
    payload_dict = {"iss": "vizier", "decision": "ALLOW", "exp": time.time() - 3600, "jti": "rcpt-jws-expired"}
    payload = base64.urlsafe_b64encode(json.dumps(payload_dict).encode()).decode().rstrip("=")
    sig = base64.urlsafe_b64encode(b"dummysignature").decode().rstrip("=")
    jws_token = f"{header}.{payload}.{sig}"

    req = json.dumps({
        "jsonrpc": "2.0",
        "id": 7,
        "method": "tools/call",
        "params": {
            "name": "vizier_verify_receipt",
            "arguments": {"receipt": jws_token}
        }
    })
    resp = json.loads(mcp_server.handle_request(req))
    assert resp["id"] == 7
    result = resp["result"]
    assert result["isError"] is True
    assert result["structuredContent"]["status"] == "EXPIRED"
    assert result["structuredContent"]["valid"] is False


def test_check_policy_dlp(mcp_server):
    # Clean check
    req_clean = json.dumps({
        "jsonrpc": "2.0",
        "id": 8,
        "method": "tools/call",
        "params": {
            "name": "vizier_check_policy",
            "arguments": {
                "category": "dlp",
                "content": "Just a standard prompt with no secrets."
            }
        }
    })
    resp_clean = json.loads(mcp_server.handle_request(req_clean))
    assert resp_clean["result"]["isError"] is False
    assert resp_clean["result"]["structuredContent"]["clean"] is True

    # Leaked private key
    req_leak = json.dumps({
        "jsonrpc": "2.0",
        "id": 9,
        "method": "tools/call",
        "params": {
            "name": "vizier_check_policy",
            "arguments": {
                "category": "dlp",
                "content": "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA..."
            }
        }
    })
    resp_leak = json.loads(mcp_server.handle_request(req_leak))
    assert resp_leak["result"]["isError"] is True
    assert resp_leak["result"]["structuredContent"]["clean"] is False
    assert resp_leak["result"]["structuredContent"]["violations_count"] >= 1


def test_check_policy_sanctions(mcp_server):
    req_sanctioned = json.dumps({
        "jsonrpc": "2.0",
        "id": 10,
        "method": "tools/call",
        "params": {
            "name": "vizier_check_policy",
            "arguments": {
                "category": "sanctions",
                "content": "Taliban Central Committee"
            }
        }
    })
    resp_sanctioned = json.loads(mcp_server.handle_request(req_sanctioned))
    assert resp_sanctioned["result"]["isError"] is True
    assert resp_sanctioned["result"]["structuredContent"]["clean"] is False


def test_error_handling(mcp_server):
    # Parse error
    resp = json.loads(mcp_server.handle_request("{not json}"))
    assert resp["error"]["code"] == -32700

    # Invalid request
    resp = json.loads(mcp_server.handle_request(json.dumps({"foo": "bar"})))
    assert resp["error"]["code"] == -32600

    # Method not found
    resp = json.loads(mcp_server.handle_request(json.dumps({
        "jsonrpc": "2.0", "id": 11, "method": "unknown_method"
    })))
    assert resp["error"]["code"] == -32601

    # Tool not found
    resp = json.loads(mcp_server.handle_request(json.dumps({
        "jsonrpc": "2.0", "id": 12, "method": "tools/call", "params": {"name": "non_existent_tool"}
    })))
    assert resp["error"]["code"] == -32601


def test_stdio_runner(mcp_server):
    input_text = "\n".join([
        json.dumps({"jsonrpc": "2.0", "id": 1, "method": "ping"}),
        json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
    ]) + "\n"

    input_stream = io.StringIO(input_text)
    output_stream = io.StringIO()

    mcp_server.run_stdio(input_stream=input_stream, output_stream=output_stream)
    output_lines = [line.strip() for line in output_stream.getvalue().strip().split("\n") if line.strip()]

    assert len(output_lines) == 2
    resp1 = json.loads(output_lines[0])
    resp2 = json.loads(output_lines[1])

    assert resp1["id"] == 1
    assert resp1["result"] == {}
    assert resp2["id"] == 2
    assert len(resp2["result"]["tools"]) == 3
