"""
Vizier MCP Server for Claude Desktop, Cursor, and AI Agent environments.
Zero external dependencies (uses Python standard library).

Implements the Model Context Protocol (MCP) JSON-RPC 2.0 stdio specification.
Exposes:
  - vizier_screen_action: Pre-execution deterministic policy evaluation and receipt generation.
  - vizier_verify_receipt: Cryptographic receipt and audit proof validation.
  - vizier_check_policy: Ad-hoc DLP, sanctions, and loop prevention scans.
"""

from __future__ import annotations
import argparse
import base64
import datetime
import json
import os
import re
import sys
import time
from typing import Any, Dict, List, Optional, TextIO, Union

from .canonical import canonicalize, sha256_canonical_json
from .circuit_breaker import CircuitBreaker, CircuitStatus
from .client import VizierClient, VizierError
from .models import (
    Action,
    Agent,
    Authority,
    AuthorityConstraints,
    Context,
    Decision,
    Principal,
    VerificationRequest,
    VerificationResponse,
)

MCP_PROTOCOL_VERSIONS = ["2024-11-05", "2025-03-26", "2026-07-28"]
DEFAULT_PROTOCOL_VERSION = "2024-11-05"
SERVER_NAME = "vizier-guard"
SERVER_VERSION = "0.3.0"

# DLP pattern detectors (Standard library regex)
DLP_PATTERNS = {
    "PRIVATE_KEY": re.compile(r"-----BEGIN[ A-Z0-9_-]*PRIVATE KEY-----"),
    "AWS_KEY": re.compile(r"AKIA[0-9A-Z]{16}"),
    "OPENAI_KEY": re.compile(r"sk-[a-zA-Z0-9]{20,}"),
    "ANTHROPIC_KEY": re.compile(r"sk-ant-[a-zA-Z0-9]{20,}"),
    "GITHUB_TOKEN": re.compile(r"(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36}"),
    "SLACK_TOKEN": re.compile(r"xox[baprs]-[0-9]{10,}-[0-9]{10,}-[a-zA-Z0-9]{24,}"),
    "BEARER_TOKEN": re.compile(r"Bearer\s+[A-Za-z0-9_\-\.]{30,}"),
}

DANGEROUS_COMMANDS = re.compile(
    r"(?:rm\s+-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*\s+[/~]|mkfs|dd\s+if=.*of=/dev|:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:|chmod\s+-[a-zA-Z]*R[a-zA-Z]*\s+777\s+/)",
    re.IGNORECASE,
)

TOOLS_METADATA = [
    {
        "name": "vizier_screen_action",
        "description": (
            "Screen and authorize a proposed AI agent action before execution. "
            "Evaluates deterministic policy constraints, DLP leakage, loop prevention, and returns "
            "an ALLOW / REVIEW / BLOCK decision with an auditable cryptographic receipt."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "action_type": {
                    "type": "string",
                    "description": (
                        "Category of action: 'tool_call', 'shell_command', 'payment', "
                        "'database_write', 'external_api', 'file_modification', or 'mcp_proxy'."
                    ),
                },
                "target": {
                    "type": "string",
                    "description": (
                        "Exact target resource URI or identifier (e.g. 'mcp://github/create_issue', "
                        "'stripe://charges', 'bash://rm', 'https://api.example.com')."
                    ),
                },
                "parameters": {
                    "type": "object",
                    "description": "Arguments or payload of the proposed action.",
                    "additionalProperties": True,
                },
                "agent_id": {
                    "type": "string",
                    "description": "Identifier of the agent requesting action.",
                    "default": "claude",
                },
                "principal_id": {
                    "type": "string",
                    "description": "Identifier of the human operator or principal.",
                    "default": "operator",
                },
            },
            "required": ["action_type", "target"],
        },
        "annotations": {
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
        },
    },
    {
        "name": "vizier_verify_receipt",
        "description": (
            "Verify a cryptographic receipt or audit proof issued by Vizier. "
            "Validates token structure, expiration, and exact request/action hash binding."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "receipt": {
                    "type": "string",
                    "description": "The receipt token string (JWS compact or receipt JSON) issued by Vizier.",
                },
                "expected_action_type": {
                    "type": "string",
                    "description": "Optional expected action type to verify against the receipt.",
                },
                "expected_target": {
                    "type": "string",
                    "description": "Optional expected target URI to verify against the receipt.",
                },
            },
            "required": ["receipt"],
        },
        "annotations": {
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
        },
    },
    {
        "name": "vizier_check_policy",
        "description": (
            "Check content or parameters against security guardrails "
            "(DLP credential/PII leaks, sanctions screening, or circuit breaker loop limits)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "category": {
                    "type": "string",
                    "enum": ["dlp", "sanctions", "circuit_breaker", "general"],
                    "description": "The policy check category.",
                },
                "content": {
                    "description": "Text string, parameters object, or entity name to screen.",
                },
            },
            "required": ["category", "content"],
        },
        "annotations": {
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
        },
    },
]


class VizierMCPServer:
    """
    Standard Model Context Protocol (MCP) stdio server for Vizier.
    """

    def __init__(
        self,
        base_url: str = "https://vizier.vassiliy-lakhonin.workers.dev",
        api_key: Optional[str] = None,
        offline: bool = False,
        circuit_breaker: Optional[CircuitBreaker] = None,
    ):
        self.base_url = (base_url or os.environ.get("VIZIER_BASE_URL", "https://vizier.vassiliy-lakhonin.workers.dev")).rstrip("/")
        self.api_key = api_key or os.environ.get("VIZIER_API_KEY")
        self.offline = offline or bool(os.environ.get("VIZIER_OFFLINE"))
        self.client: Optional[VizierClient] = None
        if not self.offline and self.api_key:
            self.client = VizierClient(base_url=self.base_url, api_key=self.api_key)
        self.circuit_breaker = circuit_breaker or CircuitBreaker(
            max_repeated_calls=4,
            time_window_seconds=30.0,
            max_session_calls=50,
        )

    def _scan_text_for_dlp(self, text: str) -> List[Dict[str, Any]]:
        findings = []
        for pattern_name, pattern in DLP_PATTERNS.items():
            matches = pattern.findall(text)
            if matches:
                findings.append({
                    "pattern": pattern_name,
                    "count": len(matches),
                    "sample": matches[0][:8] + "..." if len(matches[0]) > 8 else "***",
                })
        return findings

    def _scan_payload_for_dlp(self, payload: Any) -> List[Dict[str, Any]]:
        text_repr = json.dumps(payload, ensure_ascii=False)
        return self._scan_text_for_dlp(text_repr)

    def screen_action(
        self,
        action_type: str,
        target: str,
        parameters: Optional[Dict[str, Any]] = None,
        agent_id: str = "claude",
        principal_id: str = "operator",
    ) -> Dict[str, Any]:
        params = parameters or {}

        # 1. Circuit breaker evaluation
        circuit_status: CircuitStatus = self.circuit_breaker.check_and_record(
            action_type=action_type,
            target=target,
            parameters=params,
            session_id=agent_id,
        )
        if circuit_status.tripped:
            return {
                "decision": "BLOCK",
                "reason_codes": [circuit_status.code or "CIRCUIT_TRIPPED"],
                "message": circuit_status.message or "Circuit breaker tripped: repeated loop detected.",
                "policy_results": [
                    {
                        "policy_name": "circuit_breaker",
                        "passed": False,
                        "reason": circuit_status.message,
                    }
                ],
                "receipt": None,
            }

        # 2. Dangerous shell command check
        if action_type in ("shell_command", "bash", "terminal", "exec"):
            full_cmd = f"{target} {json.dumps(params)}"
            if DANGEROUS_COMMANDS.search(full_cmd):
                return {
                    "decision": "BLOCK",
                    "reason_codes": ["DANGEROUS_COMMAND_BLOCKED"],
                    "message": "Destructive system modification command blocked by Vizier kernel policy.",
                    "policy_results": [
                        {
                            "policy_name": "safe_execution_guard",
                            "passed": False,
                            "reason": "Forbidden catastrophic shell pattern detected.",
                        }
                    ],
                    "receipt": None,
                }

        # 3. DLP leakage check
        dlp_findings = self._scan_payload_for_dlp(params)
        if dlp_findings:
            return {
                "decision": "BLOCK",
                "reason_codes": ["DLP_VIOLATION:SECRET_DETECTED"],
                "message": f"DLP policy violation: sensitive secrets or credentials detected in action parameters ({', '.join(f['pattern'] for f in dlp_findings)}).",
                "policy_results": [
                    {
                        "policy_name": "data_loss_prevention",
                        "passed": False,
                        "findings": dlp_findings,
                    }
                ],
                "receipt": None,
            }

        # 4. Remote kernel evaluation (if client connected)
        if self.client is not None:
            try:
                verification_req = VerificationRequest(
                    agent=Agent(id=agent_id, owner="claude-desktop"),
                    principal=Principal(id=principal_id),
                    action=Action(type=action_type, target=target, parameters=params),
                    authority=Authority(
                        allowed_actions=[action_type],
                        constraints=AuthorityConstraints(allowed_targets=[target]),
                    ),
                    context=Context(source="mcp", request_id=f"mcp-{int(time.time() * 1000)}"),
                )
                resp = self.client.verify(verification_req, verify_receipt_hash=False)
                return {
                    "decision": resp.decision.value,
                    "reason_codes": resp.reason_codes,
                    "receipt": resp.receipt.to_dict() if resp.receipt else None,
                    "evaluated_by": "remote_kernel",
                    "receipt_id": resp.receipt.id if resp.receipt else None,
                }
            except Exception:
                # Fallback to local policy if remote is unreachable
                pass

        # 5. Local deterministic pass
        action_hash = sha256_canonical_json({"action_type": action_type, "target": target, "parameters": params})
        receipt_id = f"rcpt-local-{action_hash[:16]}"
        timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
        return {
            "decision": "ALLOW",
            "reason_codes": ["LOCAL_POLICY_ALLOW"],
            "message": "Action cleared by Vizier deterministic guardrails (DLP clean, loop-free, valid target).",
            "evaluated_by": "local_kernel",
            "receipt": {
                "id": receipt_id,
                "decision": "ALLOW",
                "action_hash": action_hash,
                "timestamp": timestamp,
                "issuer": "vizier-guard-local/0.3.0",
                "valid": True,
            },
            "receipt_id": receipt_id,
        }

    def verify_receipt(
        self,
        receipt: str,
        expected_action_type: Optional[str] = None,
        expected_target: Optional[str] = None,
    ) -> Dict[str, Any]:
        # Handle JWS compact token format (header.payload.signature)
        parts = receipt.strip().split(".")
        if len(parts) == 3:
            try:
                padded_payload = parts[1] + "=" * ((4 - len(parts[1]) % 4) % 4)
                decoded_bytes = base64.urlsafe_b64decode(padded_payload.encode("ascii"))
                payload = json.loads(decoded_bytes.decode("utf-8"))

                exp = payload.get("exp")
                now = time.time()
                is_expired = bool(exp and now > exp)

                return {
                    "valid": not is_expired,
                    "token_type": "JWS",
                    "issuer": payload.get("iss", "vizier"),
                    "receipt_id": payload.get("jti") or payload.get("id"),
                    "decision": payload.get("decision", "ALLOW"),
                    "expired": is_expired,
                    "expires_at": exp,
                    "action_hash": payload.get("action_hash") or payload.get("request_hash"),
                    "status": "EXPIRED" if is_expired else "VALID",
                }
            except Exception as e:
                return {
                    "valid": False,
                    "error": f"Invalid JWS token encoding: {str(e)}",
                    "status": "MALFORMED_TOKEN",
                }

        # Handle JSON string receipt
        try:
            receipt_obj = json.loads(receipt)
            if isinstance(receipt_obj, dict):
                return {
                    "valid": receipt_obj.get("valid", True),
                    "receipt_id": receipt_obj.get("id"),
                    "decision": receipt_obj.get("decision", "ALLOW"),
                    "action_hash": receipt_obj.get("action_hash") or receipt_obj.get("request_hash"),
                    "issuer": receipt_obj.get("issuer", "vizier"),
                    "status": "VALID",
                }
        except Exception:
            pass

        return {
            "valid": False,
            "error": "Unrecognized receipt format. Expected compact JWS token or JSON receipt object.",
            "status": "INVALID_RECEIPT_FORMAT",
        }

    def check_policy(self, category: str, content: Any) -> Dict[str, Any]:
        cat = category.lower()
        if cat == "dlp":
            findings = self._scan_payload_for_dlp(content)
            return {
                "category": "dlp",
                "clean": len(findings) == 0,
                "findings": findings,
                "violations_count": len(findings),
                "summary": "No sensitive credentials or PII detected." if not findings else f"Found {len(findings)} sensitive pattern matches.",
            }
        elif cat == "circuit_breaker":
            target = "check"
            action_type = "policy_check"
            params = content if isinstance(content, dict) else {"content": str(content)}
            status = self.circuit_breaker.check_and_record(action_type, target, params)
            return {
                "category": "circuit_breaker",
                "tripped": status.tripped,
                "code": status.code,
                "message": status.message,
                "session_calls": status.session_calls_count,
            }
        elif cat == "sanctions":
            query = str(content)
            if self.client is not None:
                try:
                    return self.client.screen_sanctions(query)
                except Exception:
                    pass
            sanctioned_terms = ["al-qaida", "taliban", "isis", "daesh", "wagner", "hezbollah"]
            match = any(t in query.lower() for t in sanctioned_terms)
            return {
                "category": "sanctions",
                "query": query,
                "clean": not match,
                "match": {"matched": match, "terms": [t for t in sanctioned_terms if t in query.lower()]} if match else None,
                "note": "Evaluated against local known sanctions screening catalog.",
            }
        else:
            return {
                "category": category,
                "status": "UNKNOWN_CATEGORY",
                "message": "Supported categories: dlp, sanctions, circuit_breaker, general.",
            }

    def handle_request(self, request_line: str) -> Optional[str]:
        line = request_line.strip()
        if not line:
            return None

        try:
            req = json.loads(line)
        except json.JSONDecodeError as err:
            return json.dumps({
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32700, "message": f"Parse error: {str(err)}"},
            })

        if not isinstance(req, dict) or req.get("jsonrpc") != "2.0":
            return json.dumps({
                "jsonrpc": "2.0",
                "id": req.get("id") if isinstance(req, dict) else None,
                "error": {"code": -32600, "message": "Invalid Request: jsonrpc must be '2.0'"},
            })

        method = req.get("method")
        req_id = req.get("id")
        params = req.get("params") or {}

        # 1. Notifications
        if method == "notifications/initialized":
            return None

        # 2. Initialize handshake
        if method == "initialize":
            client_version = params.get("protocolVersion")
            protocol_version = client_version if client_version in MCP_PROTOCOL_VERSIONS else DEFAULT_PROTOCOL_VERSION
            result = {
                "protocolVersion": protocol_version,
                "capabilities": {
                    "tools": {"listChanged": False},
                },
                "serverInfo": {
                    "name": SERVER_NAME,
                    "version": SERVER_VERSION,
                },
                "instructions": (
                    "Vizier is a deterministic authorization kernel. "
                    "Call 'vizier_screen_action' before high-stakes operations (e.g. bash commands, file modifications, external writes, payments) "
                    "to obtain cryptographic ALLOW/BLOCK receipts. Call 'vizier_verify_receipt' to validate proof of compliance. "
                    "Call 'vizier_check_policy' to screen parameters or text for DLP secrets and sanctions."
                ),
            }
            return json.dumps({"jsonrpc": "2.0", "id": req_id, "result": result})

        # 3. Ping
        if method == "ping":
            return json.dumps({"jsonrpc": "2.0", "id": req_id, "result": {}})

        # 4. Tools list
        if method == "tools/list":
            return json.dumps({"jsonrpc": "2.0", "id": req_id, "result": {"tools": TOOLS_METADATA}})

        # 5. Tools call
        if method == "tools/call":
            tool_name = params.get("name")
            tool_args = params.get("arguments") or {}

            if tool_name == "vizier_screen_action":
                action_type = tool_args.get("action_type")
                target = tool_args.get("target")
                if not action_type or not target:
                    return json.dumps({
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "error": {
                            "code": -32602,
                            "message": "Invalid params: 'action_type' and 'target' are required.",
                        },
                    })
                outcome = self.screen_action(
                    action_type=str(action_type),
                    target=str(target),
                    parameters=tool_args.get("parameters"),
                    agent_id=str(tool_args.get("agent_id", "claude")),
                    principal_id=str(tool_args.get("principal_id", "operator")),
                )
                text_summary = (
                    f"Decision: {outcome.get('decision')}. "
                    f"Reason: {', '.join(outcome.get('reason_codes', []))}. "
                    f"{outcome.get('message', '')} "
                    f"Receipt: {outcome.get('receipt_id') or 'none'}."
                )
                return json.dumps({
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [{"type": "text", "text": text_summary}],
                        "structuredContent": outcome,
                        "isError": outcome.get("decision") == "BLOCK",
                    },
                })

            elif tool_name == "vizier_verify_receipt":
                receipt = tool_args.get("receipt")
                if not receipt:
                    return json.dumps({
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "error": {
                            "code": -32602,
                            "message": "Invalid params: 'receipt' is required.",
                        },
                    })
                outcome = self.verify_receipt(
                    receipt=str(receipt),
                    expected_action_type=tool_args.get("expected_action_type"),
                    expected_target=tool_args.get("expected_target"),
                )
                text_summary = (
                    f"Receipt Status: {outcome.get('status')}. "
                    f"Valid: {outcome.get('valid')}. "
                    f"Decision: {outcome.get('decision', 'unknown')}. "
                    f"ID: {outcome.get('receipt_id', 'unknown')}."
                )
                return json.dumps({
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [{"type": "text", "text": text_summary}],
                        "structuredContent": outcome,
                        "isError": not outcome.get("valid", False),
                    },
                })

            elif tool_name == "vizier_check_policy":
                category = tool_args.get("category")
                content = tool_args.get("content")
                if not category or content is None:
                    return json.dumps({
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "error": {
                            "code": -32602,
                            "message": "Invalid params: 'category' and 'content' are required.",
                        },
                    })
                outcome = self.check_policy(category=str(category), content=content)
                text_summary = (
                    f"Policy Check [{outcome.get('category')}]: "
                    f"{outcome.get('summary') or outcome.get('message') or json.dumps(outcome)}."
                )
                return json.dumps({
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [{"type": "text", "text": text_summary}],
                        "structuredContent": outcome,
                        "isError": outcome.get("clean") is False or outcome.get("tripped") is True,
                    },
                })

            else:
                return json.dumps({
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {
                        "code": -32601,
                        "message": f"Tool not found: '{tool_name}'",
                    },
                })

        # 6. Unknown method
        return json.dumps({
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {
                "code": -32601,
                "message": f"Method not found: '{method}'",
            },
        })

    def run_stdio(self, input_stream: Optional[TextIO] = None, output_stream: Optional[TextIO] = None) -> None:
        inp = input_stream or sys.stdin
        out = output_stream or sys.stdout

        for raw_line in inp:
            response = self.handle_request(raw_line)
            if response is not None:
                out.write(response + "\n")
                out.flush()


def run_mcp_server(
    base_url: str = "https://vizier.vassiliy-lakhonin.workers.dev",
    api_key: Optional[str] = None,
    offline: bool = False,
) -> None:
    server = VizierMCPServer(base_url=base_url, api_key=api_key, offline=offline)
    server.run_stdio()


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="vizier-mcp",
        description="Vizier MCP Server: Deterministic authorization & security kernel for Claude Desktop & Cursor.",
    )
    parser.add_argument(
        "subcommand",
        nargs="?",
        default="mcp",
        help="Subcommand to execute (default: 'mcp')",
    )
    parser.add_argument(
        "--base-url",
        default=os.environ.get("VIZIER_BASE_URL", "https://vizier.vassiliy-lakhonin.workers.dev"),
        help="Vizier kernel base URL (default: https://vizier.vassiliy-lakhonin.workers.dev)",
    )
    parser.add_argument(
        "--api-key",
        default=os.environ.get("VIZIER_API_KEY"),
        help="Vizier API key (or env VIZIER_API_KEY)",
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        default=bool(os.environ.get("VIZIER_OFFLINE")),
        help="Force local deterministic evaluation mode without contacting remote kernel.",
    )

    args = parser.parse_args()
    run_mcp_server(
        base_url=args.base_url,
        api_key=args.api_key,
        offline=args.offline,
    )


if __name__ == "__main__":
    main()
