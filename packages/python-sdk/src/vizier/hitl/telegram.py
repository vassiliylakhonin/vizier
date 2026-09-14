from __future__ import annotations
import json
import time
import urllib.request
import urllib.error
import uuid
from typing import Any, Dict, List, Optional, Union

from .base import BaseHITLHandler, HITLApprovalResult
from ..models import VerificationResponse

class TelegramHITLHandler(BaseHITLHandler):
    """
    Telegram Bot Human-in-the-Loop approval handler.
    Sends interactive approval messages with inline buttons (Approve/Reject)
    directly to a manager or security team channel via Telegram Bot API.
    Zero external dependencies required (uses Python standard library).
    """

    def __init__(
        self,
        bot_token: str,
        chat_id: Union[str, int],
        allowed_operators: List[Union[int, str]],
        timeout: float = 60.0,
        poll_interval: float = 1.5,
        base_api_url: str = "https://api.telegram.org",
    ):
        self.bot_token = bot_token
        self.chat_id = str(chat_id)
        if not allowed_operators:
            raise ValueError(
                "allowed_operators must contain at least one numeric Telegram user ID to prevent approval spoofing."
            )
        parsed_operators: set[int] = set()
        for op in allowed_operators:
            try:
                parsed_operators.add(int(op))
            except (ValueError, TypeError):
                raise ValueError(
                    f"Invalid operator ID '{op}'. allowed_operators must contain stable numeric Telegram user IDs (not mutable @usernames)."
                )
        self.allowed_operators: set[int] = parsed_operators
        self.timeout = timeout
        self.poll_interval = poll_interval
        self.api_base = f"{base_api_url.rstrip('/')}/bot{self.bot_token}"

    def _api_call(self, method: str, data: Dict[str, Any]) -> Dict[str, Any]:
        url = f"{self.api_base}/{method}"
        payload = json.dumps(data).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=10.0) as res:
                return json.loads(res.read().decode("utf-8"))
        except Exception as err:
            return {"ok": False, "description": str(err)}

    def request_approval(
        self,
        action_type: str,
        target: str,
        parameters: Dict[str, Any],
        verification: VerificationResponse,
    ) -> HITLApprovalResult:
        nonce = uuid.uuid4().hex[:8]
        cb_approve = f"vz_app_{nonce}"
        cb_reject = f"vz_rej_{nonce}"

        # 1. Format and send Telegram message
        text = (
            f"🛡️ *Vizier Action Review Required*\n\n"
            f"• *Action:* `{action_type}`\n"
            f"• *Target:* `{target}`\n"
            f"• *Parameters:* `{json.dumps(parameters, default=str)}`\n"
            f"• *Decision:* `{verification.decision}` (Risk: {verification.risk_score})\n"
            f"• *Explanation:* {verification.explanation}\n"
            f"• *Reason Codes:* `{verification.reason_codes}`\n\n"
            f"⏳ *Expires in {int(self.timeout)}s*"
        )

        reply_markup = {
            "inline_keyboard": [
                [
                    {"text": "✅ Approve", "callback_data": cb_approve},
                    {"text": "❌ Reject", "callback_data": cb_reject},
                ]
            ]
        }

        send_res = self._api_call(
            "sendMessage",
            {
                "chat_id": self.chat_id,
                "text": text,
                "parse_mode": "Markdown",
                "reply_markup": reply_markup,
            },
        )

        if not send_res.get("ok"):
            return HITLApprovalResult(
                approved=False,
                reason=f"Failed to dispatch Telegram message: {send_res.get('description')}",
            )

        message_id = send_res.get("result", {}).get("message_id")
        start_time = time.time()
        offset = 0

        # 2. Poll for callback response
        while time.time() - start_time < self.timeout:
            updates_res = self._api_call("getUpdates", {"offset": offset, "timeout": 2})
            if updates_res.get("ok") and updates_res.get("result"):
                for update in updates_res["result"]:
                    offset = max(offset, update["update_id"] + 1)
                    cb = update.get("callback_query")
                    if not cb:
                        continue

                    # Validate that callback belongs to this exact message and chat
                    cb_msg = cb.get("message") or {}
                    cb_chat_id = str(cb_msg.get("chat", {}).get("id", ""))
                    cb_msg_id = cb_msg.get("message_id")
                    if str(self.chat_id) != cb_chat_id or (message_id and cb_msg_id != message_id):
                        continue

                    data = cb.get("data")
                    from_user = cb.get("from") or {}
                    raw_user_id = from_user.get("id")
                    if raw_user_id is None:
                        continue
                    try:
                        user_id = int(raw_user_id)
                    except (ValueError, TypeError):
                        continue

                    username = from_user.get("username")
                    user = username or str(user_id)
                    cb_id = cb.get("id")

                    # Verify operator against mandatory stable numeric allowed_operators set
                    if user_id not in self.allowed_operators:
                        self._api_call(
                            "answerCallbackQuery",
                            {"callback_query_id": cb_id, "text": "Unauthorized operator.", "show_alert": True},
                        )
                        continue

                    if data == cb_approve:
                        self._api_call("answerCallbackQuery", {"callback_query_id": cb_id, "text": "Action approved!"})
                        if message_id:
                            self._api_call(
                                "editMessageText",
                                {
                                    "chat_id": self.chat_id,
                                    "message_id": message_id,
                                    "text": f"{text}\n\n✅ *APPROVED by @{user}*",
                                    "parse_mode": "Markdown",
                                },
                            )
                        return HITLApprovalResult(
                            approved=True,
                            reason=f"Approved by Telegram operator @{user}",
                            operator_id=f"telegram:{user}",
                        )

                    elif data == cb_reject:
                        self._api_call("answerCallbackQuery", {"callback_query_id": cb_id, "text": "Action rejected!"})
                        if message_id:
                            self._api_call(
                                "editMessageText",
                                {
                                    "chat_id": self.chat_id,
                                    "message_id": message_id,
                                    "text": f"{text}\n\n❌ *REJECTED by @{user}*",
                                    "parse_mode": "Markdown",
                                },
                            )
                        return HITLApprovalResult(
                            approved=False,
                            reason=f"Rejected by Telegram operator @{user}",
                            operator_id=f"telegram:{user}",
                        )

            time.sleep(self.poll_interval)

        # 3. Handle timeout
        if message_id:
            self._api_call(
                "editMessageText",
                {
                    "chat_id": self.chat_id,
                    "message_id": message_id,
                    "text": f"{text}\n\n⏳ *APPROVAL TIMED OUT*",
                    "parse_mode": "Markdown",
                },
            )

        return HITLApprovalResult(
            approved=False,
            reason=f"Telegram approval timed out after {int(self.timeout)} seconds.",
        )
