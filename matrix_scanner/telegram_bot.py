from __future__ import annotations

import json
import time
import urllib.parse
import urllib.request
from threading import Event
from typing import Any

from matrix_scanner import db
from matrix_scanner.security import Principal, is_telegram_allowed, truncate_text
from matrix_scanner.tool_executor import execute_tool

COMMAND_TO_TOOL = {
    "/status": "server_performance",
    "/performance": "server_performance",
    "/disk": "get_disk",
    "/services": "get_services",
    "/nginx": "get_nginx_errors",
    "/laravel": "get_laravel_errors",
    "/report": "generate_report",
}

TELEGRAM_MESSAGE_LIMIT = 4096
TELEGRAM_OFFSET_KEY = "telegram.next_update_offset"
MENU_PROMPT = "اختر أمرًا آخر:"
HELP_TEXT = """مرحبًا بك في Matrix Scanner.

الأوامر المتاحة:
/status - حالة السيرفر العامة
/performance - أداء السيرفر والخدمات
/services - حالة الخدمات فقط
/disk - مساحة التخزين
/report - تقرير كامل
/help - عرض القائمة"""


def command_keyboard() -> dict[str, Any]:
    return {
        "keyboard": [
            ["/status", "/report"],
            ["/services", "/disk"],
            ["/performance", "/help"],
        ],
        "resize_keyboard": True,
        "one_time_keyboard": False,
        "is_persistent": True,
    }


def map_command(text: str) -> str | None:
    command = text.strip().split()[0].lower() if text.strip() else ""
    return COMMAND_TO_TOOL.get(command)


def send_message(token: str, chat_id: int | str, text: str, timeout: int = 10, reply_markup: dict[str, Any] | None = None) -> dict[str, Any]:
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload: dict[str, Any] = {"chat_id": chat_id, "text": text}
    if reply_markup:
        payload["reply_markup"] = json.dumps(reply_markup, ensure_ascii=False)
    data = urllib.parse.urlencode(payload).encode("utf-8")
    request = urllib.request.Request(url, data=data, method="POST")
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def get_updates(token: str, offset: int | None = None, timeout: int = 30) -> dict[str, Any]:
    params: dict[str, Any] = {"timeout": timeout, "allowed_updates": json.dumps(["message", "edited_message"])}
    if offset is not None:
        params["offset"] = offset
    url = f"https://api.telegram.org/bot{token}/getUpdates?{urllib.parse.urlencode(params)}"
    with urllib.request.urlopen(url, timeout=timeout + 5) as response:
        return json.loads(response.read().decode("utf-8"))


def is_update_allowed(config: dict[str, Any], update: dict[str, Any]) -> bool:
    message = update.get("message") or update.get("edited_message") or {}
    chat = message.get("chat") or {}
    user = message.get("from") or {}
    return is_telegram_allowed(config, user.get("id"), chat.get("id"))


def extract_message(update: dict[str, Any]) -> dict[str, Any]:
    message = update.get("message") or update.get("edited_message") or {}
    return {
        "text": message.get("text", ""),
        "chat_id": (message.get("chat") or {}).get("id"),
        "user_id": (message.get("from") or {}).get("id"),
    }


def handle_update(
    *,
    conn,
    registry,
    config: dict[str, Any],
    token: str,
    update: dict[str, Any],
    send_func=send_message,
) -> dict[str, Any]:
    message = extract_message(update)
    chat_id = message["chat_id"]
    user_id = message["user_id"]
    text = message["text"]

    if chat_id is None:
        return {"status": "ignored", "reason": "missing_chat_id"}
    if not is_update_allowed(config, update):
        return {"status": "denied", "reason": "unauthorized", "chat_id": chat_id, "user_id": user_id}

    tool_key = map_command(text)
    if _is_help_command(text):
        _send_with_keyboard(send_func, token, chat_id, HELP_TEXT)
        return {"status": "handled", "tool_key": "help", "chat_id": chat_id, "user_id": user_id}
    if tool_key is None:
        _send_plain(send_func, token, chat_id, "الأمر غير معروف.")
        _send_with_keyboard(send_func, token, chat_id, MENU_PROMPT)
        return {"status": "ignored", "reason": "unknown_command", "chat_id": chat_id, "user_id": user_id}

    principal = Principal(id=None, telegram_user_id=user_id, telegram_chat_id=chat_id, role="admin")
    result = execute_tool(
        conn,
        registry,
        tool_key=tool_key,
        context={"config": config},
        source="telegram",
        principal=principal,
        input_data={"text": text, "chat_id": chat_id, "user_id": user_id},
    )
    response_text = format_tool_response(result)
    _send_plain(send_func, token, chat_id, response_text)
    _send_with_keyboard(send_func, token, chat_id, MENU_PROMPT)
    return {"status": "handled", "tool_key": tool_key, "result_ok": bool(result.get("ok"))}


def format_tool_response(result: dict[str, Any]) -> str:
    if not result.get("ok"):
        return f"تعذر تنفيذ الطلب: {result.get('error', 'unknown_error')}"
    output = result.get("output", {})
    text = output.get("telegram_text") or output.get("summary_text") or output.get("report_text") or json.dumps(output, ensure_ascii=False, indent=2)
    return truncate_text(text, TELEGRAM_MESSAGE_LIMIT)


def poll_once(
    *,
    conn,
    registry,
    config: dict[str, Any],
    token: str,
    offset: int | None = None,
    send_func=send_message,
    get_updates_func=get_updates,
) -> int | None:
    current_offset = offset if offset is not None else load_next_update_offset(conn)
    response = get_updates_func(token, offset=current_offset, timeout=int(config.get("telegram", {}).get("poll_timeout_seconds", 30)))
    if not response.get("ok"):
        return current_offset
    next_offset = current_offset
    for update in response.get("result", []):
        update_id = update.get("update_id")
        if update_id is not None and next_offset is not None and int(update_id) < int(next_offset):
            continue
        handle_update(conn=conn, registry=registry, config=config, token=token, update=update, send_func=send_func)
        if update_id is not None:
            next_offset = int(update_id) + 1
            save_next_update_offset(conn, next_offset)
    return next_offset


def run_long_polling(
    *,
    conn,
    registry,
    config: dict[str, Any],
    token: str,
    stop_after: int | None = None,
    stop_event: Event | None = None,
    send_func=send_message,
    get_updates_func=get_updates,
) -> None:
    offset = load_next_update_offset(conn)
    iterations = 0
    while not (stop_event and stop_event.is_set()):
        offset = poll_once(
            conn=conn,
            registry=registry,
            config=config,
            token=token,
            offset=offset,
            send_func=send_func,
            get_updates_func=get_updates_func,
        )
        iterations += 1
        if stop_after is not None and iterations >= stop_after:
            return
        if stop_event and stop_event.is_set():
            return
        time.sleep(float(config.get("telegram", {}).get("poll_sleep_seconds", 1)))


def load_next_update_offset(conn) -> int | None:
    value = db.get_setting(conn, TELEGRAM_OFFSET_KEY)
    return int(value) if value is not None else None


def save_next_update_offset(conn, offset: int) -> None:
    db.set_setting(conn, TELEGRAM_OFFSET_KEY, int(offset))


def _is_help_command(text: str) -> bool:
    command = text.strip().split()[0].lower() if text.strip() else ""
    return command in {"/start", "/help"}


def _send_plain(send_func, token: str, chat_id: int | str, text: str) -> None:
    send_func(token, chat_id, text)


def _send_with_keyboard(send_func, token: str, chat_id: int | str, text: str) -> None:
    try:
        send_func(token, chat_id, text, reply_markup=command_keyboard())
    except TypeError:
        send_func(token, chat_id, text)
