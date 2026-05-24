from __future__ import annotations

import json
from typing import Any, Callable

from matrix_scanner.security import truncate_text
from matrix_scanner.telegram_bot import send_message

SendFunc = Callable[..., Any]


def notify_alerts(alerts: list[dict[str, Any]], config: dict[str, Any], token: str | None, send_func: SendFunc = send_message) -> dict[str, Any]:
    if not alerts:
        return {"sent": 0, "warnings": []}
    if not config.get("alerts_enabled", True):
        return {"sent": 0, "warnings": []}
    if not config.get("telegram_enabled", False):
        return {"sent": 0, "warnings": []}

    chat_id = (config.get("telegram") or {}).get("default_chat_id")
    if not token:
        return {"sent": 0, "warnings": ["TELEGRAM_BOT_TOKEN is not set; alerts were not sent."]}
    if not chat_id:
        return {"sent": 0, "warnings": ["telegram.default_chat_id is not configured; alerts were not sent."]}

    sent = 0
    warnings = []
    for alert in alerts:
        try:
            send_func(token, chat_id, format_alert_message(alert))
            sent += 1
        except Exception as exc:  # notification must not fail the scan path
            warnings.append(f"Failed to send Telegram alert {alert.get('alert_key', 'unknown')}: {exc}")
    return {"sent": sent, "warnings": warnings}


def format_alert_message(alert: dict[str, Any]) -> str:
    lines = [
        "🚨 Matrix Scanner Alert",
        "",
        f"الخطورة: {alert.get('severity', 'unknown')}",
        f"المشكلة: {alert.get('title', 'unknown')}",
        f"الدليل: {_format_evidence(alert.get('evidence', {}))}",
        f"السبب المحتمل: {alert.get('probable_cause') or '-'}",
        f"الإجراء المقترح: {alert.get('suggested_action') or '-'}",
    ]
    return truncate_text("\n".join(lines), 1200)


def _format_evidence(evidence: Any) -> str:
    if not evidence:
        return "-"
    if isinstance(evidence, dict):
        safe_items = []
        for key, value in evidence.items():
            if _looks_like_log_field(str(key), value):
                continue
            safe_items.append(f"{key} = {_short_value(value)}")
        return truncate_text(", ".join(safe_items) if safe_items else "-", 400)
    return truncate_text(json.dumps(evidence, ensure_ascii=False, default=str), 400)


def _looks_like_log_field(key: str, value: Any) -> bool:
    lowered = key.lower()
    if any(token in lowered for token in ["log", "raw", "line", "trace", "stack", "recent_errors", "examples"]):
        return True
    return isinstance(value, (list, dict))


def _short_value(value: Any) -> str:
    if isinstance(value, (int, float, bool)) or value is None:
        return str(value)
    return truncate_text(str(value), 120)
