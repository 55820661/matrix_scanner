from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


SECRET_PATTERNS = [
    re.compile(r"(APP_KEY=)[^\s]+", re.IGNORECASE),
    re.compile(r"(DB_PASSWORD=)[^\s]+", re.IGNORECASE),
    re.compile(r"(TOKEN=)[^\s]+", re.IGNORECASE),
    re.compile(r"(SECRET=)[^\s]+", re.IGNORECASE),
]


@dataclass(frozen=True)
class Principal:
    id: int | None
    telegram_user_id: int | None
    telegram_chat_id: int | None
    role: str = "admin"


def is_telegram_allowed(config: dict[str, Any], user_id: int | None, chat_id: int | None) -> bool:
    telegram = config.get("telegram", {})
    allowed_users = {int(v) for v in telegram.get("allowed_user_ids", []) if v is not None}
    allowed_chats = {int(v) for v in telegram.get("allowed_chat_ids", []) if v is not None}
    if not allowed_users and not allowed_chats:
        return False
    return (user_id in allowed_users) or (chat_id in allowed_chats)


def redact(text: str) -> str:
    redacted = text
    for pattern in SECRET_PATTERNS:
        redacted = pattern.sub(r"\1[REDACTED]", redacted)
    return redacted


def truncate_text(text: str, max_chars: int) -> str:
    if len(text) <= max_chars:
        return text
    if max_chars <= 32:
        return text[:max_chars]
    return text[: max_chars - 32] + "\n...[truncated for safety]..."
