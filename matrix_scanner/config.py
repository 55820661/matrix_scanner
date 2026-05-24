from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


DEFAULT_CONFIG: dict[str, Any] = {
    "database_path": "data/matrix_scanner.sqlite3",
    "scan_interval_minutes": 60,
    "metrics_retention_days": 14,
    "alerts_enabled": True,
    "telegram_enabled": False,
    "confirmation_timeout_seconds": 120,
    "laravel": {
        "path": "/var/www/app",
        "log_path": "/var/www/app/storage/logs/laravel.log",
    },
    "applications": [],
    "services": ["nginx", "php-fpm", "mysql"],
    "logs": {
        "nginx_access": "/var/log/nginx/access.log",
        "nginx_error": "/var/log/nginx/error.log",
        "max_lines": 500,
    },
    "thresholds": {
        "cpu_percent": 85,
        "ram_percent": 85,
        "disk_percent": 90,
        "nginx_5xx_count": 20,
        "laravel_error_count": 5,
    },
    "telegram": {
        "allowed_user_ids": [],
        "allowed_chat_ids": [],
        "default_chat_id": None,
    },
}


@dataclass(frozen=True)
class AppConfig:
    values: dict[str, Any] = field(default_factory=lambda: dict(DEFAULT_CONFIG))
    telegram_bot_token: str | None = None
    openai_api_key: str | None = None

    @property
    def database_path(self) -> Path:
        return Path(str(self.values["database_path"]))


def load_config(path: str | Path | None = None) -> AppConfig:
    values = _deep_copy(DEFAULT_CONFIG)
    if path:
        config_path = Path(path)
        if config_path.exists():
            loaded = _parse_simple_yaml(config_path.read_text(encoding="utf-8"))
            _deep_update(values, loaded)

    return AppConfig(
        values=values,
        telegram_bot_token=os.getenv("TELEGRAM_BOT_TOKEN"),
        openai_api_key=os.getenv("OPENAI_API_KEY"),
    )


def _deep_copy(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _deep_copy(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_deep_copy(v) for v in value]
    return value


def _deep_update(target: dict[str, Any], source: dict[str, Any]) -> None:
    for key, value in source.items():
        if isinstance(value, dict) and isinstance(target.get(key), dict):
            _deep_update(target[key], value)
        else:
            target[key] = value


def _parse_simple_yaml(text: str) -> dict[str, Any]:
    """Parse the small YAML subset used by config.yaml.example.

    This intentionally avoids a dependency for the first scaffold. It supports
    top-level keys, one-level nested maps, scalar values, and lists of scalars.
    """
    root: dict[str, Any] = {}
    current_map: dict[str, Any] | None = None
    current_list_key: str | None = None
    current_top_key: str | None = None

    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].rstrip()
        if not line.strip():
            continue

        indent = len(line) - len(line.lstrip(" "))
        stripped = line.strip()

        if indent == 0:
            current_map = None
            current_list_key = None
            key, _, value = stripped.partition(":")
            key = key.strip()
            current_top_key = key
            value = value.strip()
            if value == "":
                root[key] = {}
                current_map = root[key]
            else:
                root[key] = _parse_scalar(value)
            continue

        if current_map is None:
            continue

        if stripped.startswith("- "):
            item = _parse_scalar(stripped[2:].strip())
            if current_list_key is None and current_top_key:
                if not isinstance(root.get(current_top_key), list):
                    root[current_top_key] = []
                root[current_top_key].append(item)
                continue
            if current_list_key is None:
                continue
            current_map.setdefault(current_list_key, []).append(item)
            continue

        key, _, value = stripped.partition(":")
        key = key.strip()
        value = value.strip()
        if value == "":
            current_map[key] = []
            current_list_key = key
        else:
            current_map[key] = _parse_scalar(value)
            current_list_key = None

    return root


def _parse_scalar(value: str) -> Any:
    if value in {"true", "True"}:
        return True
    if value in {"false", "False"}:
        return False
    if value in {"null", "None", "~", ""}:
        return None
    if value.startswith("[") and value.endswith("]"):
        inner = value[1:-1].strip()
        if not inner:
            return []
        return [_parse_scalar(part.strip()) for part in inner.split(",")]
    try:
        return int(value)
    except ValueError:
        return value.strip('"').strip("'")
