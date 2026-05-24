from __future__ import annotations

from collections import Counter
from pathlib import Path

from matrix_scanner.security import redact


def scan_laravel(log_path: str, project_path: str, max_lines: int = 500) -> dict:
    return {
        "log": summarize_laravel_log(log_path, max_lines),
        "env": summarize_laravel_env(project_path),
    }


def summarize_laravel_log(path: str, max_lines: int = 500) -> dict:
    log_path = Path(path)
    if not log_path.exists():
        return {"status": "unavailable", "reason": "file_not_found", "path": path}
    try:
        lines = log_path.read_text(encoding="utf-8", errors="ignore").splitlines()[-max_lines:]
    except OSError as exc:
        return {"status": "unavailable", "reason": str(exc), "path": path}
    errors = [redact(line.strip()) for line in lines if any(token in line.lower() for token in ["error", "exception", "critical", "production.error"])]
    classes = Counter()
    for line in errors:
        if ".ERROR:" in line or ".CRITICAL:" in line:
            parts = line.split()
            if parts:
                classes[parts[-1].strip("[]")] += 1
    return {"status": "ok", "total_lines": len(lines), "error_count": len(errors), "recent_errors": errors[-20:], "top_tokens": dict(classes.most_common(10))}


def summarize_laravel_env(project_path: str) -> dict:
    env_path = Path(project_path) / ".env"
    if not env_path.exists():
        return {"status": "unavailable", "reason": "env_not_found"}
    allowed = {"APP_ENV", "APP_DEBUG", "QUEUE_CONNECTION", "CACHE_DRIVER", "SESSION_DRIVER"}
    result = {}
    try:
        lines = env_path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError as exc:
        return {"status": "unavailable", "reason": str(exc)}
    for line in lines:
        if "=" not in line or line.strip().startswith("#"):
            continue
        key, value = line.split("=", 1)
        if key in allowed:
            result[key] = value
    return {"status": "ok", "values": result}
