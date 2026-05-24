from __future__ import annotations

from collections import Counter
from pathlib import Path

from matrix_scanner.security import redact


WATCH_CODES = {"499", "500", "502", "504"}


def scan_nginx(access_log: str, error_log: str, max_lines: int = 500) -> dict:
    return {
        "access": summarize_access_log(access_log, max_lines),
        "errors": summarize_error_log(error_log, max_lines),
    }


def summarize_access_log(path: str, max_lines: int = 500) -> dict:
    lines = _tail_lines(path, max_lines)
    if isinstance(lines, dict):
        return lines
    codes: Counter[str] = Counter()
    endpoints: Counter[str] = Counter()
    for line in lines:
        parts = line.split()
        if len(parts) < 9:
            continue
        request = line.split('"')
        endpoint = request[1].split()[1] if len(request) > 1 and len(request[1].split()) >= 2 else "-"
        code = parts[8]
        codes[code] += 1
        if code in WATCH_CODES:
            endpoints[endpoint] += 1
    return {
        "status": "ok",
        "total_lines": len(lines),
        "status_codes": dict(codes.most_common(10)),
        "watched_codes": {code: codes.get(code, 0) for code in WATCH_CODES},
        "failing_endpoints": dict(endpoints.most_common(10)),
    }


def summarize_error_log(path: str, max_lines: int = 500) -> dict:
    lines = _tail_lines(path, max_lines)
    if isinstance(lines, dict):
        return lines
    interesting = [redact(line.strip()) for line in lines if any(token in line.lower() for token in ["error", "crit", "failed", "upstream"])]
    return {"status": "ok", "total_lines": len(lines), "recent_errors": interesting[-20:]}


def _tail_lines(path: str, max_lines: int) -> list[str] | dict:
    log_path = Path(path)
    if not log_path.exists():
        return {"status": "unavailable", "reason": "file_not_found", "path": path}
    try:
        lines = log_path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError as exc:
        return {"status": "unavailable", "reason": str(exc), "path": path}
    return lines[-max_lines:]
