from __future__ import annotations

from matrix_scanner.scanners.laravel import summarize_laravel_log
from matrix_scanner.scanners.nginx import summarize_error_log


def get_nginx_errors(context: dict) -> dict:
    logs = context["config"].get("logs", {})
    result = summarize_error_log(logs.get("nginx_error", ""), int(logs.get("max_lines", 500)))
    return {"nginx_errors": result, "summary_text": _summarize_errors(result)}


def get_laravel_errors(context: dict) -> dict:
    laravel = context["config"].get("laravel", {})
    logs = context["config"].get("logs", {})
    result = summarize_laravel_log(laravel.get("log_path", ""), int(logs.get("max_lines", 500)))
    return {"laravel_errors": result, "summary_text": _summarize_errors(result)}


def _summarize_errors(result: dict) -> str:
    if result.get("status") != "ok":
        return f"غير متاح: {result.get('reason', 'unknown')}"
    errors = result.get("recent_errors", [])
    if not errors:
        return "لا توجد أخطاء حديثة ضمن العينة الحالية."
    return "\n".join(errors[-5:])
