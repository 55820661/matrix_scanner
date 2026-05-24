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
    groups = result.get("groups", [])
    if not groups:
        return "لا توجد أخطاء حديثة ضمن العينة الحالية."
    lines = ["Nginx error summary"]
    for group in groups[:5]:
        lines.extend(
            [
                "",
                f"- {group['title']}",
                f"  التكرار: {group['count']}",
                f"  التقييم: {group['evaluation']}",
                f"  آخر ظهور: {group.get('last_seen') or 'غير متاح'}",
                f"  أهم IPs: {', '.join(group.get('ips', [])) or 'غير متاح'}",
                f"  المسارات: {', '.join(group.get('paths', [])) or 'غير متاح'}",
                f"  الشرح: {group['explanation']}",
                f"  الإجراء المقترح: {group['suggested_action']}",
            ]
        )
    return "\n".join(lines)
