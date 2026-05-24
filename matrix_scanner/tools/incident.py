from __future__ import annotations

from typing import Any

from matrix_scanner.scanners import incident


def top_processes(context: dict) -> dict:
    result = incident.top_processes()
    return _with_summary("Top Processes", result, _rows(result.get("rows", []), ["pid", "user", "cpu_percent", "ram_percent", "command"]))


def apache_error_summary(context: dict) -> dict:
    apache = context["config"].get("apache", {})
    result = incident.apache_error_summary(apache.get("error_logs"), int(context["config"].get("logs", {}).get("max_lines", 500)))
    return _with_summary("Apache Error Summary", result, _groups(result.get("groups", [])))


def apache_5xx_summary(context: dict) -> dict:
    apache = context["config"].get("apache", {})
    result = incident.apache_5xx_summary(apache.get("access_logs") or apache.get("domlogs"), int(context["config"].get("logs", {}).get("max_lines", 1000)))
    return _with_summary("Apache 5xx Summary", result, _rows(result.get("rows", []), ["status", "endpoint", "count"]))


def laravel_log_health(context: dict) -> dict:
    result = incident.laravel_log_health(context["config"])
    return _with_summary("Laravel Log Health", result, _rows(result.get("rows", []), ["path", "log_count", "total_size_bytes", "largest_size_bytes", "uses_daily_logs"]))


def laravel_env_sanity(context: dict) -> dict:
    result = incident.laravel_env_sanity(context["config"])
    lines = ["Laravel Env Sanity"]
    for row in result.get("rows", []):
        values = ", ".join(f"{key}={value}" for key, value in row.get("values", {}).items())
        lines.append(f"- {row['path']}: {row['evaluation']} ({values or 'no safe env values'})")
        for issue in row.get("issues", []):
            lines.append(f"  - {issue}")
    return {"summary_text": "\n".join(lines), "rows": result.get("rows", []), "evaluation": _evaluation(result.get("rows", []))}


def laravel_exception_summary(context: dict) -> dict:
    result = incident.laravel_exception_summary(context["config"], int(context["config"].get("logs", {}).get("max_lines", 500)))
    return _with_summary("Laravel Exception Summary", result, _exceptions(result.get("groups", [])))


def queue_workers_summary(context: dict) -> dict:
    result = incident.queue_workers_summary()
    body = _rows(result.get("workers", []), ["pid", "user", "path", "queue_connection"])
    if result.get("warnings"):
        body += "\n" + "\n".join(f"- {warning}" for warning in result["warnings"])
    return _with_summary("Queue Workers Summary", result, body)


def supervisor_summary(context: dict) -> dict:
    supervisor = context["config"].get("supervisor", {})
    result = incident.supervisor_summary(supervisor.get("config_paths"))
    body = _rows(result.get("programs", []), ["program", "status"]) or _rows(result.get("configs", []), ["program", "numprocs", "command"])
    return _with_summary("Supervisor Summary", result, body or "Supervisor غير متاح أو لا توجد برامج مكتشفة.")


def suspicious_cron_scan(context: dict) -> dict:
    security = context["config"].get("security_scan", {})
    result = incident.suspicious_cron_scan(security.get("cron_paths"))
    return _with_summary("Suspicious Cron Scan", result, _rows(result.get("findings", []), ["path", "reasons", "evaluation"]))


def suspicious_files_scan(context: dict) -> dict:
    security = context["config"].get("security_scan", {})
    result = incident.suspicious_files_scan(security.get("file_patterns"))
    return _with_summary("Suspicious Files Scan", result, _rows(result.get("findings", []), ["path", "executable", "immutable", "daemon_like_name"]))


def _with_summary(title: str, result: dict[str, Any], body: str) -> dict:
    summary = title if not body else f"{title}\n\n{body}"
    return {"summary_text": summary, "telegram_text": summary, "sections": result, "evaluation": result.get("evaluation", "طبيعي"), "suggested_action": result.get("suggested_action", "-")}


def _rows(rows: list[dict[str, Any]], columns: list[str]) -> str:
    if not rows:
        return "لا توجد نتائج ضمن العينة الحالية."
    lines = []
    for row in rows[:10]:
        lines.append("- " + ", ".join(f"{column}: {row.get(column, '-')}" for column in columns))
    return "\n".join(lines)


def _groups(groups: list[dict[str, Any]]) -> str:
    if not groups:
        return "لا توجد أخطاء مصنفة ضمن العينة الحالية."
    lines = []
    for group in groups[:8]:
        lines.extend([
            f"- {group['title']}",
            f"  count: {group['count']}, evaluation: {group['evaluation']}",
            f"  explanation: {group['explanation']}",
            f"  suggested_action: {group['suggested_action']}",
        ])
    return "\n".join(lines)


def _exceptions(groups: list[dict[str, Any]]) -> str:
    if not groups:
        return "لا توجد Laravel exceptions مصنفة ضمن العينة الحالية."
    lines = []
    for group in groups[:8]:
        lines.extend([
            f"- {group['title']}",
            f"  count: {group['count']}, latest: {group.get('latest_timestamp') or '-'}",
            f"  probable_cause: {group['probable_cause']}",
            f"  suggested_action: {group['suggested_action']}",
        ])
    return "\n".join(lines)


def _evaluation(rows: list[dict[str, Any]]) -> str:
    return "تحذير" if any(row.get("evaluation") == "تحذير" for row in rows) else "جيد"
