from __future__ import annotations

import json
from typing import Any

from matrix_scanner.reports.performance import build_server_performance, format_performance_table, format_performance_telegram


def status_summary(scan: dict[str, Any]) -> str:
    system = scan.get("system", {})
    services = scan.get("services", {})
    cpu = _fmt(system.get("cpu_percent"))
    ram = _fmt(system.get("ram", {}).get("used_percent"))
    disk = _fmt(system.get("disk", {}).get("used_percent"))
    service_bits = ", ".join(f"{name}: {value.get('status', 'unknown')}" for name, value in services.items()) or "لا توجد خدمات configured"
    return "\n".join([
        "الحالة العامة: متاحة للفحص",
        f"CPU: {cpu}",
        f"RAM: {ram}",
        f"Disk: {disk}",
        f"Services: {service_bits}",
    ])


def full_report(scan: dict[str, Any], alerts: list[dict[str, Any]] | None = None, config: dict[str, Any] | None = None) -> str:
    alerts = alerts or []
    performance = build_server_performance(scan, config or {})
    performance_text = format_performance_table(
        performance["rows"],
        performance["service_rows"],
        performance["summary"],
        include_summary=False,
    )
    lines = [
        "تقرير Matrix Scanner",
        "",
        f"الحالة العامة: {_overall_status(performance, alerts)}",
        "",
        performance_text,
        _incident_sections(scan),
        "",
        "المشاكل المكتشفة:",
    ]
    if not alerts:
        lines.append("- لا توجد مشاكل حسب القواعد الحالية.")
    for alert in alerts:
        lines.extend([
            f"- [{alert['severity']}] {alert['title']}",
            f"  الدليل: {_short_evidence(alert.get('evidence', {}))}",
            f"  السبب المرجح: {alert.get('probable_cause', '-')}",
            f"  الإجراء المقترح: {alert.get('suggested_action', '-')}",
        ])
    lines.extend(["", "الخلاصة:", performance["summary"]])
    return "\n".join(lines)


def telegram_report(scan: dict[str, Any], alerts: list[dict[str, Any]] | None = None, config: dict[str, Any] | None = None) -> str:
    alerts = alerts or []
    performance = build_server_performance(scan, config or {})
    lines = [
        "تقرير Matrix Scanner",
        "",
        f"الحالة العامة: {_overall_status(performance, alerts)}",
        "",
        format_performance_telegram(performance["rows"], performance["service_rows"], performance["summary"]),
        _incident_sections(scan),
        "",
        "المشاكل المكتشفة:",
    ]
    if not alerts:
        lines.append("- لا توجد مشاكل حسب القواعد الحالية.")
    for alert in alerts:
        lines.extend([
            f"- [{alert['severity']}] {alert['title']}",
            f"  الدليل: {_short_evidence(alert.get('evidence', {}))}",
            f"  السبب المرجح: {alert.get('probable_cause', '-')}",
            f"  الإجراء المقترح: {alert.get('suggested_action', '-')}",
        ])
    lines.extend(["", "الخلاصة:", performance["summary"]])
    return "\n".join(lines)


def _incident_sections(scan: dict[str, Any]) -> str:
    incident = scan.get("incident", {})
    if not incident:
        return ""
    lines: list[str] = []
    sections = [
        ("Apache Errors", _format_rows(incident.get("apache_errors", {}).get("groups", []), ["title", "count", "latest_timestamp", "recent_1h_count", "recent_24h_count", "evaluation"])),
        ("Apache 5xx", _format_rows(incident.get("apache_5xx", {}).get("rows", []), ["status", "endpoint", "domain", "count", "latest_timestamp", "recent_1h_count", "recent_24h_count", "evaluation"])),
        ("Laravel Log Health", _format_rows(incident.get("laravel_log_health", {}).get("rows", []), ["path", "log_count", "total_size_bytes", "uses_daily_logs"])),
        ("Laravel Exceptions", _format_rows(incident.get("laravel_exceptions", {}).get("groups", []), ["title", "count", "latest_timestamp"])),
        ("Queue Workers", _format_rows(incident.get("queue_workers", {}).get("groups", []), ["path", "queue_connection", "count", "users"])),
        ("Supervisor", _format_rows(incident.get("supervisor", {}).get("programs", []) or incident.get("supervisor", {}).get("configs", []), ["program", "status", "numprocs"])),
    ]
    for title, body in sections:
        lines.extend(["", title, body or "- No findings in the current sample."])
    warnings = incident.get("queue_workers", {}).get("warnings", [])
    cron = incident.get("suspicious_cron", {}).get("findings", [])
    files = incident.get("suspicious_files", {}).get("findings", [])
    lines.extend(["", "Security/Cron"])
    if not warnings and not cron and not files:
        lines.append("- No suspicious cron, file, or queue findings in the current sample.")
    for warning in warnings[:5]:
        lines.append(f"- queue warning: {warning}")
    if cron:
        lines.append(f"- suspicious cron findings: {len(cron)}")
    if files:
        lines.append(f"- suspicious file findings: {len(files)}")
    return "\n".join(lines)


def _format_rows(rows: list[dict[str, Any]], keys: list[str]) -> str:
    lines = []
    for row in rows[:5]:
        lines.append("- " + ", ".join(f"{key}={row.get(key, '-')}" for key in keys))
    return "\n".join(lines)


def _fmt(value: Any) -> str:
    if value is None:
        return "غير متاح"
    return f"{value}%"


def _overall_status(performance: dict[str, Any], alerts: list[dict[str, Any]]) -> str:
    if any(alert.get("severity") == "critical" for alert in alerts):
        return "حرجة"
    if alerts:
        return "تحتاج متابعة"

    metric_statuses = {row["status"] for row in performance["rows"]}
    service_evaluations = {row["evaluation"] for row in performance["service_rows"]}
    if "حرج" in metric_statuses:
        return "حرجة"
    if "تحذير" in metric_statuses or "تحذير" in service_evaluations:
        return "تحتاج متابعة"
    return "جيدة"


def _short_evidence(evidence: Any) -> str:
    if not evidence:
        return "-"
    text = json.dumps(evidence, ensure_ascii=False, default=str)
    if len(text) <= 240:
        return text
    return text[:237] + "..."
