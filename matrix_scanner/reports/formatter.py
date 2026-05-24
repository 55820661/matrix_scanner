from __future__ import annotations

import json
from typing import Any

from matrix_scanner.reports.performance import build_server_performance, format_performance_table


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
