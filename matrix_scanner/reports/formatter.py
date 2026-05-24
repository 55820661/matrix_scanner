from __future__ import annotations

from typing import Any


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


def full_report(scan: dict[str, Any], alerts: list[dict[str, Any]] | None = None) -> str:
    alerts = alerts or []
    lines = ["تقرير Matrix Scanner", "", status_summary(scan), "", "المشاكل المكتشفة:"]
    if not alerts:
        lines.append("- لا توجد مشاكل حسب القواعد الحالية.")
    for alert in alerts:
        lines.extend([
            f"- [{alert['severity']}] {alert['title']}",
            f"  السبب المرجح: {alert.get('probable_cause', '-')}",
            f"  الإجراء المقترح: {alert.get('suggested_action', '-')}",
        ])
    return "\n".join(lines)


def _fmt(value: Any) -> str:
    if value is None:
        return "غير متاح"
    return f"{value}%"
