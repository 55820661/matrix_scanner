from __future__ import annotations

from typing import Any


def evaluate_alerts(scan: dict[str, Any], thresholds: dict[str, Any]) -> list[dict[str, Any]]:
    alerts: list[dict[str, Any]] = []
    system = scan.get("system", {})
    cpu = system.get("cpu_percent")
    if cpu is not None and cpu > thresholds.get("cpu_percent", 85):
        alerts.append(_alert("system.cpu.high", "warning", "CPU مرتفع", {"cpu_percent": cpu}, "ضغط على المعالج", "راجع العمليات الأعلى استهلاكًا."))

    ram = system.get("ram", {}).get("used_percent")
    if ram is not None and ram > thresholds.get("ram_percent", 85):
        alerts.append(_alert("system.ram.high", "warning", "استخدام الذاكرة مرتفع", {"ram_percent": ram}, "ضغط ذاكرة أو تسريب محتمل", "راجع استهلاك عمليات PHP-FPM وMySQL."))

    disk = system.get("disk", {}).get("used_percent")
    if disk is not None and disk > thresholds.get("disk_percent", 90):
        alerts.append(_alert("system.disk.high", "critical", "مساحة القرص منخفضة", {"disk_percent": disk}, "امتلاء ملفات logs أو uploads", "راجع أكبر المسارات قبل حذف أي شيء."))

    for name, result in scan.get("services", {}).items():
        if result.get("status") not in {"active", "unavailable"}:
            alerts.append(_alert(f"service.{name}.down", "critical", f"الخدمة {name} لا تعمل", result, "الخدمة متوقفة أو فشلت", "افحص logs الخدمة قبل أي restart."))

    laravel_errors = scan.get("laravel", {}).get("log", {}).get("error_count")
    if laravel_errors is not None and laravel_errors > thresholds.get("laravel_error_count", 5):
        alerts.append(_alert("laravel.errors.high", "warning", "أخطاء Laravel متكررة", {"error_count": laravel_errors}, "استثناءات متكررة في التطبيق", "راجع آخر أخطاء Laravel وحدد السبب."))

    return alerts


def _alert(key: str, severity: str, title: str, evidence: dict, cause: str, action: str) -> dict:
    return {
        "alert_key": key,
        "severity": severity,
        "title": title,
        "evidence": evidence,
        "probable_cause": cause,
        "suggested_action": action,
    }
