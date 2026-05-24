from __future__ import annotations

from typing import Any


DEFAULT_THRESHOLDS = {
    "cpu_percent": 85,
    "cpu_watch_percent": 70,
    "ram_percent": 90,
    "ram_watch_percent": 75,
    "disk_percent": 90,
    "disk_watch_percent": 80,
}


def build_server_performance(scan: dict[str, Any], config: dict[str, Any] | None = None) -> dict[str, Any]:
    config = config or {}
    thresholds = DEFAULT_THRESHOLDS | config.get("thresholds", {})
    metric_rows = [
        _metric_row("CPU", _percent_value(scan.get("system", {}).get("cpu_percent")), _usage_status(scan.get("system", {}).get("cpu_percent"), thresholds["cpu_watch_percent"], thresholds["cpu_percent"], "جيد")),
        _metric_row("RAM", _percent_value(scan.get("system", {}).get("ram", {}).get("used_percent")), _usage_status(scan.get("system", {}).get("ram", {}).get("used_percent"), thresholds["ram_watch_percent"], thresholds["ram_percent"], "طبيعي")),
        _metric_row("Disk", _percent_value(scan.get("system", {}).get("disk", {}).get("used_percent")), _disk_status(scan.get("system", {}).get("disk", {}).get("used_percent"), thresholds["disk_watch_percent"], thresholds["disk_percent"])),
        _metric_row("Load", _load_value(scan.get("system", {}).get("load_average")), "جيد" if scan.get("system", {}).get("load_average") else "غير متاح"),
        _metric_row("Swap", _percent_value(scan.get("system", {}).get("swap", {}).get("used_percent")), _usage_status(scan.get("system", {}).get("swap", {}).get("used_percent"), 50, 80, "جيد")),
        _metric_row("Uptime", _uptime_value(scan.get("system", {}).get("uptime_seconds")), "مستقر" if scan.get("system", {}).get("uptime_seconds") else "غير متاح"),
    ]
    service_rows = build_service_rows(scan.get("services", {}), config.get("services", []))
    summary = _summary(metric_rows, service_rows, bool(config.get("services", [])))
    return {"rows": metric_rows, "service_rows": service_rows, "summary": summary, "summary_text": format_performance_table(metric_rows, service_rows, summary)}


def build_service_rows(scanned_services: dict[str, Any], configured_services: list[str]) -> list[dict[str, str]]:
    rows = []
    for service_name in configured_services:
        rows.append(_service_row(service_name, scanned_services.get(service_name)))
    return rows


def format_performance_table(metric_rows: list[dict[str, str]], service_rows: list[dict[str, str]], summary: str) -> str:
    lines = [
        "Server Performance",
        "",
        "| Metric | Value | Status |",
        "| --- | ---: | --- |",
    ]
    lines.extend(f"| {row['metric']} | {row['value']} | {row['status']} |" for row in metric_rows)
    lines.extend(["", "Services", ""])
    if service_rows:
        lines.extend(["| Service | Status | Evaluation |", "| --- | --- | --- |"])
        lines.extend(f"| {row['service']} | {row['status']} | {row['evaluation']} |" for row in service_rows)
    else:
        lines.append("No services configured.")
    lines.extend(["", f"الخلاصة: {summary}"])
    return "\n".join(lines)


def _metric_row(metric: str, value: str, status: str) -> dict[str, str]:
    return {"metric": metric, "value": value, "status": status}


def _service_row(service_name: str, service: dict[str, Any] | None) -> dict[str, str]:
    if not service:
        return {"service": service_name, "status": "unknown", "evaluation": "لم يتم الفحص"}
    status = service.get("status", "unknown")
    if status in {"active", "running"} or service.get("ok") is True:
        return {"service": service_name, "status": "running", "evaluation": "يعمل"}
    if status == "unavailable":
        return {"service": service_name, "status": "unknown", "evaluation": "لم يتم الفحص"}
    return {"service": service_name, "status": str(status), "evaluation": "تحذير"}


def _percent_value(value: Any) -> str:
    if value is None:
        return "غير متاح"
    return f"{round(float(value), 2):g}%"


def _load_value(value: Any) -> str:
    if isinstance(value, (list, tuple)) and value:
        return f"{float(value[0]):.2f}"
    if value is None:
        return "غير متاح"
    return str(value)


def _uptime_value(seconds: Any) -> str:
    if seconds is None:
        return "غير متاح"
    days = int(float(seconds) // 86400)
    if days:
        return f"{days} days"
    hours = int(float(seconds) // 3600)
    return f"{hours} hours"


def _usage_status(value: Any, watch: float, warn: float, good_label: str) -> str:
    if value is None:
        return "غير متاح"
    value = float(value)
    if value < watch:
        return good_label
    if value <= warn:
        return "مراقبة"
    return "تحذير"


def _disk_status(value: Any, watch: float, critical: float) -> str:
    if value is None:
        return "غير متاح"
    value = float(value)
    if value < watch:
        return "جيد"
    if value <= critical:
        return "مراقبة"
    return "حرج"


def _summary(metric_rows: list[dict[str, str]], service_rows: list[dict[str, str]], has_configured_services: bool) -> str:
    metric_statuses = {row["status"] for row in metric_rows}
    service_evaluations = {row["evaluation"] for row in service_rows}
    if not has_configured_services:
        return "لا توجد خدمات محددة للفحص، وتم عرض مؤشرات السيرفر فقط."
    if "تحذير" in service_evaluations:
        return "توجد خدمة أو أكثر لا تعمل وتحتاج مراجعة."
    if "حرج" in metric_statuses:
        return "توجد مشكلة حرجة تحتاج متابعة فورية."
    if "تحذير" in metric_statuses:
        return "حالة السيرفر تحتاج متابعة، ولا توجد مشكلة حرجة حاليًا."
    if "لم يتم الفحص" in service_evaluations:
        return "حالة السيرفر جزئية لأن خدمة أو أكثر لم يتم فحصها."
    if "مراقبة" in metric_statuses:
        return "حالة السيرفر جيدة إجمالًا مع بعض المؤشرات تحت المراقبة، وجميع الخدمات المختارة تعمل حاليًا."
    if "غير متاح" in metric_statuses:
        return "الفحص جزئي بسبب بنود غير متاحة، ولا توجد مشكلة حرجة ظاهرة حاليًا."
    return "حالة السيرفر جيدة، وجميع الخدمات المختارة تعمل حاليًا."
