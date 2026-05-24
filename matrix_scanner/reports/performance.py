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
    rows = [
        _metric_row("CPU", _percent_value(scan.get("system", {}).get("cpu_percent")), _usage_status(scan.get("system", {}).get("cpu_percent"), thresholds["cpu_watch_percent"], thresholds["cpu_percent"], "جيد")),
        _metric_row("RAM", _percent_value(scan.get("system", {}).get("ram", {}).get("used_percent")), _usage_status(scan.get("system", {}).get("ram", {}).get("used_percent"), thresholds["ram_watch_percent"], thresholds["ram_percent"], "طبيعي")),
        _metric_row("Disk", _percent_value(scan.get("system", {}).get("disk", {}).get("used_percent")), _disk_status(scan.get("system", {}).get("disk", {}).get("used_percent"), thresholds["disk_watch_percent"], thresholds["disk_percent"])),
        _metric_row("Load", _load_value(scan.get("system", {}).get("load_average")), "جيد" if scan.get("system", {}).get("load_average") else "غير متاح"),
        _metric_row("Swap", _percent_value(scan.get("system", {}).get("swap", {}).get("used_percent")), _usage_status(scan.get("system", {}).get("swap", {}).get("used_percent"), 50, 80, "جيد")),
        _metric_row("Uptime", _uptime_value(scan.get("system", {}).get("uptime_seconds")), "مستقر" if scan.get("system", {}).get("uptime_seconds") else "غير متاح"),
    ]
    services = scan.get("services", {})
    rows.extend(
        [
            _service_row("Nginx", services.get("nginx")),
            _service_row("PHP-FPM", _first_service(services, ("php-fpm", "php8.3-fpm", "php8.2-fpm", "php8.1-fpm"))),
            _service_row("MySQL", _first_service(services, ("mysql", "mariadb"))),
        ]
    )
    summary = _summary(rows)
    return {"rows": rows, "summary": summary, "summary_text": format_performance_table(rows, summary)}


def format_performance_table(rows: list[dict[str, str]], summary: str) -> str:
    lines = [
        "Server Performance",
        "",
        "| Metric | Value | Status |",
        "| --- | ---: | --- |",
    ]
    lines.extend(f"| {row['metric']} | {row['value']} | {row['status']} |" for row in rows)
    lines.extend(["", f"الخلاصة: {summary}"])
    return "\n".join(lines)


def _metric_row(metric: str, value: str, status: str) -> dict[str, str]:
    return {"metric": metric, "value": value, "status": status}


def _service_row(metric: str, service: dict[str, Any] | None) -> dict[str, str]:
    if not service:
        return _metric_row(metric, "غير متاح", "لم يتم الفحص")
    status = service.get("status", "unknown")
    if status in {"active", "running"} or service.get("ok") is True:
        return _metric_row(metric, "running", "يعمل")
    if status == "unavailable":
        return _metric_row(metric, "غير متاح", "لم يتم الفحص")
    return _metric_row(metric, str(status), "تحذير")


def _first_service(services: dict[str, dict], names: tuple[str, ...]) -> dict[str, Any] | None:
    for name in names:
        if name in services:
            return services[name]
    return None


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


def _summary(rows: list[dict[str, str]]) -> str:
    statuses = {row["status"] for row in rows}
    if "حرج" in statuses:
        return "توجد مشكلة حرجة تحتاج متابعة فورية."
    if "تحذير" in statuses:
        return "حالة السيرفر تحتاج متابعة، ولا توجد مشكلة حرجة حاليًا."
    if "مراقبة" in statuses:
        return "حالة السيرفر جيدة إجمالًا مع بعض البنود تحت المراقبة."
    if "غير متاح" in statuses or "لم يتم الفحص" in statuses:
        return "الفحص جزئي بسبب بنود غير متاحة، ولا توجد مشكلة حرجة ظاهرة حاليًا."
    return "حالة السيرفر جيدة، ولا توجد مشكلة حرجة حاليًا."
