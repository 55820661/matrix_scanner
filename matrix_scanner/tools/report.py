from __future__ import annotations

from matrix_scanner.alerts.rules import evaluate_alerts
from matrix_scanner.reports.formatter import full_report, telegram_report
from matrix_scanner.scheduler import collect_scan


def generate_report(context: dict) -> dict:
    scan = context.get("scan") or collect_scan(context["config"])
    alerts = evaluate_alerts(_scan_for_configured_services(scan, context["config"].get("services", [])), context["config"].get("thresholds", {}))
    return {
        "report_text": full_report(scan, alerts, context["config"]),
        "telegram_text": telegram_report(scan, alerts, context["config"]),
        "scan": scan,
        "alerts": alerts,
    }


def _scan_for_configured_services(scan: dict, configured_services: list[str]) -> dict:
    filtered = dict(scan)
    filtered["services"] = {
        name: result
        for name, result in scan.get("services", {}).items()
        if name in configured_services
    }
    return filtered
