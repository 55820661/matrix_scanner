from __future__ import annotations

from matrix_scanner.alerts.rules import evaluate_alerts
from matrix_scanner.reports.formatter import full_report
from matrix_scanner.scheduler import collect_scan


def generate_report(context: dict) -> dict:
    scan = collect_scan(context["config"])
    alerts = evaluate_alerts(scan, context["config"].get("thresholds", {}))
    return {"report_text": full_report(scan, alerts), "scan": scan, "alerts": alerts}
