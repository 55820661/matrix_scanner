from __future__ import annotations

from matrix_scanner.reports.performance import build_server_performance
from matrix_scanner.scheduler import collect_scan


def server_performance(context: dict) -> dict:
    scan = context.get("scan") or collect_scan(context["config"])
    performance = build_server_performance(scan, context["config"])
    return {
        "summary_text": performance["summary_text"],
        "rows": performance["rows"],
        "service_rows": performance["service_rows"],
        "summary": performance["summary"],
        "scan": scan,
    }
