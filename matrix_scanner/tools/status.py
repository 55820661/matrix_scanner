from __future__ import annotations

from matrix_scanner.reports.formatter import status_summary
from matrix_scanner.scheduler import collect_scan


def get_status(context: dict) -> dict:
    scan = collect_scan(context["config"])
    return {"summary_text": status_summary(scan), "scan": scan}
