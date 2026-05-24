from __future__ import annotations

from matrix_scanner.tools.performance import server_performance


def get_status(context: dict) -> dict:
    result = server_performance(context)
    return {
        "summary_text": result["summary_text"],
        "scan": result["scan"],
        "performance_rows": result["rows"],
    }
