from __future__ import annotations

from matrix_scanner.scanners.services import scan_services


def get_services(context: dict) -> dict:
    services = scan_services(context["config"].get("services", []))
    summary = "\n".join(f"{name}: {result.get('status', 'unknown')}" for name, result in services.items())
    return {"services": services, "summary_text": summary or "لا توجد خدمات configured"}
