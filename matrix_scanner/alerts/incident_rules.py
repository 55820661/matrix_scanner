from __future__ import annotations

from typing import Any


def evaluate_incident_alerts(scan: dict[str, Any]) -> list[dict[str, Any]]:
    incident = scan.get("incident", {})
    alerts: list[dict[str, Any]] = []

    cron_findings = incident.get("suspicious_cron", {}).get("findings", [])
    if cron_findings:
        alerts.append(_alert("incident.cron.suspicious", "critical", "Suspicious cron entries detected", {"count": len(cron_findings), "sample": cron_findings[:2]}, "Cron contains suspicious persistence patterns.", "Review the listed cron entries before changing anything."))

    file_findings = incident.get("suspicious_files", {}).get("findings", [])
    if file_findings:
        alerts.append(_alert("incident.files.suspicious", "warning", "Suspicious hidden files detected", {"count": len(file_findings), "sample": file_findings[:3]}, "Hidden executable or immutable files found in common temporary/system-like paths.", "Inspect ownership, timestamps, and process links before removing anything."))

    for group in incident.get("laravel_exceptions", {}).get("groups", []):
        if group.get("count", 0) > 0:
            alerts.append(_alert(f"incident.laravel.{group.get('type', 'exception')}", "warning", group.get("title", "Laravel exception detected"), {"count": group.get("count"), "latest_timestamp": group.get("latest_timestamp"), "affected_app_paths": group.get("affected_app_paths", {})}, group.get("probable_cause", "Repeated Laravel exception."), group.get("suggested_action", "Review the Laravel log sample.")))

    for row in incident.get("apache_5xx", {}).get("rows", []):
        if row.get("count", 0) > 0:
            alerts.append(_alert(f"incident.apache.5xx.{row.get('status')}.{row.get('domain')}.{row.get('endpoint')}", "warning", "Apache 5xx responses detected", {"status": row.get("status"), "endpoint": row.get("endpoint"), "domain": row.get("domain"), "count": row.get("count"), "latest_timestamp": row.get("latest_timestamp")}, "Application or upstream returned repeated 5xx responses.", "Review the endpoint and matching application logs."))

    for group in incident.get("apache_errors", {}).get("groups", []):
        if group.get("evaluation") in {"تحذير", "critical", "warning"} and group.get("count", 0) > 0:
            alerts.append(_alert(f"incident.apache.error.{group.get('type')}", "warning", group.get("title", "Apache error detected"), {"count": group.get("count"), "last_seen": group.get("last_seen"), "log_files": group.get("log_files", {})}, group.get("explanation", "Apache reported repeated errors."), group.get("suggested_action", "Review Apache error summary.")))

    for warning in incident.get("queue_workers", {}).get("warnings", []):
        alerts.append(_alert(f"incident.queue.{_key_fragment(warning)}", "warning", "Queue worker risk detected", {"warning": warning}, "Queue workers may be over-parallelized or running under the wrong user.", "Review supervisor/cron configuration before changing workers."))

    return alerts


def _alert(key: str, severity: str, title: str, evidence: dict[str, Any], cause: str, action: str) -> dict[str, Any]:
    return {
        "alert_key": key,
        "severity": severity,
        "title": title,
        "evidence": evidence,
        "probable_cause": cause,
        "suggested_action": action,
    }


def _key_fragment(value: str) -> str:
    return "".join(ch if ch.isalnum() else "." for ch in value.lower()).strip(".")[:80] or "warning"
