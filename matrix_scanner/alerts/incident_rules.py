from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any


def evaluate_incident_alerts(scan: dict[str, Any], *, recent_minutes: int = 60, now: datetime | None = None) -> list[dict[str, Any]]:
    now = now or datetime.now(timezone.utc)
    incident = scan.get("incident", {})
    alerts: list[dict[str, Any]] = []

    cron_findings = incident.get("suspicious_cron", {}).get("findings", [])
    if cron_findings:
        alerts.append(_alert("incident.cron.suspicious", "critical", "Suspicious cron entries detected", {"count": len(cron_findings), "sample": cron_findings[:2]}, "Cron contains suspicious persistence patterns.", "Review the listed cron entries before changing anything."))

    file_findings = incident.get("suspicious_files", {}).get("findings", [])
    if file_findings:
        alerts.append(_alert("incident.files.suspicious", "warning", "Suspicious hidden files detected", {"count": len(file_findings), "sample": file_findings[:3]}, "Hidden executable or immutable files found in common temporary/system-like paths.", "Inspect ownership, timestamps, and process links before removing anything."))

    for group in incident.get("laravel_exceptions", {}).get("groups", []):
        if group.get("count", 0) > 0 and _is_recent(group, recent_minutes, now):
            alerts.append(_alert(f"incident.laravel.{group.get('type', 'exception')}", "warning", group.get("title", "Laravel exception detected"), {"count": group.get("count"), "latest_timestamp": group.get("latest_timestamp"), "affected_app_paths": group.get("affected_app_paths", {})}, group.get("probable_cause", "Repeated Laravel exception."), group.get("suggested_action", "Review the Laravel log sample.")))

    for row in incident.get("apache_5xx", {}).get("rows", []):
        if row.get("count", 0) > 0 and _is_recent(row, recent_minutes, now):
            alerts.append(_alert(f"incident.apache.5xx.{row.get('status')}.{row.get('domain')}.{row.get('endpoint')}", "warning", "Apache 5xx responses detected", {"status": row.get("status"), "endpoint": row.get("endpoint"), "domain": row.get("domain"), "count": row.get("count"), "latest_timestamp": row.get("latest_timestamp")}, "Application or upstream returned repeated 5xx responses.", "Review the endpoint and matching application logs."))

    for group in incident.get("apache_errors", {}).get("groups", []):
        if group.get("evaluation") in {"تحذير", "warning", "critical"} and group.get("count", 0) > 0 and _is_recent(group, recent_minutes, now):
            alerts.append(_alert(f"incident.apache.error.{group.get('type')}", "warning", group.get("title", "Apache error detected"), {"count": group.get("count"), "latest_timestamp": group.get("latest_timestamp"), "log_files": group.get("log_files", {})}, group.get("explanation", "Apache reported repeated errors."), group.get("suggested_action", "Review Apache error summary.")))

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


def _is_recent(item: dict[str, Any], recent_minutes: int, now: datetime) -> bool:
    if int(item.get("recent_1h_count") or 0) > 0:
        return True
    latest = _parse_timestamp(str(item.get("latest_timestamp") or item.get("last_seen") or ""))
    if latest is None:
        return False
    return latest >= now - timedelta(minutes=recent_minutes)


def _parse_timestamp(value: str) -> datetime | None:
    value = value.strip()
    if not value or value == "-":
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S UTC", "%Y-%m-%d %H:%M:%S"):
        try:
            parsed = datetime.strptime(value, fmt)
        except ValueError:
            continue
        return parsed.replace(tzinfo=timezone.utc)
    return None


def _key_fragment(value: str) -> str:
    return "".join(ch if ch.isalnum() else "." for ch in value.lower()).strip(".")[:80] or "warning"
