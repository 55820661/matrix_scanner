from __future__ import annotations

from datetime import datetime, timedelta, timezone


def filter_alerts_for_cooldown(conn, alerts: list[dict], cooldown_minutes: int = 360) -> list[dict]:
    if not alerts:
        return []
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=cooldown_minutes)
    allowed = []
    for alert in alerts:
        row = conn.execute(
            """
            SELECT created_at FROM alerts
            WHERE alert_key = ? AND created_at >= ?
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (alert["alert_key"], cutoff.isoformat()),
        ).fetchone()
        if row is None:
            allowed.append(alert)
    return allowed
