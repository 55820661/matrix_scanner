import unittest
from datetime import datetime, timezone

from matrix_scanner.alerts.incident_rules import evaluate_incident_alerts
from matrix_scanner.alerts.rules import evaluate_alerts


class AlertTests(unittest.TestCase):
    def test_evaluate_alerts_detects_thresholds(self):
        scan = {
            "system": {
                "cpu_percent": 91,
                "ram": {"used_percent": 50},
                "disk": {"used_percent": 95},
            },
            "services": {"nginx": {"status": "failed"}},
            "laravel": {"log": {"error_count": 0}},
        }

        alerts = evaluate_alerts(scan, {"cpu_percent": 85, "disk_percent": 90})
        keys = {alert["alert_key"] for alert in alerts}

        self.assertIn("system.cpu.high", keys)
        self.assertIn("system.disk.high", keys)
        self.assertIn("service.nginx.down", keys)

    def test_incident_alerts_skip_old_apache_5xx(self):
        scan = {"incident": {"apache_5xx": {"rows": [{"status": "500", "endpoint": "/", "domain": "example.com", "count": 3, "recent_1h_count": 0, "recent_24h_count": 0, "latest_timestamp": "2022-01-01 00:00:00 UTC"}]}}}

        alerts = evaluate_incident_alerts(scan, recent_minutes=60, now=datetime(2026, 5, 25, 12, tzinfo=timezone.utc))

        self.assertEqual(alerts, [])

    def test_incident_alerts_skip_old_sql_deadlock(self):
        scan = {"incident": {"laravel_exceptions": {"groups": [{"type": "sql_deadlock", "title": "SQL deadlock", "count": 1, "recent_1h_count": 0, "latest_timestamp": "2026-05-24 10:00:00"}]}}}

        alerts = evaluate_incident_alerts(scan, recent_minutes=60, now=datetime(2026, 5, 25, 12, tzinfo=timezone.utc))

        self.assertEqual(alerts, [])

    def test_incident_alerts_send_when_recent_count_exists(self):
        scan = {"incident": {"apache_5xx": {"rows": [{"status": "500", "endpoint": "/", "domain": "example.com", "count": 3, "recent_1h_count": 1, "latest_timestamp": "2022-01-01 00:00:00 UTC"}]}}}

        alerts = evaluate_incident_alerts(scan, recent_minutes=60, now=datetime(2026, 5, 25, 12, tzinfo=timezone.utc))

        self.assertEqual(alerts[0]["alert_key"], "incident.apache.5xx.500.example.com./")


if __name__ == "__main__":
    unittest.main()
