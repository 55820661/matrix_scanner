import unittest

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


if __name__ == "__main__":
    unittest.main()
