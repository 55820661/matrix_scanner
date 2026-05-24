import unittest

from matrix_scanner import db
from matrix_scanner.alerts.cooldown import filter_alerts_for_cooldown


class CooldownTests(unittest.TestCase):
    def test_filter_alerts_suppresses_existing_recent_alert(self):
        conn = db.connect(":memory:")
        alert = {"alert_key": "system.disk.high", "severity": "critical", "title": "Disk", "evidence": {}}
        db.insert_alerts(conn, 1, [alert])

        filtered = filter_alerts_for_cooldown(conn, [alert], cooldown_minutes=360)

        self.assertEqual(filtered, [])


if __name__ == "__main__":
    unittest.main()
