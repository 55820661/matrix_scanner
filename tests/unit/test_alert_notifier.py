import unittest

from matrix_scanner.alerts.notifier import format_alert_message, notify_alerts


ALERT = {
    "alert_key": "system.disk.high",
    "severity": "critical",
    "title": "مساحة القرص منخفضة",
    "evidence": {"disk_percent": 91.2},
    "probable_cause": "امتلاء ملفات logs أو uploads",
    "suggested_action": "راجع أكبر المسارات قبل حذف أي شيء.",
}


class AlertNotifierTests(unittest.TestCase):
    def test_notify_alerts_sends_when_telegram_enabled(self):
        sent = []
        config = {"alerts_enabled": True, "telegram_enabled": True, "telegram": {"default_chat_id": 456}}

        result = notify_alerts([ALERT], config, "token", send_func=lambda token, chat_id, text: sent.append((token, chat_id, text)))

        self.assertEqual(result, {"sent": 1, "warnings": []})
        self.assertEqual(sent[0][0], "token")
        self.assertEqual(sent[0][1], 456)
        self.assertIn("Matrix Scanner Alert", sent[0][2])
        self.assertIn("disk_percent = 91.2", sent[0][2])

    def test_notify_alerts_skips_when_telegram_disabled(self):
        sent = []
        config = {"alerts_enabled": True, "telegram_enabled": False, "telegram": {"default_chat_id": 456}}

        result = notify_alerts([ALERT], config, "token", send_func=lambda *args: sent.append(args))

        self.assertEqual(result["sent"], 0)
        self.assertEqual(sent, [])

    def test_notify_alerts_skips_when_alerts_disabled(self):
        sent = []
        config = {"alerts_enabled": False, "telegram_enabled": True, "telegram": {"default_chat_id": 456}}

        result = notify_alerts([ALERT], config, "token", send_func=lambda *args: sent.append(args))

        self.assertEqual(result["sent"], 0)
        self.assertEqual(sent, [])

    def test_notify_alerts_warns_without_token_without_failing(self):
        config = {"alerts_enabled": True, "telegram_enabled": True, "telegram": {"default_chat_id": 456}}

        result = notify_alerts([ALERT], config, None, send_func=lambda *args: self.fail("send should not be called"))

        self.assertEqual(result["sent"], 0)
        self.assertIn("TELEGRAM_BOT_TOKEN is not set", result["warnings"][0])

    def test_alert_message_does_not_dump_long_raw_logs(self):
        alert = ALERT | {
            "evidence": {
                "disk_percent": 91.2,
                "recent_errors": ["raw nginx log line " * 50],
                "examples": ["open() /.env failed " * 50],
            }
        }

        text = format_alert_message(alert)

        self.assertIn("disk_percent = 91.2", text)
        self.assertNotIn("raw nginx log line", text)
        self.assertNotIn("open() /.env failed", text)


if __name__ == "__main__":
    unittest.main()
