import unittest

from matrix_scanner import db
from matrix_scanner.reports.formatter import full_report
from matrix_scanner.telegram_bot import handle_update
from matrix_scanner.tool_registry import ToolSpec
from matrix_scanner.tools.report import generate_report


SAMPLE_SCAN = {
    "system": {
        "cpu_percent": 9.09,
        "ram": {"used_percent": 45.1},
        "disk": {"used_percent": 7.31},
        "load_average": [0.0, 0.0, 0.0],
        "swap": {"used_percent": 0},
        "uptime_seconds": 216 * 86400,
    },
    "services": {
        "service-1": {"status": "active", "ok": True},
        "service-2": {"status": "inactive", "ok": False},
        "unconfigured-service": {"status": "active", "ok": True},
    },
}


class ReportToolTests(unittest.TestCase):
    def test_report_displays_services_as_table(self):
        text = full_report(SAMPLE_SCAN, [], {"services": ["service-1", "service-2"]})

        self.assertIn("Services", text)
        self.assertIn("| Service | Status | Evaluation |", text)
        self.assertIn("| service-1 | running | يعمل |", text)
        self.assertIn("| service-2 | inactive | تحذير |", text)
        self.assertNotIn("Services: service-1", text)

    def test_report_does_not_show_unconfigured_services(self):
        text = full_report(SAMPLE_SCAN, [], {"services": ["service-1"]})

        self.assertIn("| service-1 | running | يعمل |", text)
        self.assertNotIn("unconfigured-service", text)
        self.assertNotIn("service-2", text)

    def test_report_handles_empty_services(self):
        text = full_report(SAMPLE_SCAN, [], {"services": []})

        self.assertIn("No services configured.", text)

    def test_report_displays_alerts_when_present(self):
        alerts = [
            {
                "severity": "warning",
                "title": "CPU مرتفع",
                "evidence": {"cpu_percent": 91},
                "probable_cause": "ضغط على المعالج",
                "suggested_action": "راجع العمليات الأعلى استهلاكًا.",
            }
        ]

        text = full_report(SAMPLE_SCAN, alerts, {"services": ["service-1"]})

        self.assertIn("[warning] CPU مرتفع", text)
        self.assertIn("الدليل: {\"cpu_percent\": 91}", text)
        self.assertIn("السبب المرجح: ضغط على المعالج", text)
        self.assertIn("الإجراء المقترح: راجع العمليات الأعلى استهلاكًا.", text)

    def test_report_displays_no_alerts_message(self):
        text = full_report(SAMPLE_SCAN, [], {"services": ["service-1"]})

        self.assertIn("- لا توجد مشاكل حسب القواعد الحالية.", text)

    def test_report_does_not_say_no_issues_when_incident_notes_exist(self):
        scan = dict(SAMPLE_SCAN)
        scan["incident"] = {"apache_5xx": {"rows": [{"status": "500", "endpoint": "/", "count": 1, "latest_timestamp": "2022-01-01 00:00:00 UTC"}]}}

        text = full_report(scan, [], {"services": ["service-1"]})

        self.assertIn("توجد ملاحظات للمراقبة", text)
        self.assertNotIn("لا توجد مشاكل حسب القواعد الحالية", text)

    def test_generate_report_uses_configured_services(self):
        result = generate_report({"config": {"services": ["service-1"], "thresholds": {}}, "scan": SAMPLE_SCAN})

        self.assertIn("| service-1 | running | يعمل |", result["report_text"])
        self.assertNotIn("unconfigured-service", result["report_text"])
        self.assertNotIn("incident", SAMPLE_SCAN)

    def test_report_command_in_telegram_uses_structured_format(self):
        conn = db.connect(":memory:")
        sent = []
        registry = {
            "generate_report": ToolSpec(
                "generate_report",
                "Report",
                "Report",
                lambda context: generate_report(context | {"scan": SAMPLE_SCAN}),
                "generate_report",
                type="diagnostic",
                output_type="report",
            )
        }
        config = {
            "services": ["service-1"],
            "thresholds": {},
            "telegram": {"allowed_user_ids": [123], "allowed_chat_ids": []},
        }
        update = {"message": {"text": "/report", "from": {"id": 123}, "chat": {"id": 456}}}

        result = handle_update(
            conn=conn,
            registry=registry,
            config=config,
            token="token",
            update=update,
            send_func=lambda token, chat_id, text: sent.append(text),
        )

        self.assertEqual(result["status"], "handled")
        self.assertIn("تقرير Matrix Scanner", sent[0])
        self.assertIn("Services", sent[0])
        self.assertIn("✅ service-1: running", sent[0])
        self.assertNotIn("| Service | Status | Evaluation |", sent[0])


if __name__ == "__main__":
    unittest.main()
