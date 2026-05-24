import unittest

from matrix_scanner import db
from matrix_scanner.tool_executor import execute_tool
from matrix_scanner.tool_registry import ToolSpec, build_registry
from matrix_scanner.tools.performance import server_performance


SAMPLE_SCAN = {
    "system": {
        "cpu_percent": 18,
        "ram": {"used_percent": 62},
        "disk": {"used_percent": 71},
        "load_average": [0.85, 0.75, 0.65],
        "swap": {"used_percent": 5},
        "uptime_seconds": 12 * 86400,
    },
    "services": {
        "nginx": {"status": "active", "ok": True},
        "php-fpm": {"status": "active", "ok": True},
        "mysql": {"status": "active", "ok": True},
    },
}


class PerformanceToolTests(unittest.TestCase):
    def test_server_performance_is_registered(self):
        registry = build_registry()

        self.assertIn("server_performance", registry)
        self.assertEqual(registry["server_performance"].type, "read_only")
        self.assertEqual(registry["server_performance"].output_type, "summary")
        self.assertFalse(registry["server_performance"].requires_confirmation)
        self.assertTrue(registry["server_performance"].enabled)

    def test_server_performance_output_contains_core_metrics_and_services(self):
        result = server_performance({"config": {}, "scan": SAMPLE_SCAN})
        text = result["summary_text"]

        for token in ("CPU", "RAM", "Disk", "Load", "Swap", "Uptime", "Nginx", "PHP-FPM", "MySQL"):
            self.assertIn(token, text)
        self.assertIn("الخلاصة:", text)

    def test_server_performance_partial_service_failure_does_not_fail_report(self):
        scan = SAMPLE_SCAN | {"services": {"nginx": {"status": "active", "ok": True}, "mysql": {"status": "unavailable"}}}

        result = server_performance({"config": {}, "scan": scan})
        text = result["summary_text"]

        self.assertIn("| MySQL | غير متاح | لم يتم الفحص |", text)
        self.assertIn("| PHP-FPM | غير متاح | لم يتم الفحص |", text)

    def test_server_performance_syncs_to_sqlite_registry(self):
        conn = db.connect(":memory:")
        db.sync_tools_registry(conn, build_registry())

        row = conn.execute("SELECT type, output_type, requires_confirmation, enabled FROM tools_registry WHERE tool_key = ?", ("server_performance",)).fetchone()

        self.assertEqual(row["type"], "read_only")
        self.assertEqual(row["output_type"], "summary")
        self.assertEqual(row["requires_confirmation"], 0)
        self.assertEqual(row["enabled"], 1)

    def test_truncation_still_applies_through_executor(self):
        conn = db.connect(":memory:")
        spec = ToolSpec(
            "server_performance",
            "Server Performance",
            "Aggregated server performance summary.",
            lambda context: {"summary_text": "x" * 500, "rows": []},
            "server_performance",
            max_output_chars=80,
        )

        result = execute_tool(conn, {"server_performance": spec}, tool_key="server_performance", context={"config": {}}, source="test")

        self.assertTrue(result["output"]["_truncated"])
        self.assertLessEqual(len(result["output"]["summary_text"]), 80)


if __name__ == "__main__":
    unittest.main()
