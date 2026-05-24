import unittest

from matrix_scanner import db
from matrix_scanner.config import AppConfig
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
        result = server_performance({"config": {"services": ["nginx", "php-fpm", "mysql"]}, "scan": SAMPLE_SCAN})
        text = result["summary_text"]

        for token in ("CPU", "RAM", "Disk", "Load", "Swap", "Uptime", "nginx", "php-fpm", "mysql"):
            self.assertIn(token, text)
        self.assertIn("الخلاصة:", text)

    def test_server_performance_partial_service_failure_does_not_fail_report(self):
        scan = SAMPLE_SCAN | {"services": {"nginx": {"status": "active", "ok": True}, "mysql": {"status": "unavailable"}}}

        result = server_performance({"config": {"services": ["nginx", "mysql"]}, "scan": scan})
        text = result["summary_text"]

        self.assertIn("| mysql | unknown | لم يتم الفحص |", text)
        self.assertNotIn("php-fpm", text)

    def test_server_performance_displays_all_configured_services(self):
        scan = SAMPLE_SCAN | {"services": {"service-1": {"status": "active", "ok": True}, "service-2": {"status": "active", "ok": True}, "service-3": {"status": "inactive"}}}

        result = server_performance({"config": {"services": ["service-1", "service-2", "service-3"]}, "scan": scan})
        text = result["summary_text"]

        self.assertIn("| service-1 | running | يعمل |", text)
        self.assertIn("| service-2 | running | يعمل |", text)
        self.assertIn("| service-3 | inactive | تحذير |", text)

    def test_server_performance_empty_services_does_not_fail(self):
        result = server_performance({"config": {"services": []}, "scan": SAMPLE_SCAN})

        self.assertIn("No services configured.", result["summary_text"])
        self.assertIn("لا توجد خدمات محددة للفحص", result["summary"])

    def test_server_performance_does_not_show_unconfigured_services(self):
        result = server_performance({"config": {"services": ["nginx"]}, "scan": SAMPLE_SCAN})
        text = result["summary_text"]

        self.assertIn("| nginx | running | يعمل |", text)
        self.assertNotIn("php-fpm", text)
        self.assertNotIn("mysql", text)

    def test_server_performance_syncs_to_sqlite_registry(self):
        conn = db.connect(":memory:")
        self.addCleanup(conn.close)
        db.sync_tools_registry(conn, build_registry())

        row = conn.execute("SELECT type, output_type, requires_confirmation, enabled FROM tools_registry WHERE tool_key = ?", ("server_performance",)).fetchone()

        self.assertEqual(row["type"], "read_only")
        self.assertEqual(row["output_type"], "summary")
        self.assertEqual(row["requires_confirmation"], 0)
        self.assertEqual(row["enabled"], 1)

    def test_truncation_still_applies_through_executor(self):
        conn = db.connect(":memory:")
        self.addCleanup(conn.close)
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

    def test_server_performance_accepts_app_config(self):
        config = AppConfig(
            values={
                "services": [],
                "logs": {"nginx_access": "missing-access.log", "nginx_error": "missing-error.log", "max_lines": 10},
                "laravel": {"path": ".", "log_path": "missing-laravel.log"},
                "php_fpm": {"service_name": "php-fpm", "pool_config_paths": []},
                "mysql": {"service_name": "mysql", "timeout_seconds": 1},
                "thresholds": {},
            }
        )

        result = server_performance({"config": config})

        self.assertIn("Server Performance", result["summary_text"])

    def test_server_performance_with_applications_only_config(self):
        config = AppConfig(
            values={
                "services": [],
                "applications": [{"service_name": "app", "path": "/opt/app", "type": "unknown", "log_path": ""}],
                "logs": {"nginx_access": "missing-access.log", "nginx_error": "missing-error.log", "max_lines": 10},
                "php_fpm": {"service_name": "php-fpm", "pool_config_paths": []},
                "mysql": {"service_name": "mysql", "timeout_seconds": 1},
                "thresholds": {},
            }
        )

        result = server_performance({"config": config})

        self.assertIn("Server Performance", result["summary_text"])


if __name__ == "__main__":
    unittest.main()
