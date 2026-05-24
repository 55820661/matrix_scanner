import unittest

from matrix_scanner import db
from matrix_scanner.config import AppConfig
from matrix_scanner.scheduler import collect_scan, run_scan
from matrix_scanner.tool_registry import build_registry


class DbAndSchedulerTests(unittest.TestCase):
    def test_db_initializes_and_scan_is_stored(self):
        conn = db.connect(":memory:")
        config = {
            "services": [],
            "logs": {"nginx_access": "missing-access.log", "nginx_error": "missing-error.log", "max_lines": 10},
            "laravel": {"path": ".", "log_path": "missing-laravel.log"},
            "thresholds": {"disk_percent": 101, "cpu_percent": 101, "ram_percent": 101},
        }

        result = run_scan(conn, config)

        self.assertEqual(result["scan_id"], 1)
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM scan_results").fetchone()[0], 1)

    def test_tools_registry_syncs_metadata(self):
        conn = db.connect(":memory:")
        db.sync_tools_registry(conn, build_registry())

        count = conn.execute("SELECT COUNT(*) FROM tools_registry").fetchone()[0]
        self.assertGreaterEqual(count, 6)

    def test_collect_scan_accepts_app_config(self):
        config = AppConfig(
            values={
                "services": [],
                "logs": {"nginx_access": "missing-access.log", "nginx_error": "missing-error.log", "max_lines": 10},
                "laravel": {"path": ".", "log_path": "missing-laravel.log"},
                "php_fpm": {"service_name": "php-fpm", "pool_config_paths": []},
                "mysql": {"service_name": "mysql", "timeout_seconds": 1},
            }
        )

        result = collect_scan(config)

        self.assertIn("system", result)
        self.assertIn("services", result)


if __name__ == "__main__":
    unittest.main()
