import unittest
from unittest import mock

from matrix_scanner import db
from matrix_scanner.config import AppConfig
from matrix_scanner.scheduler import collect_scan, run_scan
from matrix_scanner.tool_registry import build_registry


class DbAndSchedulerTests(unittest.TestCase):
    def test_db_initializes_and_scan_is_stored(self):
        conn = db.connect(":memory:")
        self.addCleanup(conn.close)
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
        self.addCleanup(conn.close)
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

    def test_collect_scan_with_empty_laravel_config_does_not_fail(self):
        config = {
            "services": [],
            "logs": {"nginx_access": "missing-access.log", "nginx_error": "missing-error.log", "max_lines": 10},
            "laravel": {"path": "", "log_path": ""},
            "php_fpm": {"service_name": "php-fpm", "pool_config_paths": []},
            "mysql": {"service_name": "mysql", "timeout_seconds": 1},
        }

        result = collect_scan(config)

        self.assertEqual(result["laravel"], {"enabled": False, "reason": "No Laravel log path configured"})

    def test_collect_scan_with_laravel_log_path_list_does_not_fail(self):
        config = {
            "services": [],
            "logs": {"nginx_access": "missing-access.log", "nginx_error": "missing-error.log", "max_lines": 10},
            "laravel": {"path": ".", "log_path": ["bad"]},
            "php_fpm": {"service_name": "php-fpm", "pool_config_paths": []},
            "mysql": {"service_name": "mysql", "timeout_seconds": 1},
        }

        result = collect_scan(config)

        self.assertEqual(result["laravel"], {"enabled": False, "reason": "No Laravel log path configured"})

    def test_collect_scan_applications_only_config_does_not_fail(self):
        config = {
            "services": [],
            "applications": [{"service_name": "app", "path": "/opt/app", "type": "unknown", "log_path": ""}],
            "logs": {"nginx_access": "missing-access.log", "nginx_error": "missing-error.log", "max_lines": 10},
            "php_fpm": {"service_name": "php-fpm", "pool_config_paths": []},
            "mysql": {"service_name": "mysql", "timeout_seconds": 1},
        }

        result = collect_scan(config)

        self.assertEqual(result["laravel"], {"enabled": False, "reason": "No Laravel log path configured"})

    def test_laravel_scanner_called_only_for_valid_paths(self):
        base = {
            "services": [],
            "logs": {"nginx_access": "missing-access.log", "nginx_error": "missing-error.log", "max_lines": 10},
            "php_fpm": {"service_name": "php-fpm", "pool_config_paths": []},
            "mysql": {"service_name": "mysql", "timeout_seconds": 1},
        }

        with mock.patch("matrix_scanner.scheduler.scan_laravel", return_value={"ok": True}) as scan_laravel:
            collect_scan(base | {"laravel": {"path": ".", "log_path": ["bad"]}})
            scan_laravel.assert_not_called()

        with mock.patch("matrix_scanner.scheduler.scan_laravel", return_value={"ok": True}) as scan_laravel:
            collect_scan(base | {"laravel": {"path": ".", "log_path": "missing-laravel.log"}})
            scan_laravel.assert_called_once_with("missing-laravel.log", ".", 10)

    def test_scan_sends_telegram_alert_when_enabled(self):
        conn = db.connect(":memory:")
        self.addCleanup(conn.close)
        sent = []
        config = {
            "alerts_enabled": True,
            "telegram_enabled": True,
            "telegram": {"default_chat_id": 456},
            "thresholds": {"disk_percent": 90, "cpu_percent": 101, "ram_percent": 101},
            "alert_cooldown_minutes": 360,
        }
        raw = {"system": {"cpu_percent": 1, "ram": {"used_percent": 1}, "disk": {"used_percent": 91.2}}, "services": {}}

        with mock.patch("matrix_scanner.scheduler.collect_scan", return_value=raw):
            result = run_scan(conn, config, telegram_token="token", alert_send_func=lambda token, chat_id, text: sent.append((token, chat_id, text)))

        self.assertEqual(result["notification"]["sent"], 1)
        self.assertEqual(sent[0][0], "token")
        self.assertEqual(sent[0][1], 456)
        self.assertIn("مساحة القرص منخفضة", sent[0][2])

    def test_scan_alert_cooldown_prevents_duplicate_telegram_alert(self):
        conn = db.connect(":memory:")
        self.addCleanup(conn.close)
        sent = []
        config = {
            "alerts_enabled": True,
            "telegram_enabled": True,
            "telegram": {"default_chat_id": 456},
            "thresholds": {"disk_percent": 90, "cpu_percent": 101, "ram_percent": 101},
            "alert_cooldown_minutes": 360,
        }
        raw = {"system": {"cpu_percent": 1, "ram": {"used_percent": 1}, "disk": {"used_percent": 91.2}}, "services": {}}

        with mock.patch("matrix_scanner.scheduler.collect_scan", return_value=raw):
            run_scan(conn, config, telegram_token="token", alert_send_func=lambda token, chat_id, text: sent.append(text))
            second = run_scan(conn, config, telegram_token="token", alert_send_func=lambda token, chat_id, text: sent.append(text))

        self.assertEqual(len(sent), 1)
        self.assertEqual(second["alerts"], [])
        self.assertEqual(second["notification"]["sent"], 0)

    def test_scan_does_not_fail_when_telegram_token_missing(self):
        conn = db.connect(":memory:")
        self.addCleanup(conn.close)
        config = {
            "alerts_enabled": True,
            "telegram_enabled": True,
            "telegram": {"default_chat_id": 456},
            "thresholds": {"disk_percent": 90, "cpu_percent": 101, "ram_percent": 101},
        }
        raw = {"system": {"cpu_percent": 1, "ram": {"used_percent": 1}, "disk": {"used_percent": 91.2}}, "services": {}}

        with mock.patch("matrix_scanner.scheduler.collect_scan", return_value=raw):
            result = run_scan(conn, config, telegram_token=None, alert_send_func=lambda *args: self.fail("send should not be called"))

        self.assertEqual(result["notification"]["sent"], 0)
        self.assertIn("TELEGRAM_BOT_TOKEN is not set", result["notification"]["warnings"][0])

    def test_scan_does_not_store_or_send_when_alerts_disabled(self):
        conn = db.connect(":memory:")
        self.addCleanup(conn.close)
        config = {
            "alerts_enabled": False,
            "telegram_enabled": True,
            "telegram": {"default_chat_id": 456},
            "thresholds": {"disk_percent": 90, "cpu_percent": 101, "ram_percent": 101},
        }
        raw = {"system": {"cpu_percent": 1, "ram": {"used_percent": 1}, "disk": {"used_percent": 91.2}}, "services": {}}

        with mock.patch("matrix_scanner.scheduler.collect_scan", return_value=raw):
            result = run_scan(conn, config, telegram_token="token", alert_send_func=lambda *args: self.fail("send should not be called"))

        self.assertEqual(result["alerts"], [])
        self.assertEqual(result["notification"]["sent"], 0)
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0], 0)


if __name__ == "__main__":
    unittest.main()
