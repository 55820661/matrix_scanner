import unittest
from pathlib import Path

from matrix_scanner.setup import ServiceInfo, build_config_yaml, parse_service_selection, should_overwrite_config


SERVICES = [
    ServiceInfo("nginx"),
    ServiceInfo("matrix-gateway"),
    ServiceInfo("mysql"),
    ServiceInfo("php-fpm"),
]


class SetupTests(unittest.TestCase):
    def test_parse_selection_numbers(self):
        self.assertEqual(parse_service_selection("1,2,4", SERVICES), ["nginx", "matrix-gateway", "php-fpm"])

    def test_parse_selection_all(self):
        self.assertEqual(parse_service_selection("all", SERVICES), ["nginx", "matrix-gateway", "mysql", "php-fpm"])

    def test_parse_selection_none(self):
        self.assertEqual(parse_service_selection("none", SERVICES), [])

    def test_prevent_overwrite_without_confirmation(self):
        changed = should_overwrite_config(Path("README.md"), force=False, confirm=lambda prompt: "n")

        self.assertFalse(changed)

    def test_create_config_contains_selected_services(self):
        content = build_config_yaml(
            services=["nginx", "mysql"],
            database_path="data/matrix_scanner.sqlite3",
            nginx_access_log="/var/log/nginx/access.log",
            nginx_error_log="/var/log/nginx/error.log",
            app_path="/var/www/app",
            app_log_path="/var/www/app/storage/logs/laravel.log",
            logs_max_lines=500,
        )

        self.assertIn("services:\n  - nginx\n  - mysql", content)
        self.assertIn("database_path: data/matrix_scanner.sqlite3", content)
        self.assertNotIn("TELEGRAM_BOT_TOKEN", content)


if __name__ == "__main__":
    unittest.main()
