import contextlib
import io
import unittest
from pathlib import Path
from unittest import mock

from matrix_scanner.cli import main
from matrix_scanner.setup import (
    ServiceInfo,
    build_config_yaml,
    filter_setup_services,
    parse_service_selection,
    run_interactive_setup,
    should_overwrite_config,
)


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

    def test_default_filter_hides_system_services(self):
        services = [
            ServiceInfo("systemd-journald", active_state="active"),
            ServiceInfo("user@1000", active_state="active"),
            ServiceInfo("apt-daily", active_state="active"),
            ServiceInfo("getty@tty1", active_state="active"),
            ServiceInfo("nginx", active_state="active"),
        ]

        result = filter_setup_services(services)

        self.assertEqual([service.name for service in result], ["nginx"])

    def test_service_with_working_directory_is_candidate(self):
        services = [ServiceInfo("custom-worker", active_state="active", working_directory="/var/www/app")]

        result = filter_setup_services(services)

        self.assertEqual([service.name for service in result], ["custom-worker"])

    def test_nginx_is_candidate_service(self):
        services = [ServiceInfo("nginx", active_state="active")]

        result = filter_setup_services(services)

        self.assertEqual([service.name for service in result], ["nginx"])

    def test_all_services_returns_everything(self):
        services = [
            ServiceInfo("systemd-journald", active_state="active"),
            ServiceInfo("apt-daily", active_state="inactive"),
            ServiceInfo("nginx", active_state="active"),
        ]

        result = filter_setup_services(services, all_services=True)

        self.assertEqual([service.name for service in result], ["systemd-journald", "apt-daily", "nginx"])

    def test_manual_input_still_works_for_hidden_service(self):
        self.assertEqual(parse_service_selection("custom-worker,another-service", []), ["custom-worker", "another-service"])

    def test_run_setup_keyboard_interrupt_leaves_no_config(self):
        path = Path("setup_cancelled_test_config.yaml")
        if path.exists():
            path.unlink()

        with mock.patch("matrix_scanner.setup.discover_systemd_services", return_value=[]):
            with contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaises(KeyboardInterrupt):
                    run_interactive_setup(path, input_func=lambda prompt: (_ for _ in ()).throw(KeyboardInterrupt()))

        self.assertFalse(path.exists())

    def test_cli_setup_keyboard_interrupt_returns_130_without_traceback(self):
        output = io.StringIO()
        with mock.patch("matrix_scanner.cli.run_interactive_setup", side_effect=KeyboardInterrupt):
            with contextlib.redirect_stdout(output):
                code = main(["--config", "setup_cancelled_test_config.yaml", "setup"])

        self.assertEqual(code, 130)
        self.assertIn("Setup cancelled. No changes were made.", output.getvalue())
        self.assertNotIn("Traceback", output.getvalue())


if __name__ == "__main__":
    unittest.main()
