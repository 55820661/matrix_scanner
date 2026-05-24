import contextlib
import io
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from matrix_scanner.cli import _safe_input, main
from matrix_scanner.setup import (
    ApplicationInfo,
    InvalidServiceSelection,
    ServiceInfo,
    build_config_yaml,
    detect_applications,
    filter_setup_services,
    parse_service_selection,
    prompt_service_selection,
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
            applications=[],
            database_path="data/matrix_scanner.sqlite3",
            nginx_access_log="/var/log/nginx/access.log",
            nginx_error_log="/var/log/nginx/error.log",
            logs_max_lines=500,
        )

        self.assertIn("services:\n  - nginx\n  - mysql", content)
        self.assertIn("database_path: data/matrix_scanner.sqlite3", content)
        self.assertNotIn("TELEGRAM_BOT_TOKEN", content)

    def test_config_contains_applications(self):
        content = build_config_yaml(
            services=["app-worker"],
            applications=[ApplicationInfo("app-worker", "/opt/app", "unknown", "")],
            database_path="data/matrix_scanner.sqlite3",
            nginx_access_log="/var/log/nginx/access.log",
            nginx_error_log="/var/log/nginx/error.log",
            logs_max_lines=500,
        )

        self.assertIn("applications:\n  - service_name: app-worker\n    path: /opt/app\n    type: unknown\n    log_path:", content)

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

    def test_service_name_selection_is_rejected(self):
        with self.assertRaises(InvalidServiceSelection):
            parse_service_selection("nginx", SERVICES)

    def test_invalid_selection_reprompts_without_traceback(self):
        answers = iter(["nginx", "1"])
        output = io.StringIO()

        with contextlib.redirect_stdout(output):
            result = prompt_service_selection(lambda prompt: next(answers), SERVICES)

        self.assertEqual(result, ["nginx"])
        self.assertIn("Invalid selection. Please enter numbers only, all, or none.", output.getvalue())
        self.assertNotIn("Traceback", output.getvalue())

    def test_setup_does_not_prompt_for_additional_service_names(self):
        prompts = []
        answers = iter(["none"])

        def input_func(prompt):
            prompts.append(prompt)
            return next(answers)

        with mock.patch("matrix_scanner.setup.discover_systemd_services", return_value=[]):
            with mock.patch("matrix_scanner.setup.write_config", return_value=True):
                with contextlib.redirect_stdout(io.StringIO()):
                    run_interactive_setup(Path("ignored.yaml"), input_func=input_func)

        self.assertFalse(any("Additional service names" in prompt for prompt in prompts))

    def test_setup_does_not_prompt_for_laravel_paths(self):
        prompts = []
        answers = iter(["none"])

        def input_func(prompt):
            prompts.append(prompt)
            return next(answers)

        with mock.patch("matrix_scanner.setup.discover_systemd_services", return_value=[]):
            with mock.patch("matrix_scanner.setup.write_config", return_value=True):
                with contextlib.redirect_stdout(io.StringIO()):
                    run_interactive_setup(Path("ignored.yaml"), input_func=input_func)

        self.assertFalse(any("Laravel app path" in prompt for prompt in prompts))
        self.assertFalse(any("Laravel log path" in prompt for prompt in prompts))

    def test_setup_does_not_prompt_for_nginx_or_database_or_log_lines(self):
        prompts = []
        answers = iter(["none"])

        def input_func(prompt):
            prompts.append(prompt)
            return next(answers)

        with mock.patch("matrix_scanner.setup.discover_systemd_services", return_value=[]):
            with mock.patch("matrix_scanner.setup.write_config", return_value=True):
                with contextlib.redirect_stdout(io.StringIO()):
                    run_interactive_setup(Path("ignored.yaml"), input_func=input_func)

        forbidden = ("Nginx access log", "Nginx error log", "SQLite database path", "Log max lines")
        self.assertFalse(any(any(label in prompt for label in forbidden) for prompt in prompts))

    def test_setup_defaults_database_and_max_lines(self):
        content = build_config_yaml(
            services=[],
            applications=[],
            database_path="data/matrix_scanner.sqlite3",
            nginx_access_log="",
            nginx_error_log="",
            logs_max_lines=500,
        )

        self.assertIn("database_path: data/matrix_scanner.sqlite3", content)
        self.assertIn("  max_lines: 500", content)

    def test_setup_uses_detected_nginx_logs_when_present(self):
        with mock.patch("matrix_scanner.setup.Path.exists", return_value=True):
            from matrix_scanner.setup import detect_nginx_log_path

            self.assertEqual(detect_nginx_log_path("/var/log/nginx/access.log"), "/var/log/nginx/access.log")

    def test_setup_does_not_fail_when_nginx_logs_missing(self):
        with mock.patch("matrix_scanner.setup.Path.exists", return_value=False):
            from matrix_scanner.setup import detect_nginx_log_path

            self.assertEqual(detect_nginx_log_path("/var/log/nginx/access.log"), "")

    def test_service_working_directory_becomes_application(self):
        services = [ServiceInfo("app", working_directory="/opt/app")]

        applications = detect_applications(services)

        self.assertEqual(applications, [ApplicationInfo("app", "/opt/app", "unknown", "")])

    def test_multiple_services_create_multiple_applications(self):
        services = [ServiceInfo("app-one", working_directory="/opt/one"), ServiceInfo("app-two", working_directory="/opt/two")]

        applications = detect_applications(services)

        self.assertEqual([app.path for app in applications], ["/opt/one", "/opt/two"])

    def test_laravel_log_path_detected_only_when_file_exists(self):
        existing = ServiceInfo("laravel-app", working_directory="tests/fixtures/laravel-app")
        missing = ServiceInfo("laravel-missing", working_directory="tests/fixtures/laravel-missing")

        applications = detect_applications([existing, missing])

        self.assertEqual(applications[0].type, "laravel")
        self.assertTrue(applications[0].log_path.endswith("storage\\logs\\laravel.log") or applications[0].log_path.endswith("storage/logs/laravel.log"))
        self.assertEqual(applications[1].log_path, "")

    def test_gunicorn_service_is_not_classified_as_laravel(self):
        services = [ServiceInfo("django-app", working_directory="/opt/django", exec_start="/venv/bin/gunicorn project.wsgi")]

        applications = detect_applications(services)

        self.assertEqual(applications[0].type, "django")
        self.assertEqual(applications[0].log_path, "")

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

    def test_safe_input_decodes_invalid_terminal_bytes_without_traceback(self):
        stdin = SimpleNamespace(buffer=io.BytesIO(b"1,\xd9,3\n"), encoding="utf-8")
        stdout = io.StringIO()

        with mock.patch("matrix_scanner.cli.sys.stdin", stdin):
            with contextlib.redirect_stdout(stdout):
                value = _safe_input("Select: ")

        self.assertIn("Select: ", stdout.getvalue())
        self.assertIn("\ufffd", value)


if __name__ == "__main__":
    unittest.main()
