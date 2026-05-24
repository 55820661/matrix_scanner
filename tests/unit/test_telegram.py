import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from threading import Event
from types import SimpleNamespace
from unittest.mock import patch

from matrix_scanner import db
from matrix_scanner.cli import _telegram_bot
from matrix_scanner.telegram_bot import BACK_BUTTON, MAIN_MENU_PROMPT, MENU_PROMPT, SUBMENU_PROMPT, available_commands, build_help_text, command_keyboard, format_tool_response, handle_update, is_update_allowed, map_command, poll_once, submenu_keyboard
from matrix_scanner.telegram_bot import run_long_polling
from matrix_scanner.tool_registry import ToolSpec


def tool(tool_key, *, enabled=True, type="read_only"):
    return ToolSpec(tool_key, tool_key, tool_key, lambda context: {"summary_text": "ok"}, tool_key, enabled=enabled, type=type)


def telegram_registry(**overrides):
    registry = {
        "server_performance": tool("server_performance"),
        "get_disk": tool("get_disk"),
        "get_services": tool("get_services"),
        "get_nginx_errors": tool("get_nginx_errors", type="diagnostic"),
        "get_laravel_errors": tool("get_laravel_errors", type="diagnostic"),
        "generate_report": tool("generate_report", type="diagnostic"),
        "top_processes": tool("top_processes"),
        "apache_error_summary": tool("apache_error_summary"),
        "apache_5xx_summary": tool("apache_5xx_summary"),
        "laravel_log_health": tool("laravel_log_health"),
        "laravel_env_sanity": tool("laravel_env_sanity"),
        "laravel_exception_summary": tool("laravel_exception_summary"),
        "queue_workers_summary": tool("queue_workers_summary"),
        "supervisor_summary": tool("supervisor_summary"),
        "suspicious_cron_scan": tool("suspicious_cron_scan"),
        "suspicious_files_scan": tool("suspicious_files_scan"),
    }
    registry.update(overrides)
    return registry


class TelegramTests(unittest.TestCase):
    def test_map_command_to_tool(self):
        self.assertEqual(map_command("/status"), "server_performance")
        self.assertEqual(map_command("/performance"), "server_performance")
        self.assertEqual(map_command("/report please"), "generate_report")
        self.assertIsNone(map_command("/start"))
        self.assertIsNone(map_command("/help"))
        self.assertIsNone(map_command("status"))

    def test_telegram_auth_uses_ids_not_username(self):
        config = {"telegram": {"allowed_user_ids": [123], "allowed_chat_ids": []}}
        update = {"message": {"text": "/status", "from": {"id": 123, "username": "someone"}, "chat": {"id": 999}}}

        self.assertIs(is_update_allowed(config, update), True)

        denied = {"message": {"text": "/status", "from": {"id": 999, "username": "someone"}, "chat": {"id": 888}}}
        self.assertIs(is_update_allowed(config, denied), False)

    def test_handle_update_denies_unauthorized_without_sending(self):
        conn = db.connect(":memory:")
        sent = []
        update = {"message": {"text": "/status", "from": {"id": 999}, "chat": {"id": 888}}}

        result = handle_update(
            conn=conn,
            registry={},
            config={"telegram": {"allowed_user_ids": [123], "allowed_chat_ids": []}},
            token="token",
            update=update,
            send_func=lambda *args: sent.append(args),
        )

        self.assertEqual(result["status"], "denied")
        self.assertEqual(sent, [])

    def test_handle_update_executes_status_tool_and_sends_summary(self):
        conn = db.connect(":memory:")
        sent = []
        registry = telegram_registry(
            server_performance=ToolSpec(
                "server_performance", "Status", "Status", lambda context: {"summary_text": "الحالة العامة: جيدة"}, "server_performance"
            )
        )
        update = {"message": {"text": "/status", "from": {"id": 123}, "chat": {"id": 456}}}

        result = handle_update(
            conn=conn,
            registry=registry,
            config={"telegram": {"allowed_user_ids": [123], "allowed_chat_ids": []}},
            token="token",
            update=update,
            send_func=lambda token, chat_id, text: sent.append((token, chat_id, text)),
        )

        self.assertEqual(result["status"], "handled")
        self.assertEqual(result["tool_key"], "server_performance")
        self.assertEqual(sent, [("token", 456, "الحالة العامة: جيدة"), ("token", 456, MENU_PROMPT)])
        row = conn.execute("SELECT source, tool_key, status FROM tool_invocations").fetchone()
        self.assertEqual(row["source"], "telegram")
        self.assertEqual(row["tool_key"], "server_performance")
        self.assertEqual(row["status"], "completed")

    def test_status_uses_telegram_formatter(self):
        conn = db.connect(":memory:")
        sent = []
        registry = telegram_registry(
            server_performance=ToolSpec(
                "server_performance",
                "Status",
                "Status",
                lambda context: {
                    "summary_text": "| Metric | Value | Status |\n| --- | ---: | --- |",
                    "telegram_text": "Server Performance\n\nCPU: 4.7% - جيد",
                },
                "server_performance",
            )
        )
        update = {"message": {"text": "/status", "from": {"id": 123}, "chat": {"id": 456}}}

        handle_update(
            conn=conn,
            registry=registry,
            config={"telegram": {"allowed_user_ids": [123], "allowed_chat_ids": []}},
            token="token",
            update=update,
            send_func=lambda token, chat_id, text, reply_markup=None: sent.append((text, reply_markup)),
        )

        self.assertEqual(sent[0], ("Server Performance\n\nCPU: 4.7% - جيد", None))
        self.assertEqual(sent[1], (SUBMENU_PROMPT, submenu_keyboard("🖥 Server", registry, {"telegram": {"allowed_user_ids": [123], "allowed_chat_ids": []}})))

    def test_handle_update_sends_short_report_for_report_command(self):
        conn = db.connect(":memory:")
        sent = []
        registry = telegram_registry(
            generate_report=ToolSpec(
                "generate_report",
                "Report",
                "Report",
                lambda context: {"report_text": "تقرير Matrix Scanner\nلا توجد مشاكل."},
                "generate_report",
                type="diagnostic",
                output_type="report",
            )
        )
        update = {"message": {"text": "/report", "from": {"id": 123}, "chat": {"id": 456}}}

        result = handle_update(
            conn=conn,
            registry=registry,
            config={"telegram": {"allowed_user_ids": [123], "allowed_chat_ids": []}},
            token="token",
            update=update,
            send_func=lambda token, chat_id, text, reply_markup=None: sent.append((chat_id, text, reply_markup)),
        )

        self.assertEqual(result["status"], "handled")
        self.assertEqual(sent[0], (456, "تقرير Matrix Scanner\nلا توجد مشاكل.", None))
        self.assertEqual(sent[1], (456, SUBMENU_PROMPT, submenu_keyboard("📄 Reports", registry, {"telegram": {"allowed_user_ids": [123], "allowed_chat_ids": []}})))

    def test_start_displays_menu_with_keyboard(self):
        conn = db.connect(":memory:")
        sent = []
        update = {"message": {"text": "/start", "from": {"id": 123}, "chat": {"id": 456}}}

        result = handle_update(
            conn=conn,
            registry=telegram_registry(),
            config={"telegram": {"allowed_user_ids": [123], "allowed_chat_ids": []}},
            token="token",
            update=update,
            send_func=lambda token, chat_id, text, reply_markup=None: sent.append((text, reply_markup)),
        )

        self.assertEqual(result["status"], "handled")
        self.assertEqual(result["tool_key"], "help")
        self.assertIn("مرحبًا بك في Matrix Scanner", sent[0][0])
        self.assertIn("اختر قسمًا", sent[0][0])
        self.assertEqual(sent[0][1], command_keyboard(telegram_registry(), {"telegram": {"allowed_user_ids": [123], "allowed_chat_ids": []}}))

    def test_help_displays_menu_with_keyboard(self):
        conn = db.connect(":memory:")
        sent = []
        update = {"message": {"text": "/help", "from": {"id": 123}, "chat": {"id": 456}}}

        result = handle_update(
            conn=conn,
            registry=telegram_registry(),
            config={"telegram": {"allowed_user_ids": [123], "allowed_chat_ids": []}},
            token="token",
            update=update,
            send_func=lambda token, chat_id, text, reply_markup=None: sent.append((text, reply_markup)),
        )

        self.assertEqual(result["status"], "handled")
        self.assertIn("اختر قسمًا", sent[0][0])
        self.assertEqual(sent[0][1], command_keyboard(telegram_registry(), {"telegram": {"allowed_user_ids": [123], "allowed_chat_ids": []}}))

    def test_start_keyboard_shows_main_menu_only(self):
        registry = telegram_registry()
        config = {"telegram": {"allowed_user_ids": [123], "allowed_chat_ids": []}}
        flattened = [item for row in command_keyboard(registry, config)["keyboard"] for item in row]

        self.assertIn("🖥 Server", flattened)
        self.assertIn("🌐 Web / Logs", flattened)
        self.assertNotIn("/status", flattened)
        self.assertNotIn("/nginx", flattened)

    def test_web_submenu_contains_nginx_when_enabled(self):
        keyboard = submenu_keyboard("🌐 Web / Logs", telegram_registry(), {"telegram": {"allowed_user_ids": [123], "allowed_chat_ids": []}})
        flattened = [command for row in keyboard["keyboard"] for command in row]

        self.assertIn("/nginx", flattened)
        self.assertIn("/apache", flattened)
        self.assertIn(BACK_BUTTON, flattened)

    def test_disabled_command_is_hidden(self):
        registry = telegram_registry(get_nginx_errors=tool("get_nginx_errors", enabled=False, type="diagnostic"))
        config = {"telegram": {"allowed_user_ids": [123], "allowed_chat_ids": []}}

        text = build_help_text(registry, config)
        flattened = [command for row in command_keyboard(registry, config)["keyboard"] for command in row]
        submenu = [command for row in submenu_keyboard("🌐 Web / Logs", registry, config)["keyboard"] for command in row]

        self.assertNotIn("/nginx", text)
        self.assertNotIn("/nginx", flattened)
        self.assertNotIn("/nginx", submenu)

    def test_action_command_is_hidden_without_approved_fix(self):
        registry = telegram_registry(restart_service=tool("restart_service", type="action"))
        config = {"approved_fix": False, "telegram": {"allowed_user_ids": [123], "allowed_chat_ids": []}}

        with patch.dict("matrix_scanner.telegram_bot.COMMAND_TO_TOOL", {"/restart": "restart_service"}, clear=False):
            text = build_help_text(registry, config)
            flattened = [command for row in command_keyboard(registry, config)["keyboard"] for command in row]

        self.assertNotIn("/restart", text)
        self.assertNotIn("/restart", flattened)

    def test_server_group_selection_displays_server_commands_only(self):
        conn = db.connect(":memory:")
        sent = []
        registry = telegram_registry()
        config = {"telegram": {"allowed_user_ids": [123], "allowed_chat_ids": []}}

        result = handle_update(
            conn=conn,
            registry=registry,
            config=config,
            token="token",
            update={"message": {"text": "🖥 Server", "from": {"id": 123}, "chat": {"id": 456}}},
            send_func=lambda token, chat_id, text, reply_markup=None: sent.append((text, reply_markup)),
        )

        flattened = [command for row in sent[0][1]["keyboard"] for command in row]
        self.assertEqual(result["group"], "🖥 Server")
        self.assertIn("/status", flattened)
        self.assertIn("/top", flattened)
        self.assertNotIn("/apache", flattened)

    def test_laravel_group_selection_displays_laravel_commands_only(self):
        conn = db.connect(":memory:")
        sent = []
        registry = telegram_registry()
        config = {"telegram": {"allowed_user_ids": [123], "allowed_chat_ids": []}}

        handle_update(
            conn=conn,
            registry=registry,
            config=config,
            token="token",
            update={"message": {"text": "🧩 Laravel", "from": {"id": 123}, "chat": {"id": 456}}},
            send_func=lambda token, chat_id, text, reply_markup=None: sent.append((text, reply_markup)),
        )

        flattened = [command for row in sent[0][1]["keyboard"] for command in row]
        self.assertIn("/laravel", flattened)
        self.assertIn("/laravel-exceptions", flattened)
        self.assertNotIn("/queue", flattened)

    def test_back_returns_main_menu(self):
        conn = db.connect(":memory:")
        sent = []
        registry = telegram_registry()
        config = {"telegram": {"allowed_user_ids": [123], "allowed_chat_ids": []}}

        handle_update(
            conn=conn,
            registry=registry,
            config=config,
            token="token",
            update={"message": {"text": BACK_BUTTON, "from": {"id": 123}, "chat": {"id": 456}}},
            send_func=lambda token, chat_id, text, reply_markup=None: sent.append((text, reply_markup)),
        )

        flattened = [item for row in sent[0][1]["keyboard"] for item in row]
        self.assertEqual(sent[0][0], MAIN_MENU_PROMPT)
        self.assertIn("🖥 Server", flattened)

    def test_after_apache_command_shows_web_logs_submenu(self):
        conn = db.connect(":memory:")
        sent = []
        registry = telegram_registry(apache_error_summary=ToolSpec("apache_error_summary", "Apache", "Apache", lambda context: {"summary_text": "apache ok"}, "apache_error_summary"))
        config = {"telegram": {"allowed_user_ids": [123], "allowed_chat_ids": []}}

        result = handle_update(
            conn=conn,
            registry=registry,
            config=config,
            token="token",
            update={"message": {"text": "/apache", "from": {"id": 123}, "chat": {"id": 456}}},
            send_func=lambda token, chat_id, text, reply_markup=None: sent.append((text, reply_markup)),
        )

        flattened = [command for row in sent[1][1]["keyboard"] for command in row]
        self.assertEqual(result["tool_key"], "apache_error_summary")
        self.assertEqual(sent[0], ("apache ok", None))
        self.assertIn("/nginx", flattened)
        self.assertIn("/apache", flattened)
        self.assertNotIn("/queue", flattened)

    def test_after_queue_command_shows_workers_submenu(self):
        conn = db.connect(":memory:")
        sent = []
        registry = telegram_registry(queue_workers_summary=ToolSpec("queue_workers_summary", "Queue", "Queue", lambda context: {"summary_text": "queue ok"}, "queue_workers_summary"))
        config = {"telegram": {"allowed_user_ids": [123], "allowed_chat_ids": []}}

        result = handle_update(
            conn=conn,
            registry=registry,
            config=config,
            token="token",
            update={"message": {"text": "/queue", "from": {"id": 123}, "chat": {"id": 456}}},
            send_func=lambda token, chat_id, text, reply_markup=None: sent.append((text, reply_markup)),
        )

        flattened = [command for row in sent[1][1]["keyboard"] for command in row]
        self.assertEqual(result["tool_key"], "queue_workers_summary")
        self.assertEqual(sent[0], ("queue ok", None))
        self.assertIn("/queue", flattened)
        self.assertIn("/supervisor", flattened)
        self.assertNotIn("/apache", flattened)

    def test_unknown_command_sends_error_then_menu_without_unauthorized_leak(self):
        conn = db.connect(":memory:")
        sent = []
        update = {"message": {"text": "/wat", "from": {"id": 123}, "chat": {"id": 456}}}

        result = handle_update(
            conn=conn,
            registry=telegram_registry(),
            config={"telegram": {"allowed_user_ids": [123], "allowed_chat_ids": []}},
            token="token",
            update=update,
            send_func=lambda token, chat_id, text, reply_markup=None: sent.append((text, reply_markup)),
        )

        self.assertEqual(result["status"], "ignored")
        self.assertEqual(sent[0], ("أمر غير معروف. اختر من القائمة:", command_keyboard(telegram_registry(), {"telegram": {"allowed_user_ids": [123], "allowed_chat_ids": []}})))

    def test_poll_once_updates_offset_and_dispatches(self):
        conn = db.connect(":memory:")
        sent = []
        registry = {
            "server_performance": ToolSpec(
                "server_performance",
                "Status",
                "Status",
                lambda context: {"summary_text": "ok"},
                "server_performance",
            )
        }

        def fake_updates(token, offset=None, timeout=30):
            return {
                "ok": True,
                "result": [
                    {"update_id": 10, "message": {"text": "/status", "from": {"id": 123}, "chat": {"id": 456}}}
                ],
            }

        next_offset = poll_once(
            conn=conn,
            registry=registry,
            config={"telegram": {"allowed_user_ids": [123], "allowed_chat_ids": [], "poll_timeout_seconds": 1}},
            token="token",
            send_func=lambda token, chat_id, text: sent.append(text),
            get_updates_func=fake_updates,
        )

        self.assertEqual(next_offset, 11)
        self.assertEqual(sent, ["ok", MENU_PROMPT])

    def test_run_long_polling_exits_when_stop_event_is_set(self):
        conn = db.connect(":memory:")
        stop_event = Event()
        stop_event.set()

        run_long_polling(
            conn=conn,
            registry={},
            config={"telegram": {"poll_sleep_seconds": 0}},
            token="token",
            stop_event=stop_event,
            get_updates_func=lambda *args, **kwargs: self.fail("get_updates should not run after stop"),
        )

    def test_run_long_polling_once_still_runs_one_iteration(self):
        conn = db.connect(":memory:")
        calls = []

        def fake_updates(token, offset=None, timeout=30):
            calls.append(offset)
            return {"ok": True, "result": []}

        run_long_polling(
            conn=conn,
            registry={},
            config={"telegram": {"poll_sleep_seconds": 0, "poll_timeout_seconds": 1}},
            token="token",
            stop_after=1,
            get_updates_func=fake_updates,
        )

        self.assertEqual(calls, [None])

    def test_telegram_bot_keyboard_interrupt_stops_without_traceback(self):
        app_config = SimpleNamespace(telegram_bot_token="token", values={})
        stdout = StringIO()
        stderr = StringIO()

        with patch("matrix_scanner.cli.run_long_polling", side_effect=KeyboardInterrupt), redirect_stdout(stdout), redirect_stderr(stderr):
            code = _telegram_bot(app_config, db.connect(":memory:"), {})

        self.assertEqual(code, 130)
        self.assertIn("Telegram bot stopped.", stdout.getvalue())
        self.assertNotIn("Traceback", stdout.getvalue())
        self.assertNotIn("Traceback", stderr.getvalue())

    def test_poll_once_does_not_repeat_same_update(self):
        conn = db.connect(":memory:")
        sent = []
        registry = {
            "server_performance": ToolSpec(
                "server_performance",
                "Status",
                "Status",
                lambda context: {"summary_text": "ok"},
                "server_performance",
            )
        }

        def fake_updates(token, offset=None, timeout=30):
            return {
                "ok": True,
                "result": [
                    {"update_id": 10, "message": {"text": "/status", "from": {"id": 123}, "chat": {"id": 456}}},
                    {"update_id": 10, "message": {"text": "/status", "from": {"id": 123}, "chat": {"id": 456}}},
                ],
            }

        next_offset = poll_once(
            conn=conn,
            registry=registry,
            config={"telegram": {"allowed_user_ids": [123], "allowed_chat_ids": [], "poll_timeout_seconds": 1}},
            token="token",
            send_func=lambda token, chat_id, text: sent.append(text),
            get_updates_func=fake_updates,
        )

        self.assertEqual(next_offset, 11)
        self.assertEqual(sent, ["ok", MENU_PROMPT])

        sent.clear()
        next_offset = poll_once(
            conn=conn,
            registry=registry,
            config={"telegram": {"allowed_user_ids": [123], "allowed_chat_ids": [], "poll_timeout_seconds": 1}},
            token="token",
            send_func=lambda token, chat_id, text: sent.append(text),
            get_updates_func=fake_updates,
        )

        self.assertEqual(next_offset, 11)
        self.assertEqual(sent, [])

    def test_telegram_formatter_prefers_non_table_text(self):
        text = format_tool_response(
            {
                "ok": True,
                "output": {
                    "summary_text": "| Metric | Value | Status |\n| --- | ---: | --- |",
                    "telegram_text": "Server Performance\n\nCPU: 4.7% - جيد",
                },
            }
        )

        self.assertIn("CPU: 4.7% - جيد", text)
        self.assertNotIn("| Metric |", text)


if __name__ == "__main__":
    unittest.main()
