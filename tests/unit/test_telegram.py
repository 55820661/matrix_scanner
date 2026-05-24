import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from threading import Event
from types import SimpleNamespace
from unittest.mock import patch

from matrix_scanner import db
from matrix_scanner.cli import _telegram_bot
from matrix_scanner.telegram_bot import format_tool_response, handle_update, is_update_allowed, map_command, poll_once
from matrix_scanner.telegram_bot import run_long_polling
from matrix_scanner.tool_registry import ToolSpec


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
        registry = {
            "server_performance": ToolSpec(
                "server_performance",
                "Status",
                "Status",
                lambda context: {"summary_text": "الحالة العامة: جيدة"},
                "server_performance",
            )
        }
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
        self.assertEqual(sent, [("token", 456, "الحالة العامة: جيدة")])
        row = conn.execute("SELECT source, tool_key, status FROM tool_invocations").fetchone()
        self.assertEqual(row["source"], "telegram")
        self.assertEqual(row["tool_key"], "server_performance")
        self.assertEqual(row["status"], "completed")

    def test_status_uses_telegram_formatter(self):
        conn = db.connect(":memory:")
        sent = []
        registry = {
            "server_performance": ToolSpec(
                "server_performance",
                "Status",
                "Status",
                lambda context: {
                    "summary_text": "| Metric | Value | Status |\n| --- | ---: | --- |",
                    "telegram_text": "Server Performance\n\nCPU: 4.7% - جيد",
                },
                "server_performance",
            )
        }
        update = {"message": {"text": "/status", "from": {"id": 123}, "chat": {"id": 456}}}

        handle_update(
            conn=conn,
            registry=registry,
            config={"telegram": {"allowed_user_ids": [123], "allowed_chat_ids": []}},
            token="token",
            update=update,
            send_func=lambda token, chat_id, text: sent.append(text),
        )

        self.assertEqual(sent, ["Server Performance\n\nCPU: 4.7% - جيد"])

    def test_handle_update_sends_short_report_for_report_command(self):
        conn = db.connect(":memory:")
        sent = []
        registry = {
            "generate_report": ToolSpec(
                "generate_report",
                "Report",
                "Report",
                lambda context: {"report_text": "تقرير Matrix Scanner\nلا توجد مشاكل."},
                "generate_report",
                type="diagnostic",
                output_type="report",
            )
        }
        update = {"message": {"text": "/report", "from": {"id": 123}, "chat": {"id": 456}}}

        result = handle_update(
            conn=conn,
            registry=registry,
            config={"telegram": {"allowed_user_ids": [123], "allowed_chat_ids": []}},
            token="token",
            update=update,
            send_func=lambda token, chat_id, text: sent.append((chat_id, text)),
        )

        self.assertEqual(result["status"], "handled")
        self.assertEqual(sent, [(456, "تقرير Matrix Scanner\nلا توجد مشاكل.")])

    def test_handle_update_supports_start_and_help(self):
        conn = db.connect(":memory:")
        sent = []
        update = {"message": {"text": "/help", "from": {"id": 123}, "chat": {"id": 456}}}

        result = handle_update(
            conn=conn,
            registry={},
            config={"telegram": {"allowed_user_ids": [123], "allowed_chat_ids": []}},
            token="token",
            update=update,
            send_func=lambda token, chat_id, text: sent.append(text),
        )

        self.assertEqual(result["status"], "handled")
        self.assertEqual(result["tool_key"], "help")
        self.assertIn("/status", sent[0])
        self.assertIn("/report", sent[0])

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
        self.assertEqual(sent, ["ok"])

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
        self.assertEqual(sent, ["ok"])

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
