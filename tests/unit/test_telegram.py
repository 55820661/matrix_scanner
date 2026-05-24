import unittest

from matrix_scanner import db
from matrix_scanner.telegram_bot import handle_update, is_update_allowed, map_command, poll_once
from matrix_scanner.tool_registry import ToolSpec


class TelegramTests(unittest.TestCase):
    def test_map_command_to_tool(self):
        self.assertEqual(map_command("/status"), "get_status")
        self.assertEqual(map_command("/report please"), "generate_report")
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
            "get_status": ToolSpec(
                "get_status",
                "Status",
                "Status",
                lambda context: {"summary_text": "الحالة العامة: جيدة"},
                "get_status",
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
        self.assertEqual(result["tool_key"], "get_status")
        self.assertEqual(sent, [("token", 456, "الحالة العامة: جيدة")])
        row = conn.execute("SELECT source, tool_key, status FROM tool_invocations").fetchone()
        self.assertEqual(row["source"], "telegram")
        self.assertEqual(row["tool_key"], "get_status")
        self.assertEqual(row["status"], "completed")

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

    def test_poll_once_updates_offset_and_dispatches(self):
        conn = db.connect(":memory:")
        sent = []
        registry = {
            "get_status": ToolSpec(
                "get_status",
                "Status",
                "Status",
                lambda context: {"summary_text": "ok"},
                "get_status",
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


if __name__ == "__main__":
    unittest.main()
