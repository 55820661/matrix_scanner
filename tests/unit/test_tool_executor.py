import unittest

from matrix_scanner import db
from matrix_scanner.security import Principal
from matrix_scanner.tool_executor import execute_tool
from matrix_scanner.tool_registry import ToolSpec


class ToolExecutorTests(unittest.TestCase):
    def test_unknown_tool_is_denied(self):
        conn = db.connect(":memory:")

        result = execute_tool(conn, {}, tool_key="nope", context={"config": {}}, source="test")

        self.assertIs(result["ok"], False)
        self.assertEqual(result["error"], "unknown_tool")
        row = conn.execute("SELECT status, denial_reason FROM tool_invocations").fetchone()
        self.assertEqual(row["status"], "denied")
        self.assertEqual(row["denial_reason"], "unknown_tool")

    def test_role_not_allowed_is_denied(self):
        conn = db.connect(":memory:")
        spec = ToolSpec(
            "admin_only",
            "Admin",
            "Admin only",
            lambda context: {"ok": True},
            "admin_only",
            allowed_roles=("admin",),
        )
        principal = Principal(id=1, telegram_user_id=10, telegram_chat_id=20, role="viewer")

        result = execute_tool(conn, {"admin_only": spec}, tool_key="admin_only", context={"config": {}}, source="test", principal=principal)

        self.assertIs(result["ok"], False)
        self.assertEqual(result["error"], "role_not_allowed")

    def test_action_tool_denied_when_approved_fix_disabled(self):
        conn = db.connect(":memory:")
        spec = ToolSpec(
            "restart",
            "Restart",
            "Restart service",
            lambda context: {"ok": True},
            "restart",
            type="action",
            allowed_modes=("approved_fix",),
        )

        result = execute_tool(conn, {"restart": spec}, tool_key="restart", context={"config": {"current_mode": "read_only"}}, source="test")

        self.assertIs(result["ok"], False)
        self.assertEqual(result["error"], "approved_fix_disabled")

    def test_output_is_truncated(self):
        conn = db.connect(":memory:")
        spec = ToolSpec(
            "large",
            "Large",
            "Large output",
            lambda context: {"summary_text": "x" * 200},
            "large",
            max_output_chars=50,
        )

        result = execute_tool(conn, {"large": spec}, tool_key="large", context={"config": {"current_mode": "read_only"}}, source="test")

        self.assertIs(result["ok"], True)
        self.assertIs(result["output"]["_truncated"], True)
        self.assertLessEqual(len(result["output"]["summary_text"]), 50)


if __name__ == "__main__":
    unittest.main()
