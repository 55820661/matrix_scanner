import os
import tempfile
import unittest

from matrix_scanner.config import load_config


class ConfigTests(unittest.TestCase):
    def test_config_loads_env_secrets_without_persisting(self):
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False, encoding="utf-8") as handle:
            handle.write("database_path: custom.sqlite3\nservices:\n  - nginx\ntelegram:\n  allowed_user_ids: [123]\n")
            config_path = handle.name
        self.addCleanup(lambda: os.path.exists(config_path) and os.unlink(config_path))
        old_token = os.environ.get("TELEGRAM_BOT_TOKEN")
        os.environ["TELEGRAM_BOT_TOKEN"] = "secret-token"
        self.addCleanup(self._restore_env, "TELEGRAM_BOT_TOKEN", old_token)

        config = load_config(config_path)

        self.assertEqual(config.telegram_bot_token, "secret-token")
        self.assertEqual(config.values["database_path"], "custom.sqlite3")
        self.assertEqual(config.values["services"], ["nginx"])
        self.assertEqual(config.values["telegram"]["allowed_user_ids"], [123])
        self.assertNotIn("secret-token", str(config.values))

    @staticmethod
    def _restore_env(key, value):
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value


if __name__ == "__main__":
    unittest.main()
