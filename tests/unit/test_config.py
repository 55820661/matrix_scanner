import os
import unittest
import tempfile

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

    def test_app_config_supports_dict_like_access(self):
        config = load_config(None)

        self.assertEqual(config.get("logs", {}), config.values["logs"])
        self.assertEqual(config["logs"], config.values["logs"])
        self.assertIn("logs", config)

    def test_load_config_normalizes_blank_scalar_lists(self):
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False, encoding="utf-8") as handle:
            handle.write(
                "logs:\n  nginx_access:\n  nginx_error:\n  max_lines:\nlaravel:\n  path:\n  log_path:\nmysql:\n  cli_path:\n  defaults_file:\n  timeout_seconds:\ntelegram:\n  default_chat_id:\n",
            )
            config_path = handle.name
        self.addCleanup(lambda: os.path.exists(config_path) and os.unlink(config_path))

        config = load_config(config_path)

        self.assertEqual(config.values["logs"]["nginx_access"], "")
        self.assertEqual(config.values["logs"]["nginx_error"], "")
        self.assertEqual(config.values["logs"]["max_lines"], 500)
        self.assertEqual(config.values["laravel"]["path"], "")
        self.assertEqual(config.values["laravel"]["log_path"], "")
        self.assertEqual(config.values["mysql"]["cli_path"], "")
        self.assertEqual(config.values["mysql"]["defaults_file"], "")
        self.assertEqual(config.values["mysql"]["timeout_seconds"], 5)
        self.assertIsNone(config.values["telegram"]["default_chat_id"])

    def test_load_config_normalizes_invalid_applications_items(self):
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False, encoding="utf-8") as handle:
            handle.write("applications:\n  []\n")
            config_path = handle.name
        self.addCleanup(lambda: os.path.exists(config_path) and os.unlink(config_path))

        config = load_config(config_path)

        self.assertEqual(config.values["applications"], [])

    def test_load_config_parses_applications_list_of_maps(self):
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False, encoding="utf-8") as handle:
            handle.write("applications:\n  - service_name: app\n    path: /home/app/public_html\n    type: laravel\n    log_path: /home/app/public_html/storage/logs\n")
            config_path = handle.name
        self.addCleanup(lambda: os.path.exists(config_path) and os.unlink(config_path))

        config = load_config(config_path)

        self.assertEqual(
            config.values["applications"],
            [{"service_name": "app", "path": "/home/app/public_html", "type": "laravel", "log_path": "/home/app/public_html/storage/logs"}],
        )

    @staticmethod
    def _restore_env(key, value):
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value


if __name__ == "__main__":
    unittest.main()
