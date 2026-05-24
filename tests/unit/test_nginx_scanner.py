import unittest
from unittest.mock import patch

from matrix_scanner.scanners.nginx import classify_nginx_error_line, summarize_nginx_error_groups
from matrix_scanner.tools.logs import get_nginx_errors


class NginxScannerTests(unittest.TestCase):
    def test_classifies_ssl_handshake_as_noise_not_app_failure(self):
        result = classify_nginx_error_line(
            "2026/05/24 10:00:00 [crit] 1#1: *1 SSL_do_handshake() failed "
            "(SSL: error:0A00006C:SSL routines::bad key share) while SSL handshaking, "
            "client: 203.0.113.10, server: example.com"
        )

        self.assertEqual(result["type"], "ssl_handshake_failure")
        self.assertEqual(result["evaluation"], "طبيعي")
        self.assertIn("لا يظهر من السطر وحده أنها مشكلة في التطبيق", result["explanation"])
        self.assertEqual(result["ip"], "203.0.113.10")
        self.assertEqual(result["server"], "example.com")

    def test_classifies_sensitive_file_probe(self):
        result = classify_nginx_error_line(
            '2026/05/24 10:00:01 [error] 1#1: *2 open() "/usr/share/nginx/html/.env" failed '
            '(2: No such file or directory), client: 198.51.100.4, server: example.com, request: "GET /.env HTTP/1.1"'
        )

        self.assertEqual(result["type"], "sensitive_file_probe")
        self.assertEqual(result["evaluation"], "مراقبة")
        self.assertEqual(result["path"], "/.env")
        self.assertIn("لا يعني اختراقًا ناجحًا", result["explanation"])

    def test_summarize_error_log_groups_similar_errors(self):
        groups = summarize_nginx_error_groups(
            [
                '2026/05/24 10:00:01 [error] 1#1: *2 open() "/usr/share/nginx/html/.env" failed (2: No such file or directory), client: 198.51.100.4, server: example.com, request: "GET /.env HTTP/1.1"',
                '2026/05/24 10:00:02 [error] 1#1: *3 open() "/usr/share/nginx/html/.env" failed (2: No such file or directory), client: 198.51.100.5, server: example.com, request: "GET /.env HTTP/1.1"',
                "2026/05/24 10:00:03 [crit] 1#1: *4 SSL_do_handshake() failed while SSL handshaking, client: 203.0.113.10, server: example.com",
            ]
        )

        probe = next(group for group in groups if group["type"] == "sensitive_file_probe")
        self.assertEqual(probe["count"], 2)
        self.assertEqual(probe["last_seen"], "2026/05/24 10:00:02")
        self.assertEqual(probe["paths"], ["/.env"])
        self.assertEqual(probe["ips"], ["198.51.100.4", "198.51.100.5"])

    def test_nginx_tool_returns_human_summary_not_raw_log_dump(self):
        grouped = {
            "status": "ok",
            "total_lines": 1,
            "recent_errors": ['open() "/usr/share/nginx/html/.env" failed'],
            "groups": [
                {
                    "type": "sensitive_file_probe",
                    "title": "Probing for sensitive files",
                    "count": 1,
                    "last_seen": "2026/05/24 10:00:01",
                    "ips": ["198.51.100.4"],
                    "server": "example.com",
                    "paths": ["/.env"],
                    "evaluation": "مراقبة",
                    "explanation": "محاولة فحص/اختراق للبحث عن ملف حساس.",
                    "suggested_action": "تأكد من حظر الوصول إلى ملفات .env والملفات الحساسة من Nginx.",
                    "examples": ['open() "/usr/share/nginx/html/.env" failed'],
                }
            ],
        }

        with patch("matrix_scanner.tools.logs.summarize_error_log", return_value=grouped):
            result = get_nginx_errors({"config": {"logs": {"nginx_error": "missing.log", "max_lines": 50}}})

        text = result["summary_text"]
        self.assertIn("Nginx error summary", text)
        self.assertIn("Probing for sensitive files", text)
        self.assertIn("محاولة فحص/اختراق", text)
        self.assertNotIn('open() "/usr/share/nginx/html/.env" failed', text)


if __name__ == "__main__":
    unittest.main()
