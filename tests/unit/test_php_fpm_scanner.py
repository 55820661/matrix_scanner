from pathlib import Path
import unittest

from matrix_scanner.scanners.php_fpm import scan_pool_configs


class PhpFpmScannerTests(unittest.TestCase):
    def test_scan_pool_config_extracts_safe_values(self):
        fixture = Path("tests/fixtures/php-fpm-pool.conf")

        result = scan_pool_configs([str(fixture)])

        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["pools"][0]["values"]["pm.max_children"], "25")
        self.assertEqual(result["pools"][0]["values"]["pm"], "dynamic")


if __name__ == "__main__":
    unittest.main()
