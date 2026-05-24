import unittest

from matrix_scanner.scanners.mysql import _parse_mysql_output


class MysqlScannerTests(unittest.TestCase):
    def test_parse_mysql_output(self):
        output = "\n".join(
            [
                "max_connections\t151",
                "innodb_buffer_pool_size\t134217728",
                "Threads_running\t2",
                "Slow_queries\t4",
                "Sleep\t8",
                "Query\t1",
            ]
        )

        result = _parse_mysql_output(output)

        self.assertEqual(result["max_connections"], "151")
        self.assertEqual(result["Threads_running"], "2")
        self.assertEqual(result["processlist_commands"]["Sleep"], 8)


if __name__ == "__main__":
    unittest.main()
