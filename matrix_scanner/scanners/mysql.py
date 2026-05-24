from __future__ import annotations

import shutil
import subprocess

from matrix_scanner.scanners.services import service_status


STATUS_QUERY = """
SHOW GLOBAL VARIABLES WHERE Variable_name IN ('max_connections', 'innodb_buffer_pool_size');
SHOW GLOBAL STATUS WHERE Variable_name IN ('Threads_running', 'Slow_queries');
SELECT COMMAND, COUNT(*) FROM information_schema.PROCESSLIST GROUP BY COMMAND;
"""


def scan_mysql(service_name: str = "mysql", cli_path: str | None = None, defaults_file: str | None = None, timeout: int = 5) -> dict:
    return {
        "service": service_status(service_name),
        "status": mysql_status(cli_path=cli_path, defaults_file=defaults_file, timeout=timeout),
    }


def mysql_status(cli_path: str | None = None, defaults_file: str | None = None, timeout: int = 5) -> dict:
    mysql = cli_path or shutil.which("mysql")
    if mysql is None:
        return {"status": "unavailable", "reason": "mysql_cli_not_found"}

    command = [mysql]
    if defaults_file:
        command.append(f"--defaults-extra-file={defaults_file}")
    command.extend(["--batch", "--raw", "--skip-column-names", "-e", STATUS_QUERY])

    try:
        proc = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"status": "unavailable", "reason": str(exc)}

    if proc.returncode != 0:
        return {"status": "unavailable", "reason": "mysql_cli_failed", "stderr": _safe_stderr(proc.stderr)}

    return {"status": "ok", "values": _parse_mysql_output(proc.stdout)}


def _parse_mysql_output(output: str) -> dict:
    values: dict[str, str | dict[str, int]] = {"processlist_commands": {}}
    for line in output.splitlines():
        parts = line.split("\t")
        if len(parts) != 2:
            continue
        key, value = parts
        if key in {"Sleep", "Query", "Connect", "Binlog Dump", "Daemon"}:
            try:
                values["processlist_commands"][key] = int(value)  # type: ignore[index]
            except ValueError:
                values["processlist_commands"][key] = 0  # type: ignore[index]
        else:
            values[key] = value
    return values


def _safe_stderr(stderr: str) -> str:
    lowered = stderr.lower()
    if "password" in lowered or "access denied" in lowered:
        return "mysql authentication failed"
    return stderr.strip()[:500]
