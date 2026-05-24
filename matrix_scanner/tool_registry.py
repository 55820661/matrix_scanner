from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

ToolHandler = Callable[[dict[str, Any]], dict[str, Any]]


@dataclass(frozen=True)
class ToolSpec:
    tool_key: str
    display_name: str
    description: str
    handler: ToolHandler
    handler_name: str
    type: str = "read_only"
    risk_level: str = "low"
    allowed_roles: tuple[str, ...] = ("admin",)
    output_type: str = "summary"
    max_runtime_seconds: int = 10
    max_output_chars: int = 3500
    allowed_modes: tuple[str, ...] = ("read_only", "diagnostic")
    enabled: bool = True
    requires_confirmation: bool = False


def build_registry() -> dict[str, ToolSpec]:
    from matrix_scanner.tools.disk import get_disk
    from matrix_scanner.tools.incident import (
        apache_5xx_summary,
        apache_error_summary,
        laravel_env_sanity,
        laravel_exception_summary,
        laravel_log_health,
        queue_workers_summary,
        supervisor_summary,
        suspicious_cron_scan,
        suspicious_files_scan,
        top_processes,
    )
    from matrix_scanner.tools.logs import get_laravel_errors, get_nginx_errors
    from matrix_scanner.tools.performance import server_performance
    from matrix_scanner.tools.report import generate_report
    from matrix_scanner.tools.services import get_services
    from matrix_scanner.tools.status import get_status

    specs = [
        ToolSpec("get_status", "Status", "General server status.", get_status, "get_status"),
        ToolSpec("server_performance", "Server Performance", "Aggregated server performance summary.", server_performance, "server_performance"),
        ToolSpec("get_disk", "Disk", "Disk usage summary.", get_disk, "get_disk"),
        ToolSpec("get_services", "Services", "Configured service status.", get_services, "get_services"),
        ToolSpec("get_nginx_errors", "Nginx Errors", "Nginx error summary.", get_nginx_errors, "get_nginx_errors", type="diagnostic"),
        ToolSpec("get_laravel_errors", "Laravel Errors", "Laravel error summary.", get_laravel_errors, "get_laravel_errors", type="diagnostic"),
        ToolSpec("generate_report", "Full Report", "Full diagnostic report.", generate_report, "generate_report", type="diagnostic", output_type="report", max_output_chars=8000),
        ToolSpec("top_processes", "Top Processes", "Top CPU/RAM processes.", top_processes, "top_processes"),
        ToolSpec("apache_error_summary", "Apache Error Summary", "Apache error log classifier.", apache_error_summary, "apache_error_summary"),
        ToolSpec("apache_5xx_summary", "Apache 5xx Summary", "Apache 5xx response summary.", apache_5xx_summary, "apache_5xx_summary"),
        ToolSpec("laravel_log_health", "Laravel Log Health", "Laravel log size and rotation health.", laravel_log_health, "laravel_log_health"),
        ToolSpec("laravel_env_sanity", "Laravel Env Sanity", "Safe Laravel .env production sanity checks.", laravel_env_sanity, "laravel_env_sanity"),
        ToolSpec("laravel_exception_summary", "Laravel Exception Summary", "Laravel exception classifier.", laravel_exception_summary, "laravel_exception_summary"),
        ToolSpec("queue_workers_summary", "Queue Workers Summary", "Read-only queue worker process summary.", queue_workers_summary, "queue_workers_summary"),
        ToolSpec("supervisor_summary", "Supervisor Summary", "Supervisor status and config summary.", supervisor_summary, "supervisor_summary"),
        ToolSpec("suspicious_cron_scan", "Suspicious Cron Scan", "Read-only suspicious cron scan.", suspicious_cron_scan, "suspicious_cron_scan"),
        ToolSpec("suspicious_files_scan", "Suspicious Files Scan", "Read-only suspicious hidden files scan.", suspicious_files_scan, "suspicious_files_scan"),
    ]
    return {spec.tool_key: spec for spec in specs}
