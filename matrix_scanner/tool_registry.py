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
    ]
    return {spec.tool_key: spec for spec in specs}
