from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable


@dataclass(frozen=True)
class ServiceInfo:
    name: str
    description: str = ""
    active_state: str = ""
    working_directory: str = ""
    exec_start: str = ""
    user: str = ""
    environment_file: str = ""


def discover_systemd_services(limit: int = 80) -> list[ServiceInfo]:
    systemctl = shutil.which("systemctl")
    if systemctl is None:
        return []
    command = [systemctl, "list-units", "--type=service", "--all", "--no-legend", "--no-pager"]
    try:
        proc = subprocess.run(command, capture_output=True, text=True, timeout=8, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return []
    if proc.returncode != 0:
        return []

    services: list[ServiceInfo] = []
    for line in proc.stdout.splitlines():
        parts = line.split(None, 4)
        if not parts:
            continue
        name = parts[0]
        description = parts[4] if len(parts) >= 5 else ""
        active_state = parts[2] if len(parts) >= 3 else ""
        services.append(ServiceInfo(name=_strip_service_suffix(name), description=description, active_state=active_state))
    services.sort(key=lambda item: (item.active_state != "active", item.name))
    return services[:limit]


def enrich_service_metadata(service: ServiceInfo) -> ServiceInfo:
    systemctl = shutil.which("systemctl")
    if systemctl is None:
        return service
    unit = service.name if service.name.endswith(".service") else f"{service.name}.service"
    command = [
        systemctl,
        "show",
        unit,
        "--property=Description,WorkingDirectory,ExecStart,User,EnvironmentFile,ActiveState",
        "--no-pager",
    ]
    try:
        proc = subprocess.run(command, capture_output=True, text=True, timeout=5, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return service
    if proc.returncode != 0:
        return service

    values = {}
    for line in proc.stdout.splitlines():
        key, _, value = line.partition("=")
        values[key] = value
    return ServiceInfo(
        name=service.name,
        description=values.get("Description") or service.description,
        active_state=values.get("ActiveState") or service.active_state,
        working_directory=values.get("WorkingDirectory", ""),
        exec_start=values.get("ExecStart", ""),
        user=values.get("User", ""),
        environment_file=values.get("EnvironmentFile", ""),
    )


def parse_service_selection(selection: str, services: list[ServiceInfo]) -> list[str]:
    value = selection.strip()
    if not value or value.lower() == "none":
        return []
    if value.lower() == "all":
        return [service.name for service in services]

    selected: list[str] = []
    for token in value.split(","):
        item = token.strip()
        if not item:
            continue
        if item.isdigit():
            index = int(item) - 1
            if 0 <= index < len(services):
                selected.append(services[index].name)
            continue
        selected.append(_strip_service_suffix(item))
    return _dedupe(selected)


def build_config_yaml(
    *,
    services: list[str],
    database_path: str,
    nginx_access_log: str,
    nginx_error_log: str,
    app_path: str,
    app_log_path: str,
    logs_max_lines: int,
) -> str:
    lines = [
        "# Matrix Scanner config. Secrets must be provided via environment variables.",
        "",
        f"database_path: {database_path}",
        "scan_interval_minutes: 60",
        "metrics_retention_days: 14",
        "alerts_enabled: true",
        "alert_cooldown_minutes: 360",
        "telegram_enabled: false",
        "confirmation_timeout_seconds: 120",
        "",
        "laravel:",
        f"  path: {app_path}",
        f"  log_path: {app_log_path}",
        "",
    ]
    if services:
        lines.append("services:")
        lines.extend(f"  - {service}" for service in services)
    else:
        lines.append("services: []")
    lines.extend(
        [
            "",
            "logs:",
            f"  nginx_access: {nginx_access_log}",
            f"  nginx_error: {nginx_error_log}",
            f"  max_lines: {logs_max_lines}",
            "",
            "php_fpm:",
            "  service_name: php-fpm",
            "  pool_config_paths:",
            "    - /etc/php/*/fpm/pool.d/*.conf",
            "",
            "mysql:",
            "  service_name: mysql",
            "  cli_path:",
            "  defaults_file:",
            "  timeout_seconds: 5",
            "",
            "thresholds:",
            "  cpu_percent: 85",
            "  ram_percent: 85",
            "  disk_percent: 90",
            "  nginx_5xx_count: 20",
            "  laravel_error_count: 5",
            "",
            "telegram:",
            "  allowed_user_ids: []",
            "  allowed_chat_ids: []",
            "  default_chat_id:",
            "  poll_timeout_seconds: 30",
            "  poll_sleep_seconds: 1",
            "",
        ]
    )
    return "\n".join(lines)


def should_overwrite_config(path: Path, *, force: bool, confirm: Callable[[str], str]) -> bool:
    if force or not path.exists():
        return True
    answer = confirm(f"{path} already exists. Overwrite? [y/N]: ").strip().lower()
    return answer in {"y", "yes"}


def write_config(path: Path, content: str, *, force: bool = False, confirm: Callable[[str], str] = input) -> bool:
    if not should_overwrite_config(path, force=force, confirm=confirm):
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    Path("data").mkdir(exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return True


def run_interactive_setup(config_path: Path, *, force: bool = False) -> bool:
    services = discover_systemd_services()
    if services:
        print("Available systemd services:")
        for index, service in enumerate(services, start=1):
            suffix = f" - {service.description}" if service.description else ""
            state = f" [{service.active_state}]" if service.active_state else ""
            print(f"[{index}] {service.name}{state}{suffix}")
    else:
        print("No systemd services discovered. You can still enter service names manually.")

    selection = input("Select services to monitor (1,2,4 / all / none): ")
    selected = parse_service_selection(selection, services)
    manual = input("Additional service names, comma-separated (optional): ").strip()
    if manual:
        selected.extend(parse_service_selection(manual, []))
        selected = _dedupe(selected)

    enriched = [enrich_service_metadata(ServiceInfo(name=service)) for service in selected]
    suggested_app_path = _first_non_empty([service.working_directory for service in enriched], "/var/www/app")
    app_path = input(f"Laravel app path [{suggested_app_path}]: ").strip() or suggested_app_path
    app_log = input(f"Laravel log path [{app_path}/storage/logs/laravel.log]: ").strip() or f"{app_path}/storage/logs/laravel.log"
    nginx_access = input("Nginx access log [/var/log/nginx/access.log]: ").strip() or "/var/log/nginx/access.log"
    nginx_error = input("Nginx error log [/var/log/nginx/error.log]: ").strip() or "/var/log/nginx/error.log"
    database_path = input("SQLite database path [data/matrix_scanner.sqlite3]: ").strip() or "data/matrix_scanner.sqlite3"
    max_lines_text = input("Log max lines [500]: ").strip() or "500"
    try:
        max_lines = int(max_lines_text)
    except ValueError:
        max_lines = 500

    content = build_config_yaml(
        services=selected,
        database_path=database_path,
        nginx_access_log=nginx_access,
        nginx_error_log=nginx_error,
        app_path=app_path,
        app_log_path=app_log,
        logs_max_lines=max_lines,
    )
    return write_config(config_path, content, force=force)


def _strip_service_suffix(name: str) -> str:
    return name[:-8] if name.endswith(".service") else name


def _dedupe(values: list[str]) -> list[str]:
    seen = set()
    result = []
    for value in values:
        if value and value not in seen:
            seen.add(value)
            result.append(value)
    return result


def _first_non_empty(values: list[str], default: str) -> str:
    for value in values:
        if value:
            return value
    return default
