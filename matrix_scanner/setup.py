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


@dataclass(frozen=True)
class ApplicationInfo:
    service_name: str
    path: str
    type: str = "unknown"
    log_path: str = ""


class InvalidServiceSelection(ValueError):
    """Raised when setup service selection is not all/none/numeric."""


EXCLUDED_SERVICE_PREFIXES = (
    "systemd-",
    "user@",
    "user-runtime-dir@",
    "getty",
    "apt-",
    "initrd-",
    "modprobe@",
    "e2scrub",
    "keyboard-setup",
    "console-setup",
    "ifupdown-pre",
)

EXCLUDED_SERVICE_NAMES = {
    "dpkg-db-backup",
    "networking",
    "dbus",
    "cron",
    "ssh",
    "ufw",
    "qemu-guest-agent",
}

IMPORTANT_SERVICE_NAMES = {
    "nginx",
    "apache2",
    "httpd",
    "mysql",
    "mariadb",
    "postgresql",
    "redis",
    "php-fpm",
    "php8.3-fpm",
    "php8.2-fpm",
    "php8.1-fpm",
    "supervisor",
    "supervisord",
    "docker",
}

APP_EXEC_TOKENS = (
    "gunicorn",
    "uvicorn",
    "node",
    "npm",
    "yarn",
    "pnpm",
    "python",
    "php-fpm",
    "artisan",
    "docker",
    "docker-compose",
    "java",
    "dotnet",
    "celery",
    "rq",
    "worker",
)


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


def filter_setup_services(
    services: list[ServiceInfo],
    *,
    all_services: bool = False,
    include_inactive: bool = False,
) -> list[ServiceInfo]:
    if all_services:
        return services
    filtered = services if include_inactive else [service for service in services if service.active_state in {"", "active"}]
    return [service for service in filtered if is_candidate_application_service(service)]


def is_candidate_application_service(service: ServiceInfo) -> bool:
    name = service.name
    if any(name.startswith(prefix) for prefix in EXCLUDED_SERVICE_PREFIXES):
        return False
    if name in EXCLUDED_SERVICE_NAMES:
        return False
    if name in IMPORTANT_SERVICE_NAMES:
        return True
    if service.working_directory:
        return True
    exec_start = service.exec_start.lower()
    if any(token in exec_start for token in APP_EXEC_TOKENS):
        return True
    description = service.description.lower()
    if any(token in description for token in ("application", "web server", "database", "queue", "worker")):
        return True
    return False


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
            raise InvalidServiceSelection("empty selection item")
        if not item.isdigit():
            raise InvalidServiceSelection("service names are not accepted")
        index = int(item) - 1
        if not 0 <= index < len(services):
            raise InvalidServiceSelection("selection index out of range")
        selected.append(services[index].name)
    return _dedupe(selected)


def prompt_service_selection(input_func: Callable[[str], str], services: list[ServiceInfo]) -> list[str]:
    while True:
        selection = input_func("Select services to monitor (1,2,4 / all / none): ")
        try:
            return parse_service_selection(selection, services)
        except InvalidServiceSelection:
            print("Invalid selection. Please enter numbers only, all, or none.")


def build_config_yaml(
    *,
    services: list[str],
    applications: list[ApplicationInfo] | None = None,
    database_path: str,
    nginx_access_log: str,
    nginx_error_log: str,
    logs_max_lines: int,
) -> str:
    applications = applications or []
    laravel_app = next((app for app in applications if app.type == "laravel"), None)
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
        "applications:",
    ]
    if applications:
        for app in applications:
            lines.extend(
                [
                    f"  - service_name: {app.service_name}",
                    f"    path: {app.path}",
                    f"    type: {app.type}",
                    f"    log_path: {app.log_path}",
                ]
            )
    else:
        lines.append("  []")
    lines.extend(
        [
            "",
            "# Kept for backwards compatibility with current Laravel scanner.",
            "# New setup data is written under applications above.",
        "laravel:",
            f"  path: {laravel_app.path if laravel_app else ''}",
            f"  log_path: {laravel_app.log_path if laravel_app else ''}",
        "",
        ]
    )
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


def detect_nginx_log_path(path: str) -> str:
    return path if Path(path).exists() else ""


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
    temp_path = path.with_name(f".{path.name}.tmp")
    temp_path.write_text(content, encoding="utf-8")
    temp_path.replace(path)
    return True


def detect_applications(services: list[ServiceInfo]) -> list[ApplicationInfo]:
    applications: list[ApplicationInfo] = []
    for service in services:
        if not service.working_directory:
            continue
        path = service.working_directory
        app_type = detect_application_type(service, Path(path))
        log_path = detect_application_log_path(app_type, Path(path))
        applications.append(ApplicationInfo(service_name=service.name, path=path, type=app_type, log_path=log_path))
    return applications


def detect_application_type(service: ServiceInfo, app_path: Path) -> str:
    if (app_path / "artisan").exists():
        return "laravel"
    exec_start = service.exec_start.lower()
    if "gunicorn" in exec_start or "uwsgi" in exec_start or "django" in exec_start:
        return "django"
    if "node" in exec_start or "npm" in exec_start or "yarn" in exec_start or "pnpm" in exec_start:
        return "node"
    return "unknown"


def detect_application_log_path(app_type: str, app_path: Path) -> str:
    if app_type != "laravel":
        return ""
    laravel_log = app_path / "storage" / "logs" / "laravel.log"
    return str(laravel_log) if laravel_log.exists() else ""


def run_interactive_setup(
    config_path: Path,
    *,
    force: bool = False,
    all_services: bool = False,
    include_inactive: bool = False,
    input_func: Callable[[str], str] = input,
) -> bool:
    discovered = discover_systemd_services()
    enriched_discovered = [enrich_service_metadata(service) for service in discovered]
    services = filter_setup_services(enriched_discovered, all_services=all_services, include_inactive=include_inactive)
    if services:
        print("All systemd services:" if all_services else "Candidate application services:")
        for index, service in enumerate(services, start=1):
            suffix = f" - {service.description}" if service.description else ""
            state = f" [{service.active_state}]" if service.active_state else ""
            print(f"[{index}] {service.name}{state}{suffix}")
    else:
        print("No candidate services discovered.")

    selected = prompt_service_selection(input_func, services)

    enriched = [enrich_service_metadata(ServiceInfo(name=service)) for service in selected]
    applications = detect_applications(enriched)
    nginx_access = detect_nginx_log_path("/var/log/nginx/access.log")
    nginx_error = detect_nginx_log_path("/var/log/nginx/error.log")
    database_path = "data/matrix_scanner.sqlite3"
    max_lines = 500

    content = build_config_yaml(
        services=selected,
        applications=applications,
        database_path=database_path,
        nginx_access_log=nginx_access,
        nginx_error_log=nginx_error,
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
