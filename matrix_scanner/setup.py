from __future__ import annotations

import re
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
    "ufw",
    "qemu-guest-agent",
}

CORE_SERVICE_NAMES = {
    "mysqld",
    "mariadb",
    "mysql",
    "crond",
    "sshd",
    "httpd",
    "nginx",
    "supervisord",
    "queueprocd",
}

IMPORTANT_SERVICE_NAMES = {
    "nginx",
    "apache2",
    "httpd",
    "mysqld",
    "mysql",
    "mariadb",
    "crond",
    "sshd",
    "queueprocd",
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

PROCESS_SERVICE_TOKENS = {
    "mysqld": ("mysqld",),
    "mariadb": ("mariadbd", "mysqld"),
    "mysql": ("mysqld", "mariadbd"),
    "crond": ("crond",),
    "sshd": ("sshd",),
    "httpd": ("httpd", "apache2"),
    "nginx": ("nginx",),
    "supervisord": ("supervisord",),
    "queueprocd": ("queueprocd",),
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


def discover_critical_services() -> list[ServiceInfo]:
    services: list[ServiceInfo] = []
    process_text = _process_list_text()
    for name in sorted(CORE_SERVICE_NAMES):
        state = _systemd_active_state(name)
        if state == "active":
            services.append(ServiceInfo(name=name, description="Core service", active_state="active"))
            continue
        if _process_matches_service(name, process_text):
            services.append(ServiceInfo(name=name, description="Core service detected from process list", active_state="active"))
    return services


def _systemd_active_state(name: str) -> str:
    systemctl = shutil.which("systemctl")
    if systemctl is None:
        return ""
    try:
        proc = subprocess.run([systemctl, "is-active", name], capture_output=True, text=True, timeout=3, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return proc.stdout.strip() if proc.returncode == 0 else ""


def _process_list_text() -> str:
    ps = shutil.which("ps")
    if ps is None:
        return ""
    try:
        proc = subprocess.run([ps, "-eo", "comm,args"], capture_output=True, text=True, timeout=4, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return proc.stdout if proc.returncode == 0 else ""


def _process_matches_service(name: str, process_text: str) -> bool:
    if not process_text:
        return False
    tokens = PROCESS_SERVICE_TOKENS.get(name, (name,))
    return any(re.search(rf"(^|\s|/){re.escape(token)}(\s|$)", process_text, re.MULTILINE) for token in tokens)


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
    apache_error_log: str = "",
    apache_domlogs_dir: str = "",
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
        "incident_alerts_enabled: true",
        "telegram_enabled: false",
        "confirmation_timeout_seconds: 120",
        "",
    ]
    if applications:
        lines.append("applications:")
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
        lines.append("applications: []")
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
            "apache:",
            "  error_logs:",
            f"    - {apache_error_log}",
            "  domlogs:",
            f"    - {apache_domlogs_dir}",
            "  access_logs:",
            f"    - {apache_domlogs_dir}",
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


def detect_applications(services: list[ServiceInfo], *, include_cpanel: bool = False, cpanel_home: str = "/home") -> list[ApplicationInfo]:
    applications: list[ApplicationInfo] = []
    for service in services:
        if not service.working_directory:
            continue
        path = service.working_directory
        app_type = detect_application_type(service, Path(path))
        log_path = detect_application_log_path(app_type, Path(path))
        applications.append(ApplicationInfo(service_name=service.name, path=path, type=app_type, log_path=log_path))
    if include_cpanel:
        applications.extend(discover_cpanel_laravel_apps(cpanel_home))
    return _dedupe_applications(applications)


def discover_cpanel_laravel_apps(base: str = "/home") -> list[ApplicationInfo]:
    home = Path(base)
    if not home.exists():
        return []
    candidates = []
    for pattern in ("*/public_html", "*/public_html/*", "*/public_html/public/*"):
        candidates.extend(home.glob(pattern))
    applications = []
    for path in candidates:
        if is_laravel_app_path(path):
            service_name = f"detected-{path.parts[2] if len(path.parts) > 2 else path.name}-{path.name}".replace("_", "-")
            applications.append(ApplicationInfo(service_name=service_name, path=str(path), type="laravel", log_path=detect_application_log_path("laravel", path)))
    return _dedupe_applications(applications)


def is_laravel_app_path(path: Path) -> bool:
    return (path / "artisan").exists() and (path / ".env").exists() and (path / "storage" / "logs").exists()


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
    log_dir = app_path / "storage" / "logs"
    if not log_dir.exists():
        return ""
    return str(log_dir)


def run_interactive_setup(
    config_path: Path,
    *,
    force: bool = False,
    all_services: bool = False,
    include_inactive: bool = False,
    input_func: Callable[[str], str] = input,
) -> bool:
    discovered = _merge_services(discover_systemd_services(), discover_critical_services())
    enriched_discovered = [enrich_service_metadata(service) for service in discovered]
    services = filter_setup_services(enriched_discovered, all_services=all_services, include_inactive=include_inactive)
    if services:
        print("All systemd services:" if all_services else "Candidate services:")
        for index, service in enumerate(services, start=1):
            suffix = f" - {service.description}" if service.description else ""
            state = f" [{service.active_state}]" if service.active_state else ""
            print(f"[{index}] {service.name}{state}{suffix}")
    else:
        print("No candidate services discovered.")

    selected = prompt_service_selection(input_func, services)

    enriched = [enrich_service_metadata(ServiceInfo(name=service)) for service in selected]
    applications = detect_applications(enriched, include_cpanel=True)
    nginx_access = detect_nginx_log_path("/var/log/nginx/access.log")
    nginx_error = detect_nginx_log_path("/var/log/nginx/error.log")
    apache_error = detect_existing_path("/etc/apache2/logs/error_log") or detect_existing_path("/usr/local/apache/logs/error_log") or detect_existing_path("/var/log/httpd/error_log")
    apache_domlogs = detect_existing_path("/etc/apache2/logs/domlogs") or detect_existing_path("/usr/local/apache/domlogs")
    database_path = "data/matrix_scanner.sqlite3"
    max_lines = 500

    content = build_config_yaml(
        services=selected,
        applications=applications,
        database_path=database_path,
        nginx_access_log=nginx_access,
        nginx_error_log=nginx_error,
        logs_max_lines=max_lines,
        apache_error_log=apache_error,
        apache_domlogs_dir=apache_domlogs,
    )
    return write_config(config_path, content, force=force, confirm=input_func)


def detect_existing_path(path: str) -> str:
    return path if Path(path).exists() else ""


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


def _merge_services(*groups: list[ServiceInfo]) -> list[ServiceInfo]:
    merged: dict[str, ServiceInfo] = {}
    for group in groups:
        for service in group:
            existing = merged.get(service.name)
            if existing is None or (existing.active_state != "active" and service.active_state == "active"):
                merged[service.name] = service
    return sorted(merged.values(), key=lambda item: (item.active_state != "active", item.name))


def _dedupe_applications(applications: list[ApplicationInfo]) -> list[ApplicationInfo]:
    seen = set()
    result = []
    for app in applications:
        if app.path in seen:
            continue
        seen.add(app.path)
        result.append(app)
    return result
