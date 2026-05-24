from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from matrix_scanner import db
from matrix_scanner.alerts.cooldown import filter_alerts_for_cooldown
from matrix_scanner.alerts.notifier import notify_alerts
from matrix_scanner.alerts.rules import evaluate_alerts
from matrix_scanner.scanners.laravel import scan_laravel
from matrix_scanner.scanners.mysql import scan_mysql
from matrix_scanner.scanners.nginx import scan_nginx
from matrix_scanner.scanners.php_fpm import scan_php_fpm
from matrix_scanner.scanners.services import scan_services
from matrix_scanner.scanners.system import scan_system


def run_scan(conn, config: dict[str, Any], *, telegram_token: str | None = None, alert_send_func=None) -> dict[str, Any]:
    started = datetime.now(timezone.utc)
    raw = collect_scan(config)
    summary = {
        "cpu_percent": raw.get("system", {}).get("cpu_percent"),
        "ram_percent": raw.get("system", {}).get("ram", {}).get("used_percent"),
        "disk_percent": raw.get("system", {}).get("disk", {}).get("used_percent"),
        "services": {k: v.get("status") for k, v in raw.get("services", {}).items()},
    }
    alerts = evaluate_alerts(raw, config.get("thresholds", {}))
    alerts_to_store = filter_alerts_for_cooldown(conn, alerts, int(config.get("alert_cooldown_minutes", 360))) if config.get("alerts_enabled", True) else []
    finished = datetime.now(timezone.utc)
    scan_id = db.insert_scan_result(
        conn,
        started_at=started.isoformat(),
        finished_at=finished.isoformat(),
        status="completed",
        summary=summary,
        raw_result=raw,
    )
    db.insert_alerts(conn, scan_id, alerts_to_store)
    notification = notify_alerts(alerts_to_store, config, telegram_token, alert_send_func) if alert_send_func else notify_alerts(alerts_to_store, config, telegram_token)
    return {"scan_id": scan_id, "summary": summary, "raw": raw, "alerts": alerts_to_store, "notification": notification}


def collect_scan(config: dict[str, Any]) -> dict[str, Any]:
    logs = config.get("logs", {})
    laravel = config.get("laravel", {})
    php_fpm = config.get("php_fpm", {})
    mysql = config.get("mysql", {})
    max_lines = int(logs.get("max_lines", 500))
    return {
        "system": scan_system(),
        "services": scan_services(config.get("services", [])),
        "nginx": scan_nginx(logs.get("nginx_access", ""), logs.get("nginx_error", ""), max_lines),
        "php_fpm": scan_php_fpm(php_fpm.get("service_name", "php-fpm"), php_fpm.get("pool_config_paths", [])),
        "mysql": scan_mysql(
            mysql.get("service_name", "mysql"),
            mysql.get("cli_path"),
            mysql.get("defaults_file"),
            int(mysql.get("timeout_seconds", 5)),
        ),
        "laravel": scan_laravel_if_configured(laravel, max_lines),
    }


def as_non_empty_str(value: Any) -> str:
    return value.strip() if isinstance(value, str) and value.strip() else ""


def scan_laravel_if_configured(laravel: Any, max_lines: int) -> dict[str, Any]:
    if not isinstance(laravel, dict):
        return {"enabled": False, "reason": "No Laravel log path configured"}
    project_path = as_non_empty_str(laravel.get("path"))
    log_path = as_non_empty_str(laravel.get("log_path"))
    if not project_path or not log_path:
        return {"enabled": False, "reason": "No Laravel log path configured"}
    return scan_laravel(log_path, project_path, max_lines)
