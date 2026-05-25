from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from matrix_scanner.security import redact, truncate_text

SAFE_ENV_KEYS = {"APP_ENV", "APP_DEBUG", "LOG_CHANNEL", "LOG_LEVEL", "QUEUE_CONNECTION", "CACHE_DRIVER", "SESSION_DRIVER"}
APACHE_ERROR_DEFAULTS = ["/etc/apache2/logs/error_log", "/usr/local/apache/logs/error_log", "/var/log/apache2/error.log", "/var/log/httpd/error_log"]
APACHE_ACCESS_DEFAULTS = ["/etc/apache2/logs/domlogs", "/usr/local/apache/domlogs", "/var/log/apache2/access.log", "/var/log/httpd/access_log"]
SUSPICIOUS_FILE_PATTERNS = ["/usr/share/man/*/.*", "/tmp/.*", "/var/tmp/.*", "/dev/shm/.*"]


def top_processes(limit: int = 10) -> dict[str, Any]:
    if not shutil.which("ps"):
        return {"status": "unavailable", "reason": "ps_not_found", "rows": []}
    try:
        proc = subprocess.run(["ps", "axo", "pid,user,pcpu,pmem,comm,args", "--sort=-pcpu"], capture_output=True, text=True, timeout=5, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"status": "unavailable", "reason": str(exc), "rows": []}
    rows = []
    for line in proc.stdout.splitlines()[1:limit + 1]:
        parts = line.split(None, 5)
        if len(parts) < 6:
            continue
        rows.append({"pid": parts[0], "user": parts[1], "cpu_percent": parts[2], "ram_percent": parts[3], "command": parts[4], "args": truncate_text(redact(parts[5]), 160)})
    return {"status": "ok", "rows": rows}


def apache_error_summary(paths: list[str] | None = None, max_lines: int = 500, now: datetime | None = None) -> dict[str, Any]:
    now = now or datetime.now(timezone.utc)
    lines = _read_many_logs_with_sources(paths or APACHE_ERROR_DEFAULTS, max_lines)
    groups: dict[str, dict[str, Any]] = {}
    for source, line in lines:
        item = classify_apache_error(line)
        seen_at = item["seen_at"]
        group = groups.setdefault(item["type"], {**{k: item[k] for k in ("type", "title", "explanation", "suggested_action")}, "count": 0, "latest_timestamp": "", "_latest_dt": None, "recent_1h_count": 0, "recent_24h_count": 0, "client_ips": Counter(), "paths": Counter(), "referers": Counter(), "log_files": Counter(), "examples": []})
        group["count"] += 1
        if seen_at:
            if group["_latest_dt"] is None or seen_at > group["_latest_dt"]:
                group["_latest_dt"] = seen_at
                group["latest_timestamp"] = _format_dt(seen_at)
            if seen_at >= now - timedelta(hours=1):
                group["recent_1h_count"] += 1
            if seen_at >= now - timedelta(hours=24):
                group["recent_24h_count"] += 1
        if item["client_ip"]:
            group["client_ips"][item["client_ip"]] += 1
        if item["path"]:
            group["paths"][item["path"]] += 1
        if item["referer"]:
            group["referers"][item["referer"]] += 1
        group["log_files"][source] += 1
        if len(group["examples"]) < 2:
            group["examples"].append(item["example"])
    rows = []
    for group in groups.values():
        latest = group.pop("_latest_dt", None)
        evaluation, message = _activity_evaluation(group["count"], group["recent_1h_count"], latest, now, base=group["type"])
        rows.append({
            **group,
            "last_seen": group["latest_timestamp"],
            "evaluation": evaluation,
            "message": message,
            "sample_client_ip": _first_counter_key(group["client_ips"]),
            "sample_path": _first_counter_key(group["paths"]),
            "sample_referer": _first_counter_key(group["referers"]),
            "client_ips": dict(group["client_ips"].most_common(5)),
            "paths": dict(group["paths"].most_common(5)),
            "referers": dict(group["referers"].most_common(3)),
            "log_files": dict(group["log_files"].most_common(5)),
        })
    return {"status": "ok", "total_lines": len(lines), "groups": sorted(rows, key=lambda row: row["count"], reverse=True)}


def classify_apache_error(line: str) -> dict[str, str]:
    lower = line.lower()
    if "ah01075" in lower or "proxy_fcgi:error" in lower:
        base = _class("proxy_fcgi_timeout", "Apache proxy_fcgi timeout", "تحذير", "Apache/PHP-FPM request timeout أو backend لم يرد في الوقت المناسب.", "راجع PHP-FPM وطلبات Laravel البطيئة.")
    elif "timeout" in lower:
        base = _class("timeout", "Apache timeout", "تحذير", "طلب أو backend تجاوز وقت الانتظار.", "راجع endpoints البطيئة والموارد.")
    elif "permission denied" in lower:
        base = _class("permission_denied", "Apache permission denied", "تحذير", "Apache لا يملك صلاحية الوصول لملف أو مجلد.", "راجع ownership/permissions للمسار المذكور.")
    elif "client denied" in lower:
        base = _class("client_denied", "Apache client denied", "مراقبة", "طلب تم رفضه بقواعد access control.", "راجع القاعدة إذا كان الرفض غير متوقع.")
    else:
        base = _class("other_apache_error", "Other Apache errors", "مراقبة", "أخطاء Apache غير مصنفة.", "راجع الأمثلة المختصرة عند التكرار.")
    timestamp = _extract_apache_time(line)
    return {
        **base,
        "timestamp": timestamp,
        "seen_at": _parse_apache_datetime(timestamp),
        "client_ip": _extract_client_ip(line),
        "path": _extract_request_path(line),
        "referer": _extract_referer(line),
        "example": truncate_text(redact(line.strip()), 220),
    }


def apache_5xx_summary(paths: list[str] | None = None, max_lines: int = 1000, now: datetime | None = None) -> dict[str, Any]:
    now = now or datetime.now(timezone.utc)
    effective_max_lines = max(max_lines, 5000)
    lines = _read_many_logs_with_sources(paths or APACHE_ACCESS_DEFAULTS, effective_max_lines)
    groups: dict[tuple[str, str, str], dict[str, Any]] = {}
    for source, line in lines:
        item = _parse_access_5xx(line)
        if not item:
            continue
        domain = _domain_from_log_source(source)
        key = (item["status"], item["endpoint"], domain)
        group = groups.setdefault(key, {"status": item["status"], "endpoint": item["endpoint"], "domain": domain, "log_file": source, "source": Path(source).name, "count": 0, "latest_timestamp": "", "_latest_dt": None, "recent_1h_count": 0, "recent_24h_count": 0, "ips": Counter(), "user_agents": Counter(), "sample_full_path": ""})
        group["count"] += 1
        seen_at = item.get("seen_at")
        if seen_at:
            if group["_latest_dt"] is None or seen_at > group["_latest_dt"]:
                group["_latest_dt"] = seen_at
                group["latest_timestamp"] = _format_dt(seen_at)
            if seen_at >= now - timedelta(hours=1):
                group["recent_1h_count"] += 1
            if seen_at >= now - timedelta(hours=24):
                group["recent_24h_count"] += 1
        group["sample_full_path"] = group["sample_full_path"] or item["full_path"]
        group["ips"][item["ip"]] += 1
        if item["user_agent"]:
            group["user_agents"][item["user_agent"]] += 1
    rows = []
    for group in groups.values():
        latest = group.pop("_latest_dt", None)
        evaluation, message = _activity_evaluation(group["count"], group["recent_1h_count"], latest, now, base="apache_5xx")
        rows.append({**group, "evaluation": evaluation, "message": message, "ips": dict(group["ips"].most_common(5)), "user_agents": dict(group["user_agents"].most_common(3)), "sample_user_agent": _first_counter_key(group["user_agents"])})
    return {"status": "ok", "rows": sorted(rows, key=lambda row: row["count"], reverse=True)}


def laravel_log_health(config: dict[str, Any]) -> dict[str, Any]:
    rows = []
    apps = _application_paths(config)
    if not apps:
        return {"status": "ok", "rows": [], "message": "No Laravel applications configured.", "suggested_action": "أضف التطبيقات إلى applications أو laravel.path في config.yaml."}
    for app in apps:
        log_dir = Path(app["path"]) / "storage" / "logs"
        logs = list(log_dir.glob("*.log")) if log_dir.exists() else []
        total_size = sum(path.stat().st_size for path in logs if path.exists())
        largest = max(logs, key=lambda path: path.stat().st_size, default=None)
        rows.append({
            "service_name": app.get("service_name", ""),
            "path": str(app["path"]),
            "log_dir": str(log_dir),
            "exists": log_dir.exists(),
            "log_count": len(logs),
            "total_size_bytes": total_size,
            "largest_log": str(largest) if largest else "",
            "largest_size_bytes": largest.stat().st_size if largest else 0,
            "uses_daily_logs": any(re.search(r"laravel-\d{4}-\d{2}-\d{2}\.log$", path.name) for path in logs),
            "last_modified": _mtime(max(logs, key=lambda path: path.stat().st_mtime, default=None)),
        })
    return {"status": "ok", "rows": rows, "suggested_action": "في الإنتاج يفضل daily logs مع LOG_LEVEL=warning أو error حسب الحاجة، بدون تعديل تلقائي."}


def laravel_env_sanity(config: dict[str, Any]) -> dict[str, Any]:
    rows = []
    apps = _application_paths(config)
    if not apps:
        return {"status": "ok", "rows": [], "message": "No Laravel applications configured."}
    for app in apps:
        env_path = Path(app["path"]) / ".env"
        values = _read_safe_env(env_path)
        issues = []
        if values.get("APP_ENV") == "production" and values.get("APP_DEBUG", "").lower() == "true":
            issues.append("APP_DEBUG=true في production")
        if values.get("LOG_CHANNEL") in {"single", "stack"} and values.get("APP_ENV") == "production":
            issues.append("LOG_CHANNEL قد ينتج ملفًا ضخمًا في production")
        if values.get("LOG_LEVEL", "").lower() in {"debug", "info"} and values.get("APP_ENV") == "production":
            issues.append("LOG_LEVEL تفصيلي للإنتاج")
        rows.append({"path": str(app["path"]), "env_exists": env_path.exists(), "values": values, "evaluation": "تحذير" if issues else "جيد", "issues": issues})
    return {"status": "ok", "rows": rows}


def laravel_exception_summary(config: dict[str, Any], max_lines: int = 500) -> dict[str, Any]:
    groups: dict[str, dict[str, Any]] = {}
    log_paths = _laravel_log_paths_with_apps(config)
    if not log_paths:
        return {"status": "ok", "groups": [], "message": "No Laravel log paths configured."}
    for item in log_paths:
        app_path = item["app_path"]
        log_path = item["log_path"]
        for event in _laravel_log_events(_tail_lines(log_path, max_lines)):
            finding = classify_laravel_exception(event)
            if not finding:
                continue
            group = groups.setdefault(finding["type"], {**finding, "count": 0, "app_paths": Counter()})
            group["count"] += 1
            group["app_paths"][app_path] += 1
            group["latest_timestamp"] = finding["latest_timestamp"] or group.get("latest_timestamp", "")
            if finding.get("example"):
                group["sample_message"] = group.get("sample_message") or finding["example"]
    rows = []
    for group in groups.values():
        rows.append({**group, "affected_app_paths": dict(group["app_paths"].most_common(5))})
    return {"status": "ok", "groups": sorted(rows, key=lambda row: row["count"], reverse=True)}


def classify_laravel_exception(line: str) -> dict[str, str] | None:
    lower = line.lower()
    if "jwt" in lower and ("invalid" in lower or "bearer null" in lower):
        return _exception("jwt_invalid_token", "JWT invalid token / Bearer null", line, "طلبات بتوكن ناقص أو غير صالح.", "راجع clients التي ترسل Authorization header.")
    if "deadlock" in lower:
        return _exception("sql_deadlock", "SQL deadlock", line, "تنازع معاملات قاعدة البيانات غالبًا بسبب workers متوازية أو queries طويلة.", "راجع queue workers والمعاملات المتكررة.")
    if "unknown column" in lower:
        return _exception("unknown_column", "Unknown column", line, "الكود يتوقع عمودًا غير موجود في قاعدة البيانات.", "راجع migrations والإصدار المنشور.")
    if "queryexception" in lower:
        return _exception("query_exception", "Laravel QueryException", line, "استثناء قاعدة بيانات من Laravel.", "راجع الاستعلام والـ stack المختصر في logs.")
    if "oauthserverexception" in lower:
        return _exception("oauth_exception", "OAuthServerException", line, "مشكلة في OAuth/token validation.", "راجع إعدادات OAuth والطلبات الفاشلة.")
    return None


def queue_workers_summary() -> dict[str, Any]:
    processes = top_processes(200).get("rows", [])
    workers = []
    per_path = defaultdict(int)
    for proc in processes:
        args = proc.get("args", "")
        if "artisan" in args and "queue:work" in args:
            path = _extract_cwd_from_args(args)
            connection = _extract_queue_connection(args)
            source = _worker_source(args)
            workers.append({"pid": proc["pid"], "user": proc["user"], "path": path, "queue_connection": connection, "source": source, "args": args})
            per_path[(path, connection)] += 1
    warnings = []
    groups = []
    for (path, conn), count in sorted(per_path.items()):
        users = sorted({worker["user"] for worker in workers if worker["path"] == path and worker["queue_connection"] == conn})
        groups.append({"path": path, "queue_connection": conn, "count": count, "users": users})
        if conn == "database" and count > 1:
            warnings.append(f"Multiple workers on database queue for application {path}")
        if path.startswith("/home/") and "root" in users:
            warnings.append(f"Queue worker is running as root for cPanel application {path}")
    return {"status": "ok", "workers": workers, "groups": groups, "warnings": warnings, "evaluation": "تحذير" if warnings else "جيد"}


def supervisor_summary(paths: list[str] | None = None) -> dict[str, Any]:
    status_rows = []
    if shutil.which("supervisorctl"):
        try:
            proc = subprocess.run(["supervisorctl", "status"], capture_output=True, text=True, timeout=5, check=False)
            for line in proc.stdout.splitlines():
                parts = line.split(None, 2)
                if len(parts) >= 2:
                    status_rows.append({"program": parts[0], "status": parts[1], "detail": parts[2] if len(parts) > 2 else ""})
        except (OSError, subprocess.TimeoutExpired):
            pass
    configs = []
    for pattern in paths or ["/etc/supervisord.d/*.conf", "/etc/supervisor/conf.d/*.conf"]:
        for path in Path("/").glob(pattern.lstrip("/")) if pattern.startswith("/") else Path().glob(pattern):
            configs.extend(_parse_supervisor_conf(path))
    return {"status": "ok", "programs": status_rows, "configs": configs, "available": bool(status_rows or configs)}


def suspicious_cron_scan(paths: list[str] | None = None) -> dict[str, Any]:
    entries = []
    cron_paths = paths or ["/var/spool/cron/root", "/var/spool/cron/crontabs/root", "/etc/crontab"]
    for path in cron_paths:
        for line in _read_lines(path):
            finding = _classify_cron_line(line)
            if finding:
                entries.append({"path": path, **finding})
    if paths is None:
        for line in _read_user_crontab():
            finding = _classify_cron_line(line)
            if finding:
                entries.append({"path": "crontab -l", **finding})
    return {"status": "ok", "findings": entries, "evaluation": "تحذير" if entries else "جيد"}


def suspicious_files_scan(patterns: list[str] | None = None) -> dict[str, Any]:
    findings = []
    for pattern in patterns or SUSPICIOUS_FILE_PATTERNS:
        for path in _glob(pattern):
            if not path.is_file():
                continue
            executable = bool(path.stat().st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))
            immutable = _has_immutable(path)
            daemon_like = bool(re.search(r"(kworker|systemd|dbus|sshd|cron|init)", path.name))
            if executable or immutable or daemon_like:
                findings.append({"path": str(path), "executable": executable, "immutable": immutable, "daemon_like_name": daemon_like, "evaluation": "تحذير"})
    return {"status": "ok", "findings": findings, "evaluation": "تحذير" if findings else "جيد"}


def _class(error_type: str, title: str, evaluation: str, explanation: str, suggested_action: str) -> dict[str, str]:
    return {"type": error_type, "title": title, "evaluation": evaluation, "explanation": explanation, "suggested_action": suggested_action}


def _exception(error_type: str, title: str, line: str, cause: str, action: str) -> dict[str, str]:
    return {"type": error_type, "title": title, "latest_timestamp": _extract_laravel_time(line), "probable_cause": cause, "suggested_action": action, "example": truncate_text(redact(line.strip()), 220)}


def _read_many_logs(paths: list[str], max_lines: int) -> list[str]:
    return [line for _, line in _read_many_logs_with_sources(paths, max_lines)]


def _read_many_logs_with_sources(paths: list[str], max_lines: int) -> list[tuple[str, str]]:
    lines = []
    for path in paths:
        if not path:
            continue
        p = Path(path)
        if p.is_dir():
            for child in sorted(p.glob("*"), key=lambda item: item.stat().st_mtime if item.exists() else 0, reverse=True)[:20]:
                lines.extend((str(child), line) for line in _tail_lines(child, max_lines))
        else:
            lines.extend((str(p), line) for line in _tail_lines(p, max_lines))
    return lines[-max_lines:]


def _tail_lines(path: str | Path, max_lines: int) -> list[str]:
    p = Path(path)
    if not p.exists() or not p.is_file():
        return []
    return p.read_text(encoding="utf-8", errors="ignore").splitlines()[-max_lines:]


def _read_lines(path: str) -> list[str]:
    p = Path(path)
    if not p.exists() or not p.is_file():
        return []
    return [line.strip() for line in p.read_text(encoding="utf-8", errors="ignore").splitlines() if line.strip() and not line.strip().startswith("#")]


def _read_user_crontab() -> list[str]:
    if not shutil.which("crontab"):
        return []
    try:
        proc = subprocess.run(["crontab", "-l"], capture_output=True, text=True, timeout=3, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return []
    if proc.returncode != 0:
        return []
    return [line.strip() for line in proc.stdout.splitlines() if line.strip() and not line.strip().startswith("#")]


def _application_paths(config: dict[str, Any]) -> list[dict[str, str]]:
    apps = []
    applications = config.get("applications", [])
    if isinstance(applications, list):
        for app in applications:
            if not isinstance(app, dict):
                continue
            path = app.get("path")
            if path:
                apps.append({"service_name": str(app.get("service_name", "")), "path": str(path)})
    laravel = config.get("laravel", {})
    if isinstance(laravel, dict) and laravel.get("path"):
        apps.append({"service_name": "laravel", "path": str(laravel["path"])})
    return _dedupe_apps(apps)


def _laravel_log_paths(config: dict[str, Any]) -> list[str]:
    return [item["log_path"] for item in _laravel_log_paths_with_apps(config)]


def _laravel_log_paths_with_apps(config: dict[str, Any]) -> list[dict[str, str]]:
    paths = []
    laravel = config.get("laravel", {})
    if isinstance(laravel, dict) and laravel.get("log_path"):
        log_path = Path(str(laravel["log_path"]))
        if log_path.is_dir():
            paths.extend({"app_path": str(laravel.get("path", "")), "log_path": str(path)} for path in log_path.glob("*.log") if path.exists())
        else:
            paths.append({"app_path": str(laravel.get("path", "")), "log_path": str(log_path)})
    for app in _application_paths(config):
        log_dir = Path(app["path"]) / "storage" / "logs"
        paths.extend({"app_path": app["path"], "log_path": str(path)} for path in log_dir.glob("*.log") if path.exists())
    seen = set()
    result = []
    for item in paths:
        if item["log_path"] in seen:
            continue
        seen.add(item["log_path"])
        result.append(item)
    return result


def _laravel_log_events(lines: list[str]) -> list[str]:
    events: list[str] = []
    current: list[str] = []
    for line in lines:
        if _extract_laravel_time(line) and current:
            events.append("\n".join(current))
            current = [line]
        else:
            current.append(line)
    if current:
        events.append("\n".join(current))
    return events


def _dedupe_apps(apps: list[dict[str, str]]) -> list[dict[str, str]]:
    seen = set()
    result = []
    for app in apps:
        if app["path"] in seen:
            continue
        seen.add(app["path"])
        result.append(app)
    return result


def _read_safe_env(path: Path) -> dict[str, str]:
    values = {}
    for line in _read_lines(str(path)):
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key in SAFE_ENV_KEYS:
            values[key] = value.strip().strip('"').strip("'")
    return values


def _mtime(path: Path | None) -> str:
    if not path:
        return ""
    from datetime import datetime, timezone

    return datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).isoformat()


def _extract_apache_time(line: str) -> str:
    match = re.search(r"\[([^\]]*(?:\d{4}|[+-]\d{4})[^\]]*)\]", line)
    return match.group(1) if match else ""


def _parse_apache_datetime(value: str) -> datetime | None:
    value = value.strip()
    if not value:
        return None
    normalized = re.sub(r"\.\d{3,6}", "", value)
    formats = (
        "%d/%b/%Y:%H:%M:%S %z",
        "%a %b %d %H:%M:%S %Y",
        "%b %d %H:%M:%S %Y",
        "%Y-%m-%d %H:%M:%S",
    )
    for fmt in formats:
        try:
            parsed = datetime.strptime(normalized, fmt)
        except ValueError:
            continue
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    return None


def _format_dt(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _parse_access_5xx(line: str) -> dict[str, str] | None:
    parts = line.split('"')
    if len(parts) < 3:
        return None
    left = parts[0].split()
    request = parts[1].split()
    right = parts[2].split()
    if not left or len(request) < 2 or not right:
        return None
    status_code = right[0]
    if status_code not in {"500", "502", "503", "504"}:
        return None
    timestamp = _extract_apache_time(line)
    return {"ip": left[0], "endpoint": _normalize_endpoint(request[1]), "full_path": truncate_text(redact(request[1]), 160), "status": status_code, "timestamp": timestamp, "seen_at": _parse_apache_datetime(timestamp), "user_agent": truncate_text(redact(parts[5]), 120) if len(parts) > 5 else ""}


def _normalize_endpoint(endpoint: str) -> str:
    return endpoint.split("?", 1)[0] or "/"


def _domain_from_log_source(source: str) -> str:
    name = Path(source).name
    return name.removesuffix("-ssl_log") if name else ""


def _extract_client_ip(line: str) -> str:
    match = re.search(r"\[client ([^\]:\s]+)(?::\d+)?\]", line)
    return match.group(1) if match else ""


def _extract_request_path(line: str) -> str:
    request_match = re.search(r'request:\s+"[A-Z]+\s+([^"\s]+)', line)
    if request_match:
        return truncate_text(redact(_normalize_endpoint(request_match.group(1))), 160)
    uri_match = re.search(r"uri:\s+([^,\s]+)", line)
    if uri_match:
        return truncate_text(redact(_normalize_endpoint(uri_match.group(1))), 160)
    return ""


def _extract_referer(line: str) -> str:
    match = re.search(r'referer:\s*([^,\s]+)', line)
    return truncate_text(redact(match.group(1)), 160) if match else ""


def _activity_evaluation(count: int, recent_1h_count: int, latest: datetime | None, now: datetime, *, base: str) -> tuple[str, str]:
    if recent_1h_count <= 0:
        return "مراقبة", "مشاكل قديمة داخل العينة ولا تظهر نشطة حاليًا"
    if base == "apache_5xx" and recent_1h_count >= 20:
        return "حرج", "أخطاء 5xx نشطة ومتكررة خلال آخر ساعة"
    if base != "apache_5xx" and recent_1h_count >= 50:
        return "حرج", "أخطاء Apache نشطة ومتكررة خلال آخر ساعة"
    return "تحذير", "المشكلة ظهرت خلال آخر ساعة وتحتاج مراجعة"


def _first_counter_key(counter: Counter) -> str:
    return counter.most_common(1)[0][0] if counter else ""


def _extract_laravel_time(line: str) -> str:
    match = re.search(r"\[(\d{4}-\d{2}-\d{2}[^\]]+)\]", line)
    return match.group(1) if match else ""


def _extract_cwd_from_args(args: str) -> str:
    match = re.search(r"(/[^ ]+)/artisan", args)
    return match.group(1) if match else ""


def _extract_queue_connection(args: str) -> str:
    match = re.search(r"queue:work\s+([^\s]+)", args)
    return match.group(1) if match else ""


def _worker_source(args: str) -> str:
    lower = args.lower()
    if "supervisor" in lower or "supervisord" in lower:
        return "supervisor"
    if "cron" in lower:
        return "cron"
    return "manual process"


def _parse_supervisor_conf(path: Path) -> list[dict[str, str]]:
    programs = []
    current: dict[str, str] | None = None
    for line in _read_lines(str(path)):
        if line.startswith("[program:") and line.endswith("]"):
            current = {"program": line[9:-1], "config": str(path), "numprocs": "1", "command": ""}
            programs.append(current)
        elif current and "=" in line:
            key, value = [part.strip() for part in line.split("=", 1)]
            if key in {"command", "numprocs", "user", "directory"}:
                current[key] = truncate_text(redact(value), 220)
    return programs


def _classify_cron_line(line: str) -> dict[str, str] | None:
    lower = line.lower()
    reasons = []
    if "base64" in lower:
        reasons.append("base64 داخل cron")
    if re.search(r"\b(curl|wget)\b", lower):
        reasons.append("تحميل سكريبت خارجي")
    if "nohup" in lower and re.search(r"(/tmp/\.|/var/tmp/\.|/dev/shm/\.|/usr/share/.*/\.)", lower):
        reasons.append("nohup مع مسار مخفي")
    if "chattr" in lower:
        reasons.append("تعديل immutable attributes")
    if re.search(r"(/tmp/\.|/var/tmp/\.|/dev/shm/\.|/usr/share/.*/\.)", lower):
        reasons.append("مسار مخفي داخل system-like path")
    if not reasons:
        return None
    return {"line": truncate_text(redact(line), 220), "reasons": ", ".join(reasons), "evaluation": "تحذير"}


def _glob(pattern: str) -> list[Path]:
    try:
        if pattern.startswith("/"):
            return list(Path("/").glob(pattern.lstrip("/")))
        return list(Path().glob(pattern))
    except (OSError, ValueError):
        return []


def _has_immutable(path: Path) -> bool:
    lsattr = shutil.which("lsattr")
    if not lsattr:
        return False
    try:
        proc = subprocess.run([lsattr, str(path)], capture_output=True, text=True, timeout=3, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return False
    flags = proc.stdout.split(None, 1)[0] if proc.stdout.strip() else ""
    return "i" in flags
