from __future__ import annotations

from collections import Counter
from pathlib import Path
import re

from matrix_scanner.security import redact


WATCH_CODES = {"499", "500", "502", "504"}


def scan_nginx(access_log: str, error_log: str, max_lines: int = 500) -> dict:
    return {
        "access": summarize_access_log(access_log, max_lines),
        "errors": summarize_error_log(error_log, max_lines),
    }


def summarize_access_log(path: str, max_lines: int = 500) -> dict:
    lines = _tail_lines(path, max_lines)
    if isinstance(lines, dict):
        return lines
    codes: Counter[str] = Counter()
    endpoints: Counter[str] = Counter()
    for line in lines:
        parts = line.split()
        if len(parts) < 9:
            continue
        request = line.split('"')
        endpoint = request[1].split()[1] if len(request) > 1 and len(request[1].split()) >= 2 else "-"
        code = parts[8]
        codes[code] += 1
        if code in WATCH_CODES:
            endpoints[endpoint] += 1
    return {
        "status": "ok",
        "total_lines": len(lines),
        "status_codes": dict(codes.most_common(10)),
        "watched_codes": {code: codes.get(code, 0) for code in WATCH_CODES},
        "failing_endpoints": dict(endpoints.most_common(10)),
    }


def summarize_error_log(path: str, max_lines: int = 500) -> dict:
    lines = _tail_lines(path, max_lines)
    if isinstance(lines, dict):
        return lines
    interesting = [redact(line.strip()) for line in lines if _is_interesting_error(line)]
    groups = summarize_nginx_error_groups(interesting)
    return {"status": "ok", "total_lines": len(lines), "recent_errors": interesting[-20:], "groups": groups}


def summarize_nginx_error_groups(lines: list[str]) -> list[dict]:
    groups: dict[str, dict] = {}
    for line in lines:
        classified = classify_nginx_error_line(line)
        key = classified["type"]
        group = groups.setdefault(
            key,
            {
                "type": classified["type"],
                "title": classified["title"],
                "count": 0,
                "last_seen": "",
                "ips": set(),
                "server": "",
                "paths": set(),
                "evaluation": classified["evaluation"],
                "explanation": classified["explanation"],
                "suggested_action": classified["suggested_action"],
                "examples": [],
            },
        )
        group["count"] += 1
        group["last_seen"] = classified["timestamp"] or group["last_seen"]
        if classified["ip"]:
            group["ips"].add(classified["ip"])
        if classified["server"]:
            group["server"] = classified["server"]
        if classified["path"]:
            group["paths"].add(classified["path"])
        if len(group["examples"]) < 2:
            group["examples"].append(classified["example"])

    result = []
    for group in groups.values():
        result.append(
            {
                **group,
                "ips": sorted(group["ips"])[:5],
                "paths": sorted(group["paths"])[:5],
            }
        )
    return sorted(result, key=lambda item: item["count"], reverse=True)


def classify_nginx_error_line(line: str) -> dict:
    lower = line.lower()
    classification = _classification_for(lower)
    return {
        **classification,
        "timestamp": _extract_timestamp(line),
        "ip": _extract_ip(line),
        "server": _extract_server(line),
        "path": _extract_request_path(line),
        "example": redact(line.strip()),
    }


def _classification_for(lower: str) -> dict:
    if "ssl_do_handshake() failed" in lower or "while ssl handshaking" in lower:
        return _class(
            "ssl_handshake_failure",
            "SSL/TLS handshake failures",
            "طبيعي",
            "محاولات اتصال SSL/TLS فاشلة من IPs خارجية. غالبًا فحص آلي أو عدم توافق في handshake، ولا يظهر من السطر وحده أنها مشكلة في التطبيق.",
            "راقب التكرار فقط، وتأكد من إعدادات TLS إذا زاد العدد بشكل غير معتاد.",
        )
    if any(token in lower for token in ["/.env", "config.php", "phpinfo.php"]):
        return _class(
            "sensitive_file_probe",
            "Probing for sensitive files",
            "مراقبة",
            "محاولة فحص/اختراق للبحث عن ملف حساس. إذا كان الملف غير موجود فهذا جيد ولا يعني اختراقًا ناجحًا.",
            "تأكد من حظر الوصول إلى ملفات .env والملفات الحساسة من Nginx.",
        )
    if "connect() failed" in lower and "connection refused" in lower:
        return _class("connect_refused", "Upstream connection refused", "تحذير", "Nginx لم يستطع الاتصال بخدمة upstream.", "افحص حالة خدمة التطبيق أو PHP-FPM/Gunicorn.")
    if "upstream timed out" in lower or "timed out" in lower and "upstream" in lower:
        return _class("upstream_timeout", "Upstream timeout", "تحذير", "الـ upstream استغرق وقتًا أطول من المسموح.", "راجع بطء التطبيق أو قاعدة البيانات أو timeout settings.")
    if "permission denied" in lower:
        return _class("permission_denied", "Permission denied", "تحذير", "Nginx لا يملك صلاحية قراءة ملف أو الوصول إلى socket/path.", "راجع صلاحيات الملفات أو socket المستخدم.")
    if "client intended to send too large body" in lower:
        return _class("large_client_body", "Client body too large", "مراقبة", "طلب بحجم أكبر من حد Nginx الحالي.", "راجع client_max_body_size إذا كان الرفع الكبير متوقعًا.")
    if "no live upstreams" in lower:
        return _class("no_live_upstreams", "No live upstreams", "حرج", "كل upstreams المحددة غير متاحة من منظور Nginx.", "افحص خدمات التطبيق وupstream configuration.")
    if "open()" in lower and "failed" in lower:
        return _class("static_404", "Static file 404", "مراقبة", "طلبات لملفات static غير موجودة.", "راجع الروابط أو إعدادات static files إذا تكررت لمسارات مهمة.")
    if "fastcgi" in lower or "gunicorn" in lower or "upstream" in lower:
        return _class("upstream_error", "FastCGI/Gunicorn upstream errors", "تحذير", "خطأ مرتبط بالاتصال بين Nginx وخدمة التطبيق.", "راجع logs خدمة التطبيق وPHP-FPM/Gunicorn.")
    return _class("other_nginx_error", "Other Nginx errors", "مراقبة", "أخطاء Nginx غير مصنفة ضمن القواعد الحالية.", "راجع الأمثلة المختصرة إذا تكررت بكثافة.")


def _class(error_type: str, title: str, evaluation: str, explanation: str, suggested_action: str) -> dict:
    return {
        "type": error_type,
        "title": title,
        "evaluation": evaluation,
        "explanation": explanation,
        "suggested_action": suggested_action,
    }


def _is_interesting_error(line: str) -> bool:
    lower = line.lower()
    tokens = ["error", "crit", "failed", "upstream", "handshake", "permission denied", "too large body", "no live upstreams"]
    return any(token in lower for token in tokens)


def _extract_timestamp(line: str) -> str:
    match = re.match(r"(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})", line)
    return match.group(1) if match else ""


def _extract_ip(line: str) -> str:
    match = re.search(r"client:\s*([0-9a-fA-F:.]+)", line)
    return match.group(1) if match else ""


def _extract_server(line: str) -> str:
    match = re.search(r"server:\s*([^,\s]+)", line)
    return match.group(1) if match else ""


def _extract_request_path(line: str) -> str:
    match = re.search(r'request:\s*"[A-Z]+\s+([^\s"]+)', line)
    return match.group(1) if match else ""


def _tail_lines(path: str, max_lines: int) -> list[str] | dict:
    log_path = Path(path)
    if not log_path.exists():
        return {"status": "unavailable", "reason": "file_not_found", "path": path}
    try:
        lines = log_path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError as exc:
        return {"status": "unavailable", "reason": str(exc), "path": path}
    return lines[-max_lines:]
