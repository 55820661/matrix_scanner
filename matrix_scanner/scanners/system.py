from __future__ import annotations

import os
import shutil
import time
from pathlib import Path


def scan_system() -> dict:
    return {
        "cpu_percent": _cpu_percent(),
        "ram": _memory(),
        "swap": _swap(),
        "disk": _disk_usage("/"),
        "load_average": _load_average(),
        "uptime_seconds": _uptime(),
    }


def _cpu_percent() -> float | None:
    first = _read_cpu_times()
    if first is None:
        return None
    time.sleep(0.05)
    second = _read_cpu_times()
    if second is None:
        return None
    idle_delta = second["idle"] - first["idle"]
    total_delta = second["total"] - first["total"]
    if total_delta <= 0:
        return None
    return round((1 - idle_delta / total_delta) * 100, 2)


def _read_cpu_times() -> dict[str, int] | None:
    stat = Path("/proc/stat")
    if not stat.exists():
        return None
    parts = stat.read_text(encoding="utf-8", errors="ignore").splitlines()[0].split()[1:]
    values = [int(part) for part in parts]
    idle = values[3] + (values[4] if len(values) > 4 else 0)
    return {"idle": idle, "total": sum(values)}


def _memory() -> dict:
    info = _meminfo()
    total = info.get("MemTotal")
    available = info.get("MemAvailable")
    if not total or available is None:
        return {"status": "unavailable"}
    used = total - available
    return {
        "total_kb": total,
        "available_kb": available,
        "used_kb": used,
        "used_percent": round(used / total * 100, 2),
    }


def _swap() -> dict:
    info = _meminfo()
    total = info.get("SwapTotal")
    free = info.get("SwapFree")
    if not total:
        return {"total_kb": total or 0, "used_percent": 0}
    used = total - (free or 0)
    return {"total_kb": total, "used_kb": used, "used_percent": round(used / total * 100, 2)}


def _meminfo() -> dict[str, int]:
    path = Path("/proc/meminfo")
    if not path.exists():
        return {}
    result = {}
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        key, _, value = line.partition(":")
        result[key] = int(value.strip().split()[0])
    return result


def _disk_usage(path: str) -> dict:
    try:
        usage = shutil.disk_usage(path)
    except OSError as exc:
        return {"status": "unavailable", "error": str(exc)}
    return {
        "path": path,
        "total": usage.total,
        "used": usage.used,
        "free": usage.free,
        "used_percent": round(usage.used / usage.total * 100, 2),
    }


def _load_average() -> list[float] | None:
    if not hasattr(os, "getloadavg"):
        return None
    try:
        return [round(v, 2) for v in os.getloadavg()]
    except OSError:
        return None


def _uptime() -> float | None:
    path = Path("/proc/uptime")
    if not path.exists():
        return None
    return float(path.read_text(encoding="utf-8").split()[0])
