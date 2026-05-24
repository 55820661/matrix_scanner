from __future__ import annotations

import glob
from pathlib import Path

from matrix_scanner.scanners.services import service_status


def scan_php_fpm(service_name: str = "php-fpm", pool_config_paths: list[str] | None = None) -> dict:
    return {
        "service": service_status(service_name),
        "pool": scan_pool_configs(pool_config_paths or []),
        "processes": scan_processes(),
    }


def scan_pool_configs(paths: list[str]) -> dict:
    files = _expand_paths(paths)
    if not files:
        return {"status": "unavailable", "reason": "no_pool_config_paths"}

    pools = []
    warnings = []
    for path in files:
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
        except OSError as exc:
            warnings.append({"path": str(path), "reason": str(exc)})
            continue
        pool = {"path": str(path), "values": {}}
        for raw_line in content.splitlines():
            line = raw_line.strip()
            if not line or line.startswith(";") or "=" not in line:
                continue
            key, value = [part.strip() for part in line.split("=", 1)]
            if key in {"pm", "pm.max_children", "pm.start_servers", "pm.min_spare_servers", "pm.max_spare_servers", "pm.max_requests"}:
                pool["values"][key] = value
        pools.append(pool)

    return {"status": "ok" if pools else "unavailable", "pools": pools, "warnings": warnings}


def scan_processes() -> dict:
    proc = Path("/proc")
    if not proc.exists():
        return {"status": "unavailable", "reason": "proc_not_found"}
    count = 0
    rss_kb = 0
    for comm in proc.glob("[0-9]*/comm"):
        try:
            name = comm.read_text(encoding="utf-8", errors="ignore").strip()
        except OSError:
            continue
        if "php-fpm" not in name:
            continue
        count += 1
        statm = comm.parent / "statm"
        try:
            pages = int(statm.read_text(encoding="utf-8").split()[1])
            rss_kb += pages * 4
        except (OSError, ValueError, IndexError):
            pass
    return {"status": "ok", "process_count": count, "rss_kb_estimate": rss_kb}


def _expand_paths(paths: list[str]) -> list[Path]:
    files: list[Path] = []
    for item in paths:
        matches = [Path(match) for match in glob.glob(item)] if any(char in item for char in "*?[]") else [Path(item)]
        files.extend(path for path in matches if path.exists() and path.is_file())
    return files
