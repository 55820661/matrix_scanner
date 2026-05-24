from __future__ import annotations

import shutil
import subprocess


def scan_services(services: list[str]) -> dict[str, dict]:
    return {service: service_status(service) for service in services}


def service_status(service: str) -> dict:
    systemctl = shutil.which("systemctl")
    if systemctl is None:
        return {"status": "unavailable", "reason": "systemctl_not_found"}
    try:
        proc = subprocess.run(
            [systemctl, "is-active", service],
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"status": "unavailable", "reason": str(exc)}
    status = proc.stdout.strip() or proc.stderr.strip() or "unknown"
    return {"status": status, "ok": status == "active", "returncode": proc.returncode}
