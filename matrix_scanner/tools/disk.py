from __future__ import annotations

from matrix_scanner.scanners.system import scan_system


def get_disk(context: dict) -> dict:
    disk = scan_system().get("disk", {})
    return {"disk": disk, "summary_text": f"Disk: {disk.get('used_percent', 'غير متاح')}% مستخدم"}
