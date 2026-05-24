from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1


def connect(database_path: str | Path) -> sqlite3.Connection:
    if str(database_path) == ":memory:":
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        init_db(conn)
        return conn
    path = Path(database_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    if os.name == "nt":
        conn.execute("PRAGMA journal_mode=OFF")
    init_db(conn)
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS schema_version (
            version INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value_json TEXT NOT NULL,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS principals (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            telegram_user_id INTEGER,
            telegram_chat_id INTEGER,
            display_name TEXT,
            role TEXT NOT NULL DEFAULT 'admin',
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS tools_registry (
            tool_key TEXT PRIMARY KEY,
            display_name TEXT NOT NULL,
            description TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            type TEXT NOT NULL,
            requires_confirmation INTEGER NOT NULL DEFAULT 0,
            risk_level TEXT NOT NULL DEFAULT 'low',
            handler_name TEXT NOT NULL,
            allowed_roles TEXT NOT NULL DEFAULT 'admin',
            output_type TEXT NOT NULL DEFAULT 'summary',
            max_runtime_seconds INTEGER NOT NULL DEFAULT 10,
            max_output_chars INTEGER NOT NULL DEFAULT 3500
        );

        CREATE TABLE IF NOT EXISTS scan_results (
            scan_id INTEGER PRIMARY KEY AUTOINCREMENT,
            started_at TEXT NOT NULL,
            finished_at TEXT NOT NULL,
            status TEXT NOT NULL,
            summary_json TEXT NOT NULL,
            raw_result_json TEXT NOT NULL,
            error_message TEXT
        );

        CREATE TABLE IF NOT EXISTS alerts (
            alert_id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER,
            alert_key TEXT NOT NULL,
            severity TEXT NOT NULL,
            title TEXT NOT NULL,
            evidence_json TEXT NOT NULL,
            probable_cause TEXT,
            suggested_action TEXT,
            requires_confirmation INTEGER NOT NULL DEFAULT 0,
            status TEXT NOT NULL DEFAULT 'open',
            last_sent_at TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS tool_invocations (
            invocation_id INTEGER PRIMARY KEY AUTOINCREMENT,
            source TEXT NOT NULL,
            principal_id INTEGER,
            tool_key TEXT NOT NULL,
            input_json TEXT NOT NULL,
            output_json TEXT NOT NULL,
            status TEXT NOT NULL,
            denial_reason TEXT,
            duration_ms INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS confirmation_requests (
            confirmation_id INTEGER PRIMARY KEY AUTOINCREMENT,
            principal_id INTEGER,
            tool_key TEXT NOT NULL,
            requested_action_json TEXT NOT NULL,
            confirmation_code TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        """
    )
    count = conn.execute("SELECT COUNT(*) FROM schema_version").fetchone()[0]
    if count == 0:
        conn.execute("INSERT INTO schema_version(version) VALUES (?)", (SCHEMA_VERSION,))
    conn.commit()


def insert_scan_result(
    conn: sqlite3.Connection,
    *,
    started_at: str,
    finished_at: str,
    status: str,
    summary: dict[str, Any],
    raw_result: dict[str, Any],
    error_message: str | None = None,
) -> int:
    cursor = conn.execute(
        """
        INSERT INTO scan_results(started_at, finished_at, status, summary_json, raw_result_json, error_message)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            started_at,
            finished_at,
            status,
            json.dumps(summary, ensure_ascii=False),
            json.dumps(raw_result, ensure_ascii=False),
            error_message,
        ),
    )
    conn.commit()
    return int(cursor.lastrowid)


def insert_alerts(conn: sqlite3.Connection, scan_id: int, alerts: list[dict[str, Any]]) -> None:
    for alert in alerts:
        conn.execute(
            """
            INSERT INTO alerts(scan_id, alert_key, severity, title, evidence_json, probable_cause, suggested_action)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan_id,
                alert["alert_key"],
                alert["severity"],
                alert["title"],
                json.dumps(alert.get("evidence", {}), ensure_ascii=False),
                alert.get("probable_cause"),
                alert.get("suggested_action"),
            ),
        )
    conn.commit()


def sync_tools_registry(conn: sqlite3.Connection, registry: dict[str, Any]) -> None:
    for spec in registry.values():
        conn.execute(
            """
            INSERT INTO tools_registry(
                tool_key, display_name, description, enabled, type, requires_confirmation,
                risk_level, handler_name, allowed_roles, output_type, max_runtime_seconds, max_output_chars
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(tool_key) DO UPDATE SET
                display_name=excluded.display_name,
                description=excluded.description,
                type=excluded.type,
                requires_confirmation=excluded.requires_confirmation,
                risk_level=excluded.risk_level,
                handler_name=excluded.handler_name,
                allowed_roles=excluded.allowed_roles,
                output_type=excluded.output_type,
                max_runtime_seconds=excluded.max_runtime_seconds,
                max_output_chars=excluded.max_output_chars
            """,
            (
                spec.tool_key,
                spec.display_name,
                spec.description,
                int(spec.enabled),
                spec.type,
                int(spec.requires_confirmation),
                spec.risk_level,
                spec.handler_name,
                ",".join(spec.allowed_roles),
                spec.output_type,
                spec.max_runtime_seconds,
                spec.max_output_chars,
            ),
        )
    conn.commit()


def log_invocation(
    conn: sqlite3.Connection,
    *,
    source: str,
    principal_id: int | None,
    tool_key: str,
    input_data: dict[str, Any],
    output_data: dict[str, Any],
    status: str,
    denial_reason: str | None = None,
    duration_ms: int = 0,
) -> None:
    conn.execute(
        """
        INSERT INTO tool_invocations(source, principal_id, tool_key, input_json, output_json, status, denial_reason, duration_ms)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            source,
            principal_id,
            tool_key,
            json.dumps(input_data, ensure_ascii=False),
            json.dumps(output_data, ensure_ascii=False),
            status,
            denial_reason,
            duration_ms,
        ),
    )
    conn.commit()


def get_setting(conn: sqlite3.Connection, key: str, default: Any = None) -> Any:
    row = conn.execute("SELECT value_json FROM settings WHERE key = ?", (key,)).fetchone()
    if row is None:
        return default
    return json.loads(row["value_json"])


def set_setting(conn: sqlite3.Connection, key: str, value: Any) -> None:
    conn.execute(
        """
        INSERT INTO settings(key, value_json, updated_at)
        VALUES (?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(key) DO UPDATE SET
            value_json=excluded.value_json,
            updated_at=CURRENT_TIMESTAMP
        """,
        (key, json.dumps(value, ensure_ascii=False)),
    )
    conn.commit()
