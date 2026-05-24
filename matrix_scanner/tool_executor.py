from __future__ import annotations

import time
from typing import Any

from matrix_scanner import db
from matrix_scanner.security import Principal, truncate_text
from matrix_scanner.tool_registry import ToolSpec


def execute_tool(
    conn,
    registry: dict[str, ToolSpec],
    *,
    tool_key: str,
    context: dict[str, Any],
    source: str = "cli",
    principal: Principal | None = None,
    input_data: dict[str, Any] | None = None,
) -> dict[str, Any]:
    started = time.monotonic()
    input_data = input_data or {}

    spec = registry.get(tool_key)
    if spec is None:
        return _deny(conn, source, principal, tool_key, input_data, "unknown_tool", started)
    if not spec.enabled:
        return _deny(conn, source, principal, tool_key, input_data, "disabled_tool", started)
    if principal and principal.role not in spec.allowed_roles:
        return _deny(conn, source, principal, tool_key, input_data, "role_not_allowed", started)
    if spec.requires_confirmation:
        return _deny(conn, source, principal, tool_key, input_data, "confirmation_required", started)
    mode_denial = _mode_denial_reason(spec, context.get("config", {}))
    if mode_denial:
        return _deny(conn, source, principal, tool_key, input_data, mode_denial, started)

    try:
        output = spec.handler(context | {"input": input_data})
        output = _truncate_output(output, spec.max_output_chars)
        status = "completed"
        result = {"ok": True, "tool_key": tool_key, "output": output}
        return result
    except Exception as exc:  # handlers must fail safe at the executor boundary
        status = "failed"
        result = {"ok": False, "tool_key": tool_key, "error": str(exc)}
        return result
    finally:
        duration_ms = int((time.monotonic() - started) * 1000)
        db.log_invocation(
            conn,
            source=source,
            principal_id=principal.id if principal else None,
            tool_key=tool_key,
            input_data=input_data,
            output_data=locals().get("result", {}),
            status=locals().get("status", "failed"),
            duration_ms=duration_ms,
        )


def _deny(conn, source, principal, tool_key, input_data, reason, started) -> dict[str, Any]:
    result = {"ok": False, "tool_key": tool_key, "error": reason}
    db.log_invocation(
        conn,
        source=source,
        principal_id=principal.id if principal else None,
        tool_key=tool_key,
        input_data=input_data,
        output_data=result,
        status="denied",
        denial_reason=reason,
        duration_ms=int((time.monotonic() - started) * 1000),
    )
    return result


def _mode_denial_reason(spec: ToolSpec, config: dict[str, Any]) -> str | None:
    current_mode = str(config.get("current_mode", "read_only"))
    approved_fix = bool(config.get("approved_fix", False))
    if spec.type == "action" and not approved_fix:
        return "approved_fix_disabled"
    if current_mode not in spec.allowed_modes:
        return "mode_not_allowed"
    return None


def _truncate_output(output: dict[str, Any], max_chars: int) -> dict[str, Any]:
    preview = _json_preview(output)
    if len(preview) <= max_chars:
        return output

    truncated = dict(output)
    for key in ("summary_text", "report_text"):
        if isinstance(truncated.get(key), str):
            truncated[key] = truncate_text(truncated[key], max_chars)
            truncated["_truncated"] = True
            return truncated

    return {
        "_truncated": True,
        "summary_text": truncate_text(preview, max_chars),
    }


def _json_preview(value: Any) -> str:
    import json

    return json.dumps(value, ensure_ascii=False, default=str)
