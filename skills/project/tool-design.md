# Matrix Scanner Tool Design Skill

## Purpose
Use this skill when adding or reviewing tools such as `get_status`, `get_disk`, `get_nginx_errors`, or `generate_report`.

## Tool Contract
Each tool should define:
- `tool_key`
- display name
- description
- type: `read_only`, `diagnostic`, or `action`
- risk level
- allowed roles
- max runtime seconds
- max output chars
- input schema
- output schema
- handler function

## Handler Rules
- Handlers are plain Python functions or small classes.
- Handlers return structured data, not preformatted Telegram text.
- Handlers should not know whether the caller is CLI, Telegram, scheduler, or AI.
- Handlers should use scanner modules for raw collection and report modules for summaries.
- Handlers must handle missing files, missing commands, permission errors, and timeouts.

## Registry Pattern
The code registry is the source of executable truth:

```text
tool_key -> handler function
```

The database registry is metadata only:
- enabled/disabled.
- display text.
- roles.
- output type.
- risk metadata.

## Output Rules
- Keep normal command output concise.
- Full reports are only for `generate_report`.
- Include evidence, probable cause, and suggested action for diagnostic tools.
- Do not include secrets or excessive raw logs.

## Testing Checklist
- Authorized invocation succeeds.
- Unauthorized invocation is denied.
- Disabled tool is denied.
- Unknown `tool_key` is denied.
- Handler failure is logged and returned as a safe error.
- Output is truncated when above the configured limit.
