# Matrix Scanner Security Skill

## Purpose
Use this skill when implementing Telegram auth, tool execution, AI routing, config handling, logging, or any future approved-fix behavior.

## Security Model
- MVP modes:
  - `read_only = true`
  - `suggest_only = true`
  - `approved_fix = false`
- The agent should run as a limited OS user where possible.
- Telegram identity must use `user_id` and/or `chat_id`, never username.
- Unauthorized Telegram messages are denied or ignored and logged with minimal metadata.

## Tool Execution Rules
- No free-form shell commands from Telegram.
- No free-form shell commands from AI.
- No command templates in SQLite.
- No dynamic handler imports from database values.
- The code-level registry maps `tool_key` to handler functions.
- SQLite metadata can enable/disable tools, but cannot define executable behavior.
- Every tool has:
  - type: `read_only`, `diagnostic`, or later `action`.
  - max runtime.
  - max output size.
  - allowed roles.
  - invocation log.

## Secrets
- Store secrets only in environment variables.
- Do not store Telegram bot tokens, API keys, database passwords, or OpenAI keys in SQLite.
- Do not include secrets in reports, alerts, or command logs.
- Scrub logs before returning excerpts to Telegram.

## Future Approved-fix Requirements
Approved-fix mode is out of MVP. When added later, it requires:
- explicit confirmation flow.
- short-lived confirmation codes.
- strict service/action allowlist.
- minimal sudoers rules if OS privileges are needed.
- full audit trail.
- no destructive file operations by default.

## Review Checklist
- Can an unauthorized user trigger any handler?
- Can AI bypass `tool_executor`?
- Can DB content cause new executable behavior?
- Are errors and outputs sanitized?
- Are permission failures reported safely?
