# Matrix Scanner Telegram Skill

## Purpose
Use this skill when implementing Telegram send/test, long polling, command handling, or Telegram output formatting.

## MVP Transport
- Use Telegram long polling in MVP.
- Do not require public HTTPS webhook infrastructure for the first version.
- Keep Telegram code separate from scanners and tool handlers.

## Authentication
- Use `telegram user_id` and/or `chat_id`.
- Do not rely on username.
- Unknown users are denied or ignored according to config.
- Log denied attempts with minimal safe metadata.

## Commands
Initial explicit commands:
- `/status`
- `/disk`
- `/services`
- `/nginx`
- `/laravel`
- `/report`

Natural language routing is a later phase through `ai_router`.

## Output
- Keep Telegram messages concise.
- Split long reports if required by Telegram limits.
- Avoid raw logs unless the command explicitly asks for diagnostic detail.
- Sanitize secrets and environment values.
- Use Arabic summaries by default for user-facing responses.

## Failure Handling
- Telegram API failures should not crash scans.
- Failed sends are logged.
- Alerts should use cooldown to avoid repeated noisy messages.

## Testing Checklist
- `test-telegram` sends a message when token and chat are configured.
- Unauthorized chat is denied.
- Each explicit command maps to the expected `tool_key`.
- Tool errors return a safe message.
- Long output is truncated or split.
