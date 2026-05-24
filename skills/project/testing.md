# Matrix Scanner Testing Skill

## Purpose
Use this skill when adding tests for Matrix Scanner. It complements the general testing skill with project-specific requirements.

## Testing Priorities
Focus first on safety boundaries and deterministic behavior:
- tool authorization.
- registry allowlist.
- SQLite persistence.
- scanner parsing.
- alert cooldown.
- Telegram command mapping.
- report formatting.

## Unit Tests
Required for:
- config loading with environment secrets excluded from persisted settings.
- `tool_registry` mapping known keys to handlers.
- `tool_executor` denying unknown, disabled, or unauthorized tools.
- alert rules for threshold crossings.
- cooldown behavior.
- report formatter output shape.

## Scanner Tests
Use fixtures for:
- Nginx access/error logs.
- Laravel logs.
- PHP-FPM config snippets.
- MySQL status sample output.
- service status sample output.

Scanners should be tested without requiring real Nginx, MySQL, PHP-FPM, or Laravel.

## Integration Tests
Required for:
- first-run SQLite schema creation.
- storing scan results.
- storing alerts.
- storing tool invocations.
- CLI command smoke tests.
- Telegram command to tool mapping with mocked Telegram API.

## Security Tests
Required for:
- unauthorized Telegram users.
- username-only identity rejection.
- AI router cannot execute directly.
- DB `handler_name` cannot create a new executable handler.
- output truncation.
- secret redaction.

## Test Data Rules
- Do not commit real logs containing secrets.
- Use sanitized fixtures.
- Include edge cases:
  - missing log files.
  - permission denied.
  - malformed log lines.
  - empty scan results.
  - service unavailable.

## Done Criteria
A feature is not complete until:
- happy path tests pass.
- denial/failure path tests pass.
- unsafe behavior is covered by at least one regression test.
