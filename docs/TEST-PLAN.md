# Matrix Scanner Test Plan

## Scope
The MVP must prove that Matrix Scanner can safely collect diagnostics, store results, generate alerts, and respond to Telegram commands without executing unsafe actions.

## Test Layers
### Unit
- config loading.
- static tool registry.
- tool executor authorization and denial paths.
- scanner parsers.
- alert thresholds and cooldown.
- report formatter.

### Integration
- SQLite schema creation.
- scan result persistence.
- alert persistence.
- tool invocation logging.
- CLI smoke tests.
- Telegram command mapping with mocked API responses.

### Security Regression
- unknown Telegram user is denied.
- username is not accepted as identity.
- disabled tool is denied.
- unknown tool is denied.
- DB metadata cannot add a handler.
- secrets are redacted from output.
- output is bounded.

## Required Fixtures
- Nginx access log with 200, 499, 500, 502, and 504 responses.
- Nginx error log with representative upstream failures.
- Laravel log with sanitized exceptions.
- PHP-FPM pool config snippet.
- MySQL status sample.
- Service status samples for active, inactive, missing, and permission denied.

## MVP Acceptance Checks
- `matrix-scanner scan` stores a scan result.
- `matrix-scanner status` returns a concise summary.
- `matrix-scanner report` returns a full diagnostic report.
- Scheduler command can be run repeatedly without duplicate noisy alerts.
- Telegram `/status` maps to `get_status`.
- Telegram `/report` maps to `generate_report`.
- Unauthorized Telegram requests are denied or ignored.
- No test requires real production services.
