# Matrix Scanner Project Structure

This document defines the intended code layout for Matrix Scanner.

## Package Layout
```text
matrix_scanner/
  __init__.py
  cli.py
  config.py
  db.py
  models.py
  scheduler.py
  telegram_bot.py
  ai_router.py
  security.py
  tool_registry.py
  tool_executor.py
  scanners/
    __init__.py
    system.py
    services.py
    nginx.py
    php_fpm.py
    mysql.py
    laravel.py
  tools/
    __init__.py
    status.py
    disk.py
    services.py
    logs.py
    report.py
  alerts/
    __init__.py
    rules.py
    notifier.py
    cooldown.py
  reports/
    __init__.py
    formatter.py
    summarizer.py
tests/
  unit/
  integration/
  fixtures/
docs/
  PROJECT-STRUCTURE.md
  TEST-PLAN.md
  IMPLEMENTATION-CHECKLIST.md
config.yaml.example
```

## Responsibilities
- `cli.py`: local commands such as `scan`, `status`, `report`, and `test-telegram`.
- `config.py`: config file and environment loading.
- `db.py`: SQLite connection, schema creation, and migrations.
- `models.py`: typed data structures or ORM models.
- `scheduler.py`: periodic scan orchestration.
- `telegram_bot.py`: long polling, command mapping, Telegram send/test.
- `ai_router.py`: later natural-language-to-tool routing.
- `security.py`: principals, roles, mode checks, and redaction helpers.
- `tool_registry.py`: static allowlist of tools and handlers.
- `tool_executor.py`: authorization, execution, timeouts, truncation, and invocation logging.
- `scanners/`: read-only collectors.
- `tools/`: user-facing tool handlers.
- `alerts/`: threshold rules, cooldown, notification dispatch.
- `reports/`: Arabic summaries and full report formatting.

## Boundary Rules
- Scanners do not format Telegram messages.
- Tools do not authenticate users directly.
- Telegram does not call scanners directly; it calls `tool_executor`.
- AI does not call scanners or tools directly; it returns a proposed `tool_key`.
- Database metadata does not define executable behavior.
