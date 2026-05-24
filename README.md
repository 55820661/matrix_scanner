# Matrix Scanner

Matrix Scanner is a read-only Laravel server diagnostic agent for Linux servers.

The MVP uses Python, SQLite, scheduled scans, safe internal tools, and Telegram reporting. It is designed to inspect and suggest only; it does not restart services, edit files, run migrations, or execute arbitrary commands.

## Current Status
This repository contains the initial scaffold:
- CLI entry point.
- SQLite schema.
- static tool registry and safe executor.
- read-only scanners for system, services, Nginx logs, and Laravel logs.
- alert rules and cooldown.
- Arabic report formatting.
- Telegram send helper and command mapping.
- systemd timer templates.
- unittest-based test suite.

## Quick Start
```bash
python -m matrix_scanner.cli --config config.memory.example.yaml status
python -m matrix_scanner.cli --config config.memory.example.yaml scan
python -m matrix_scanner.cli --config config.memory.example.yaml report
python -B -m unittest discover -s tests
```

For a real server, copy `config.yaml.example` to `config.yaml`, adjust paths and services, and set secrets through environment variables:

```bash
export TELEGRAM_BOT_TOKEN="..."
```

Run the Telegram bot with long polling:

```bash
matrix-scanner --config /etc/matrix-scanner/config.yaml telegram-bot
```

Systemd templates are available in `deploy/`:
- `matrix-scanner-telegram-bot.service`
- `matrix-scanner-scan.service`
- `matrix-scanner-scan.timer`

Deployment notes: [docs/SYSTEMD-DEPLOYMENT.md](docs/SYSTEMD-DEPLOYMENT.md)

## Safety Rules
- No shell commands from Telegram, AI, SQLite, or config.
- AI routing is a later phase and may only select a `tool_key`.
- Secrets stay in environment variables.
- Telegram identity must use `user_id` or `chat_id`, not username.

## Planning
See:
- [PLANS.md](PLANS.md)
- [docs/PROJECT-STRUCTURE.md](docs/PROJECT-STRUCTURE.md)
- [docs/TEST-PLAN.md](docs/TEST-PLAN.md)
- [docs/IMPLEMENTATION-CHECKLIST.md](docs/IMPLEMENTATION-CHECKLIST.md)
