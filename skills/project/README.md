# Matrix Scanner Project Skills

This folder contains project-specific skills for building Matrix Scanner, a read-only Laravel server diagnostic agent for Linux servers.

Use these guides before implementing or reviewing related parts of the project:

- [architecture.md](architecture.md): system boundaries, component responsibilities, and MVP constraints.
- [security.md](security.md): Telegram identity checks, tool execution safety, and read-only rules.
- [tool-design.md](tool-design.md): how to define safe internal tools and handlers.
- [diagnostics.md](diagnostics.md): scanner behavior for Linux, Nginx, PHP-FPM, MySQL, and Laravel.
- [telegram.md](telegram.md): Telegram send/test and command handling rules.
- [testing.md](testing.md): project-specific testing strategy and required coverage.

## Skill Rules
- Keep MVP behavior read-only and suggest-only.
- Do not add shell command execution from Telegram, AI, config, or SQLite.
- Treat AI as a router only; it may choose a `tool_key`, never execute work directly.
- Store secrets in environment variables, not in SQLite or committed files.
- Prefer small, deterministic handlers with bounded runtime and bounded output.

## Related Planning Docs
- [../../PLANS.md](../../PLANS.md)
- [../../docs/PROJECT-STRUCTURE.md](../../docs/PROJECT-STRUCTURE.md)
- [../../docs/TEST-PLAN.md](../../docs/TEST-PLAN.md)
- [../../docs/IMPLEMENTATION-CHECKLIST.md](../../docs/IMPLEMENTATION-CHECKLIST.md)
