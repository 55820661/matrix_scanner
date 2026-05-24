# Matrix Scanner Architecture Skill

## Purpose
Use this skill when designing or changing Matrix Scanner components, package layout, data flow, or phase boundaries.

## Core Principles
- The MVP is Linux-only, Python-based, SQLite-backed, single-server, read-only, and suggest-only.
- The Internal Server Agent owns execution. Telegram and AI are input layers only.
- Scheduler-driven scans are first-class behavior, not an afterthought.
- Every diagnostic action must be bounded, logged, and safe to run repeatedly.
- Missing services, missing logs, and permission failures should degrade into diagnostic findings, not crashes.

## Component Boundaries
- `cli`: local operator entry point.
- `scheduler`: periodic scan runner and scan storage trigger.
- `telegram_bot`: Telegram long polling, authentication, and command mapping.
- `ai_router`: optional later phase that maps natural language to `tool_key`.
- `tool_executor`: authorization, mode checks, invocation logging, and handler dispatch.
- `tool_registry`: static code allowlist for safe tools.
- `scanners`: read-only collectors for system, services, logs, MySQL, PHP-FPM, and Laravel.
- `alerts`: threshold rules, cooldown, and alert persistence.
- `reports`: concise Arabic summaries and full reports.
- `db`: SQLite schema, migrations, and persistence.

## Required Checks Before Design Changes
- Does the change preserve read-only behavior?
- Is the handler reachable only through a static allowlist?
- Is output bounded and safe for Telegram?
- Is the action logged in `tool_invocations`?
- Does it work when a dependency is missing or unavailable?
- Does it avoid storing secrets in SQLite?

## Common Pitfalls
- Letting AI or Telegram construct shell commands.
- Hiding important failures inside generic "unknown error" output.
- Coupling scanner code to Telegram formatting.
- Adding daemon complexity before CLI behavior is stable.
