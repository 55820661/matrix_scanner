# Matrix Scanner Implementation Checklist

## Phase 0: Foundation + CLI
- [x] Create Python package skeleton.
- [x] Add CLI entry point.
- [x] Add `config.yaml.example`.
- [x] Load non-secret config from file.
- [x] Load secrets from environment.

## Phase 1: SQLite Schema
- [x] Create first-run database initialization.
- [x] Add schema versioning.
- [x] Add `settings`.
- [x] Add `principals`.
- [x] Add `tools_registry`.
- [x] Add `scan_results`.
- [x] Add `alerts`.
- [x] Add `tool_invocations`.
- [x] Add `confirmation_requests`.

## Phase 2: Internal Tool System
- [x] Add static tool registry.
- [x] Add tool executor.
- [x] Add principal authorization.
- [x] Add mode checks.
- [x] Add output truncation.
- [x] Add invocation logging.

## Phase 3: Read-only Scanners
- [x] Add system health scanner.
- [x] Add service status scanner.
- [x] Add Nginx log scanner.
- [x] Add PHP-FPM scanner.
- [x] Add MySQL basic scanner.
- [x] Add Laravel log/runtime scanners.

## Phase 4: Scheduler + Scan Storage
- [x] Add scan orchestration.
- [x] Store scan summaries and raw results.
- [x] Add systemd service template.
- [x] Add systemd timer template.
- [x] Document systemd deployment.
- [ ] Document cron alternative.

## Phase 5: Alert Rules
- [x] Add threshold evaluation.
- [x] Add alert keys.
- [x] Add cooldown.
- [x] Store alerts.
- [x] Generate suggested actions only.

## Phase 6: Reports
- [x] Add status summary.
- [x] Add disk summary.
- [x] Add services summary.
- [x] Add diagnostic summaries.
- [x] Add full report.

## Phase 7: Telegram Send/Test + Commands
- [x] Add Telegram send helper.
- [x] Add `test-telegram`.
- [x] Add long polling bot.
- [x] Add explicit commands.
- [x] Enforce `user_id` / `chat_id` auth.

## Phase 8: AI Routing Later
- [ ] Add JSON-only AI router.
- [ ] Add confidence threshold.
- [ ] Add clarification flow.
- [ ] Keep execution behind tool executor.

## Phase 9: Approved-fix Later
- [ ] Add confirmation requests.
- [ ] Add action allowlist.
- [ ] Add audit trail.
- [ ] Add limited sudoers documentation if needed.
