# Matrix Scanner Diagnostics Skill

## Purpose
Use this skill when implementing read-only scanners for Linux, Nginx, PHP-FPM, MySQL, and Laravel.

## General Scanner Rules
- Scanners collect facts only. They do not send alerts, write reports, or execute fixes.
- Scanner output should be structured dictionaries suitable for SQLite JSON storage.
- Each scanner should identify:
  - status.
  - evidence.
  - warnings.
  - permission or availability limitations.
- A scanner failure should become a partial result, not a process crash.

## System Health
Collect:
- CPU percentage.
- RAM usage.
- disk usage.
- load average.
- uptime.
- swap usage.

Prefer Python libraries such as `psutil` once dependencies are introduced.

## Services
Check configured services:
- nginx.
- php-fpm.
- mysql.
- additional config-defined services.

Use read-only status checks. Do not restart, reload, enable, disable, or modify services.

## Nginx
Read configured log paths:
- access log.
- error log.

Summarize:
- recent errors.
- common status codes.
- spikes in 499, 500, 502, and 504.
- frequent failing endpoints.

Avoid returning large raw log blocks.

## PHP-FPM
Collect when available:
- service status.
- pool config values such as `pm.max_children`.
- process counts.
- memory usage.
- signs of `max_children` pressure.

Do not edit pool config.

## MySQL
Read-only checks only:
- service status.
- `max_connections`.
- `Threads_running`.
- `Slow_queries`.
- `innodb_buffer_pool_size`.
- processlist summary.

Do not change schema, indexes, variables, or logs in MVP.

## Laravel
Inspect configured Laravel project path:
- `storage/logs/laravel.log`.
- `.env` values needed for diagnostics only, such as `APP_ENV` and `APP_DEBUG`.
- queue and scheduler indicators when safely available.
- failed jobs if accessible.

Never expose full `.env` contents.
