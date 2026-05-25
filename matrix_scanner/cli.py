from __future__ import annotations

import argparse
import json
import locale
import signal
import sys
import threading
from pathlib import Path

from matrix_scanner import db
from matrix_scanner.config import load_config
from matrix_scanner.scheduler import run_scan
from matrix_scanner.setup import run_interactive_setup
from matrix_scanner.telegram_bot import TelegramPollingConflict, run_long_polling, send_message
from matrix_scanner.tool_executor import execute_tool
from matrix_scanner.tool_registry import build_registry


def main(argv: list[str] | None = None) -> int:
    _configure_output_encoding()
    parser = argparse.ArgumentParser(prog="matrix-scanner")
    parser.add_argument("--config", default="config.yaml", help="Path to config file.")
    sub = parser.add_subparsers(dest="command", required=True)
    setup = sub.add_parser("setup")
    setup.add_argument("--force", action="store_true", help="Overwrite config file if it already exists.")
    setup.add_argument("--all-services", action="store_true", help="Show all systemd services instead of candidate application services.")
    setup.add_argument("--include-inactive", action="store_true", help="Include inactive services in the setup list.")
    sub.add_parser("init-db")
    sub.add_parser("scan")
    sub.add_parser("status")
    sub.add_parser("performance")
    sub.add_parser("disk")
    sub.add_parser("services")
    sub.add_parser("report")
    sub.add_parser("top")
    sub.add_parser("apache")
    sub.add_parser("5xx")
    sub.add_parser("laravel-log")
    sub.add_parser("laravel-env")
    sub.add_parser("laravel-exceptions")
    sub.add_parser("queue")
    sub.add_parser("supervisor")
    sub.add_parser("cron")
    sub.add_parser("suspicious")
    telegram = sub.add_parser("test-telegram")
    telegram.add_argument("--chat-id", help="Override Telegram chat id.")
    bot = sub.add_parser("telegram-bot")
    bot.add_argument("--once", action="store_true", help="Run one long-poll iteration and exit.")

    args = parser.parse_args(argv)
    if args.command == "setup":
        try:
            created = run_interactive_setup(
                Path(args.config),
                force=args.force,
                all_services=args.all_services,
                include_inactive=args.include_inactive,
                input_func=_safe_input,
            )
        except KeyboardInterrupt:
            print("\nSetup cancelled. No changes were made.")
            return 130
        if created:
            print(f"Config written to {args.config}")
            return 0
        print("Config was not changed.")
        return 1

    app_config = load_config(args.config if Path(args.config).exists() else None)
    conn = db.connect(app_config.database_path)
    registry = build_registry()
    db.sync_tools_registry(conn, registry)
    context = {"config": app_config.values}

    if args.command == "init-db":
        print(f"SQLite database is ready: {app_config.database_path}")
        return 0
    if args.command == "scan":
        result = run_scan(conn, app_config.values, telegram_token=app_config.telegram_bot_token)
        for warning in result.get("notification", {}).get("warnings", []):
            print(f"Warning: {warning}", file=sys.stderr)
        print(json.dumps({"scan_id": result["scan_id"], "summary": result["summary"], "alerts": result["alerts"]}, ensure_ascii=False, indent=2))
        return 0
    if args.command == "test-telegram":
        return _test_telegram(app_config, args.chat_id)
    if args.command == "telegram-bot":
        return _telegram_bot(app_config, conn, registry, stop_after=1 if args.once else None)

    tool_key = {
        "status": "get_status",
        "performance": "server_performance",
        "disk": "get_disk",
        "services": "get_services",
        "report": "generate_report",
        "top": "top_processes",
        "apache": "apache_error_summary",
        "5xx": "apache_5xx_summary",
        "laravel-log": "laravel_log_health",
        "laravel-env": "laravel_env_sanity",
        "laravel-exceptions": "laravel_exception_summary",
        "queue": "queue_workers_summary",
        "supervisor": "supervisor_summary",
        "cron": "suspicious_cron_scan",
        "suspicious": "suspicious_files_scan",
    }[args.command]
    result = execute_tool(conn, registry, tool_key=tool_key, context=context, source="cli")
    print(_display_result(result))
    return 0 if result.get("ok") else 1


def _display_result(result: dict) -> str:
    if not result.get("ok"):
        return f"Error: {result.get('error')}"
    output = result.get("output", {})
    return output.get("summary_text") or output.get("report_text") or json.dumps(output, ensure_ascii=False, indent=2)


def _test_telegram(app_config, chat_id: str | None) -> int:
    token = app_config.telegram_bot_token
    target = chat_id or app_config.values.get("telegram", {}).get("default_chat_id")
    if not token:
        print("TELEGRAM_BOT_TOKEN is not set.", file=sys.stderr)
        return 1
    if not target:
        print("Telegram chat id is not configured.", file=sys.stderr)
        return 1
    response = send_message(token, target, "Matrix Scanner test message")
    print(json.dumps(response, ensure_ascii=False, indent=2))
    return 0


def _telegram_bot(app_config, conn, registry, stop_after: int | None = None) -> int:
    token = app_config.telegram_bot_token
    if not token:
        print("TELEGRAM_BOT_TOKEN is not set.", file=sys.stderr)
        return 1
    stop_event = threading.Event()
    previous_sigterm = _install_sigterm_handler(stop_event)
    try:
        run_long_polling(conn=conn, registry=registry, config=app_config.values, token=token, stop_after=stop_after, stop_event=stop_event)
        return 0
    except TelegramPollingConflict as exc:
        print(str(exc), file=sys.stderr)
        print("Stop the existing telegram-bot service/process before starting another long polling instance.", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nTelegram bot stopped.")
        return 130
    finally:
        if previous_sigterm is not None:
            signal.signal(signal.SIGTERM, previous_sigterm)


def _install_sigterm_handler(stop_event: threading.Event):
    if not hasattr(signal, "SIGTERM"):
        return None
    previous = signal.getsignal(signal.SIGTERM)

    def _handler(signum, frame):
        stop_event.set()
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, _handler)
    return previous


def _configure_output_encoding() -> None:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8")
            except OSError:
                pass


def _safe_input(prompt: str) -> str:
    sys.stdout.write(prompt)
    sys.stdout.flush()
    stream = getattr(sys.stdin, "buffer", None)
    if stream is None:
        try:
            return input()
        except UnicodeDecodeError:
            print("\nInvalid input encoding. Please try again.")
            return ""
    raw = stream.readline()
    if raw == b"":
        raise EOFError
    encoding = sys.stdin.encoding or locale.getpreferredencoding(False) or "utf-8"
    return raw.decode(encoding, errors="replace").rstrip("\r\n")


if __name__ == "__main__":
    raise SystemExit(main())
