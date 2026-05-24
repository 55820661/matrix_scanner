# Matrix Scanner Systemd Deployment

Use these steps on the target Linux server after installing the package in `/opt/matrix-scanner`.

## 1. Environment
Create `/etc/matrix-scanner/matrix-scanner.env`:

```bash
TELEGRAM_BOT_TOKEN=replace-me
```

Do not store secrets in `config.yaml`.

## 2. Config
Create `/etc/matrix-scanner/config.yaml` from `config.yaml.example` and set:
- `database_path`
- Laravel paths
- service names
- Telegram `allowed_user_ids` or `allowed_chat_ids`

## 3. Telegram Bot Service
Install:

```bash
sudo cp deploy/matrix-scanner-telegram-bot.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now matrix-scanner-telegram-bot.service
sudo systemctl status matrix-scanner-telegram-bot.service
```

## 4. Periodic Scan Timer
Install after the bot service is working:

```bash
sudo cp deploy/matrix-scanner-scan.service /etc/systemd/system/
sudo cp deploy/matrix-scanner-scan.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now matrix-scanner-scan.timer
sudo systemctl list-timers matrix-scanner-scan.timer
```

## 5. Manual Checks
```bash
/opt/matrix-scanner/.venv/bin/matrix-scanner --config /etc/matrix-scanner/config.yaml status
/opt/matrix-scanner/.venv/bin/matrix-scanner --config /etc/matrix-scanner/config.yaml scan
/opt/matrix-scanner/.venv/bin/matrix-scanner --config /etc/matrix-scanner/config.yaml test-telegram
```

## Safety Notes
- Run as a limited `matrix-scanner` user.
- Grant read access only to required logs and configs.
- Do not run as root for MVP unless file permissions force it temporarily during testing.
- No Approved-fix actions are enabled in MVP.
