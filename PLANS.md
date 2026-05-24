# Matrix Scanner Project Plan

## الهدف العام
بناء Laravel Server Diagnostic Agent يعمل على السيرفر نفسه لمراقبة وتشخيص حالة السيرفر والتطبيق، وتخزين نتائج الفحص، وإرسال التنبيهات والتقارير للمستخدم عبر Telegram.

الدور الأساسي في النسخة الأولى هو:
- Read-only: قراءة وفحص فقط.
- Suggest-only: اقتراح إجراءات بدون تنفيذها.
- لا يتم تنفيذ أي تعديل مؤثر على السيرفر في MVP.

## نطاق MVP
- Linux فقط.
- Python.
- SQLite.
- سيرفر واحد فقط.
- Laravel stack:
  - Nginx.
  - PHP-FPM.
  - MySQL.
  - Laravel logs.
  - Queues / Scheduler.

## قرارات التصميم الأساسية
- Telegram بدل WhatsApp.
- Telegram bot يعمل بـ long polling في MVP، وليس webhook.
- الأسرار من environment فقط، مثل:
  - `TELEGRAM_BOT_TOKEN`
  - لاحقًا `OPENAI_API_KEY`
- الإعدادات غير الحساسة في `config.yaml` وSQLite.
- لا يتم الاعتماد على Telegram username.
- التحقق من المستخدم يتم عبر `telegram user_id` أو `chat_id`.
- لا توجد shell commands حرة من Telegram أو AI أو قاعدة البيانات.
- AI يختار `tool_key` فقط.
- Internal Agent هو المسؤول الوحيد عن تنفيذ handlers ثابتة داخل الكود.
- الـ agent يعمل بصلاحيات محدودة قدر الإمكان، وليس root في MVP.

## طريقة التشغيل
### 1. مسار دوري تلقائي
يتم تشغيله من البداية باستخدام scheduler:
- systemd timer.
- أو cron.

يقوم بالآتي:
- تنفيذ scan دوري.
- تخزين النتائج في SQLite.
- مقارنة النتائج بالـ thresholds.
- إنشاء alerts عند وجود مشكلة.
- إرسال Telegram alert عند الحاجة.
- اقتراح إجراء مسموح، بدون تنفيذه.

### 2. مسار On-demand من Telegram
المستخدم يرسل أمرًا أو سؤالًا من Telegram، مثل:
- السيرفر عامل إيه؟
- شوف المساحة.
- اعرض حالة الخدمات.
- شوف أخطاء nginx.
- اعمل تقرير كامل.

في MVP تبدأ الأوامر الصريحة أولًا، ثم يأتي AI routing لاحقًا.

## التصميم العام
```text
Telegram
-> Telegram Bot
-> Optional AI Router
-> Internal Server Agent
-> Tool Executor
-> Safe Handlers
-> SQLite / Direct Read-only Checks
-> Report Formatter
-> Telegram
```

## External AI Agent
يدخل لاحقًا بعد ثبات الأدوات والأوامر الصريحة.

مسؤول عن:
- فهم كلام المستخدم الطبيعي.
- اختيار الأداة المناسبة.
- إرجاع `tool_key` وarguments بصيغة JSON فقط.
- صياغة النتيجة بلغة مفهومة.
- عدم تنفيذ أي شيء مباشرة.

إذا كانت الثقة منخفضة، يطلب توضيحًا بدل اختيار أداة.

## Internal Server Agent
مسؤول عن:
- التحقق من هوية المرسل.
- التحقق من الصلاحيات.
- التحقق من أن الأداة معروفة ومفعلة ومسموحة في الوضع الحالي.
- تنفيذ handlers داخلية آمنة فقط.
- تسجيل كل عملية في SQLite.

## قاعدة البيانات SQLite
### settings
لتخزين الإعدادات القابلة للتعديل وغير الحساسة:
- scan_interval_minutes.
- metrics_retention_days.
- alerts_enabled.
- telegram_enabled.
- confirmation_timeout_seconds.
- thresholds.
- current_mode.

لا يتم تخزين secrets في هذا الجدول.

### principals
لتخزين هويات Telegram المسموح لها:
- telegram_user_id.
- telegram_chat_id.
- display_name.
- role.
- enabled.
- created_at.

### tools_registry
لتعريف metadata للأدوات المتاحة:
- tool_key.
- display_name.
- description.
- enabled.
- type: read_only / diagnostic / action.
- requires_confirmation.
- risk_level.
- handler_name.
- allowed_roles.
- output_type: summary / diagnostic / report.
- max_runtime_seconds.
- max_output_chars.

مهم: هذا الجدول لا يحتوي أوامر shell. التنفيذ يتم عبر allowlist داخل الكود فقط.

### scan_results
لتخزين نتائج الفحص الدوري:
- scan_id.
- started_at.
- finished_at.
- status.
- summary_json.
- raw_result_json.
- error_message.

### alerts
لتخزين المشاكل والتنبيهات:
- alert_id.
- scan_id.
- alert_key.
- severity.
- title.
- evidence_json.
- probable_cause.
- suggested_action.
- requires_confirmation.
- status.
- last_sent_at.
- created_at.

### tool_invocations
لتسجيل كل tool تم طلبه:
- invocation_id.
- source: cli / scheduler / telegram / ai.
- principal_id.
- tool_key.
- input_json.
- output_json.
- status: allowed / denied / failed / completed.
- denial_reason.
- duration_ms.
- created_at.

### confirmation_requests
مؤجل للاستخدام في Approved-fix mode لاحقًا:
- confirmation_id.
- principal_id.
- tool_key.
- requested_action_json.
- confirmation_code.
- expires_at.
- status.
- created_at.

## Tools Registry Safety Rules
- مصدر الحقيقة للـ handlers هو الكود، وليس قاعدة البيانات.
- `handler_name` لا يتم استيراده ديناميكيًا من DB.
- يتم عمل mapping ثابت داخل الكود:
  - `tool_key -> handler function`
- DB يستخدم لتفعيل/تعطيل tool وتخزين metadata فقط.
- لا توجد command templates.
- لا توجد shell args حرة.
- كل output له حد أقصى للحجم.
- كل tool لها timeout.
- كل invocation يتم تسجيله.

## أدوات الفحص الدورية
### system_health_scan
يفحص:
- CPU.
- RAM.
- Disk.
- Load Average.
- Uptime.
- Swap.

### service_status_scan
يفحص حالة:
- nginx.
- php-fpm.
- mysql.
- خدمات إضافية محددة في config.

### nginx_log_summary
يفحص:
- error.log.
- access.log.
- أكثر status codes تكرارًا:
  - 499.
  - 500.
  - 502.
  - 504.
- أكثر endpoints فشلًا أو تكرارًا.

### php_fpm_scan
يفحص:
- service status.
- pool config.
- pm.max_children.
- active / idle processes إذا متاح.
- memory usage.
- مؤشرات workers stuck أو max_children reached.

### mysql_basic_scan
فحص read-only فقط:
- service status.
- max_connections.
- Threads_running.
- Slow_queries.
- innodb_buffer_pool_size.
- processlist summary.

لا يتم تعديل schema أو إضافة indexes أو تغيير MySQL settings في MVP.

### laravel_log_scan
يفحص:
- `storage/logs/laravel.log`.
- الأخطاء الحديثة.
- أكثر exception classes تكرارًا.
- إشارات queue أو DB أو permission errors.

### laravel_runtime_scan
يفحص:
- APP_ENV.
- APP_DEBUG.
- queue status.
- failed_jobs.
- scheduler indicators.

## أدوات عند الطلب
النسخة الأولى تشمل:
- get_status.
- get_disk.
- get_services.
- get_nginx_errors.
- get_php_fpm_status.
- get_mysql_status.
- get_laravel_errors.
- generate_report.

## طبيعة المخرجات
### أوامر بسيطة
مثل:
- status.
- disk.
- services.

ترجع ملخصًا قصيرًا:
```text
الحالة العامة: جيدة
CPU: 18%
RAM: 62%
Disk: 71%
Nginx: يعمل
PHP-FPM: يعمل
MySQL: يعمل
```

### أوامر تشخيصية
مثل:
- get_nginx_errors.
- get_laravel_errors.
- get_mysql_status.

ترجع:
- ملخص.
- أهم الأدلة.
- السبب المحتمل.
- اقتراح مختصر.

### تقرير كامل
فقط عند طلب:
- generate_report.
- أو "اعمل تقرير كامل".

ويحتوي:
1. ملخص الحالة.
2. المشاكل المكتشفة.
3. الأدلة من اللوج.
4. درجة الخطورة.
5. السبب المرجح.
6. الإجراء المقترح.
7. هل يحتاج موافقة قبل التنفيذ لاحقًا.

## Alert Rules
الـ thresholds المبدئية:
- CPU > 85%.
- RAM > 85%.
- Disk > 90%.
- service down.
- Laravel recent critical errors.
- Nginx 502/504 spike.

قواعد التنبيه:
- لا يتم إرسال نفس التنبيه بشكل متكرر بلا تغيير.
- يوجد cooldown لكل `alert_key`.
- كل alert يحتوي evidence وprobable cause وsuggested action.
- لا يوجد تنفيذ fixes في MVP.

## Telegram Integration
### الإرسال
- إرسال alerts.
- إرسال test message.
- إرسال reports عند الطلب.

### الأوامر الصريحة في MVP
- `/status`
- `/disk`
- `/services`
- `/nginx`
- `/laravel`
- `/report`

### الأمان
- التحقق من `user_id` و`chat_id`.
- رفض أو تجاهل أي مرسل غير مصرح.
- تسجيل كل أمر في `tool_invocations`.
- لا يتم تنفيذ shell commands من الرسائل.

## أوضاع النظام
في البداية:
- `read_only = true`
- `suggest_only = true`
- `approved_fix = false`

لاحقًا يمكن دعم:
- Diagnostic mode.
- Approved-fix mode.

## ما يتم تأجيله
لا يدخل في MVP:
- restart للخدمات.
- clear cache.
- supervisor control.
- git pull.
- composer.
- artisan migrate.
- mysql update.
- تعديل config.
- إضافة index تلقائيًا.
- تفعيل slow query log تلقائيًا.
- حذف ملفات.
- تعديل ملفات.

أي شيء مؤثر يدخل لاحقًا تحت Approved-fix mode وبموافقة صريحة.

## Structure مقترح للكود
```text
matrix_scanner/
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
    system.py
    services.py
    nginx.py
    php_fpm.py
    mysql.py
    laravel.py
  tools/
    status.py
    disk.py
    services.py
    logs.py
    report.py
  alerts/
    rules.py
    notifier.py
    cooldown.py
  reports/
    formatter.py
    summarizer.py
```

## خطة التنفيذ
### Phase 0: Foundation + CLI
- إنشاء Python package باسم `matrix_scanner`.
- إضافة CLI:
  - `matrix-scanner scan`.
  - `matrix-scanner status`.
  - `matrix-scanner report`.
  - `matrix-scanner test-telegram`.
- إضافة `config.yaml.example`.
- قراءة secrets من environment.
- قراءة إعدادات Laravel path والخدمات من config.

### Phase 1: SQLite Schema
- إنشاء SQLite database تلقائيًا عند أول تشغيل.
- إضافة الجداول الأساسية:
  - settings.
  - principals.
  - tools_registry.
  - scan_results.
  - alerts.
  - tool_invocations.
  - confirmation_requests.
- إضافة migration أو schema version بسيط.

### Phase 2: Internal Tool System
- بناء `tool_registry.py`.
- بناء `tool_executor.py`.
- تنفيذ auth/authorization.
- تنفيذ mode checks.
- تسجيل كل tool invocation.
- منع أي tool غير مسجلة في allowlist.

### Phase 3: Read-only Scanners
- تنفيذ system health scanner.
- تنفيذ service status scanner.
- تنفيذ nginx log scanner.
- تنفيذ php-fpm scanner.
- تنفيذ mysql basic scanner.
- تنفيذ laravel log/runtime scanners.
- التعامل مع الملفات أو الخدمات غير المتاحة بدون crash.

### Phase 4: Scheduler + Scan Storage
- دعم تشغيل scan يدويًا من CLI.
- دعم systemd timer أو cron.
- تخزين نتائج كل scan في SQLite.
- حفظ raw result وsummary.
- تجهيز ملفات systemd اختيارية:
  - `matrix-scanner-scan.service`.
  - `matrix-scanner-scan.timer`.

### Phase 5: Alert Rules
- تنفيذ thresholds.
- تنفيذ alert cooldown.
- تخزين alerts في SQLite.
- إرسال alert فقط عند وجود مشكلة جديدة أو تغير مهم.
- توليد suggested action بدون تنفيذ.

### Phase 6: Reports
- تنفيذ status summary.
- تنفيذ disk summary.
- تنفيذ services summary.
- تنفيذ diagnostic summaries.
- تنفيذ full report.
- تنسيق النتائج بالعربية بشكل واضح ومختصر.

### Phase 7: Telegram Send/Test + Commands
- تنفيذ Telegram send.
- تنفيذ `test-telegram`.
- تنفيذ long polling bot.
- دعم الأوامر الصريحة:
  - `/status`
  - `/disk`
  - `/services`
  - `/nginx`
  - `/laravel`
  - `/report`
- تطبيق auth على `user_id` و`chat_id`.

### Phase 8: AI Routing لاحقًا
- إضافة `ai_router.py`.
- تحويل اللغة الطبيعية إلى `tool_key`.
- إجبار AI على JSON output.
- رفض الأوامر منخفضة الثقة.
- إبقاء التنفيذ داخل Internal Agent فقط.

### Phase 9: Approved-fix لاحقًا
- إضافة confirmation flow.
- إضافة allowlist للأوامر المؤثرة.
- إضافة sudoers محدود عند الحاجة.
- تسجيل audit كامل.
- عدم تنفيذ أي fix بدون موافقة صريحة.

## أول Sprint عملي
1. تثبيت هذه الخطة في `PLANS.md`.
2. إنشاء skeleton للمشروع.
3. تنفيذ config + SQLite schema.
4. تنفيذ CLI commands الأساسية.
5. تنفيذ scanners read-only الأولى.
6. تنفيذ scheduler + scan storage.
7. تنفيذ alert rules.
8. تنفيذ reports.
9. إضافة Telegram send/test.
10. إضافة Telegram commands.
