# مرجع الحقائق التشغيلية — SM Pro

> ملف مرجعى دائم فى المستودع. كل حقيقة تشغيلية مهمة (سيرفرات، إصدارات، قرارات، أوامر تراجع، حوادث) تتسجل هنا
> وتتحدث مع كل نشر. اللى هنا هو المصدر اللى أى حد يرجع له قبل ما يلمس سيرفر.
> قاعدة: مفيش باسوردات ولا مفاتيح هنا أبداً. المسارات والأوامر زى ما هى.

## 1. السيرفرات والوصول
- **dc1** = `5.9.54.26` (dc1.efadh.com)، CloudLinux 9.8، cPanel، nginx قدام Apache (ea-nginx)، KernelCare شغال. الدخول: `ssh -i ~/.ssh/cpanel_audit_178_63_134_16 root@5.9.54.26`. الشبكة بتقطع أحياناً: استخدم `ssh -n` أو `bash -s < script`، ومع الخلفية `</dev/null`.
- **dc2** = `178.63.134.16`: **ممنوع نهائياً الدخول root عليه**. المالك بينفذ أوامره بنفسه.
- **اللاب (بوابة الإصدار)** = `167.233.29.168`، المسار `/opt/smpro-testlab/src`.
- **سيرفر الترخيص** = `136.243.211.154`، المجلد `/opt/aitech-license-server`، نفس مفتاح SSH.

## 2. نسخة العمل والبناء والنشر
- نسخة العمل: `C:\Users\Salam Dev\smprov1_build`.
- البناء: `bash build/obfuscate-and-package.sh </dev/null` (بوابة اللاب + بوابة الهاردكود). **لازم ترفع `SMPRO_VERSION` فى `includes/defines.php` قبل البناء** (نسيت مرة).
- النشر: `cd packaging && bash PUBLISH.sh 1.1.10-betaNNN` (بيطلب ملف `smpro-1.1.10-betaNNN.RELEASE-NOTES.txt` موجود). `--stable` لترقية الـ STABLE.
- التنزيل على dc1: من المجلد `/usr/local/cpanel/whostmgr/docroot/cgi/addons/smpro`:
  `php -r 'define("SMPRO_BOOT",1); foreach(["defines","env","mmdb","helpers","secret","license","intrusion","update"] as $m) require_once "includes/$m.php"; echo json_encode(smpro_upd_apply("1.1.10-betaNNN"));'` (بـ `/usr/local/cpanel/3rdparty/bin/php`).
- سكريبتات الباتش تتكتب بأداة Write (الـ heredoc بيكسر الباك سلاش). الملفات CRLF.
- قواعد: مفيش كود خاص بسيرفر/عميل؛ مفيش `catch` فاضى (استخدم `smpro_soft_fail`)؛ "فحص ماقدرش يشتغل مايظهرش كأنه ملقاش حاجة"؛ أى إصلاح يدوى على سيرفر لازم يبقى ميزة منتج.

## 3. حالة الإصدارات (محدّث 21 أكتوبر 2026 11:56)
| | |
|---|---|
| STABLE | **1.1.10-beta349** (22 أكتوبر 00:44؛ 21 أكتوبر شاف 344→348، و333 من 14 أكتوبر) |
| BETA | 1.1.10-beta349 (dc1 عليه) |
| آخر بناء | beta347: جيت أخضر؛ بصمة `b46f03f3…`؛ التراجع على سيرفر الترخيص: `cp -f smpro-prev.tar.gz smpro-latest.tar.gz && cp -f VERSION.prev VERSION` |
- beta341: Learned Defense — درس باسم الملف النادر، فحص `.htaccess` اللى بيخلى امتداد غريب CGI، فحص ملفات ELF فى مجلدات الويب. اختبار t137.
- beta342: تكامل MailGuard (قراءة فقط) — `includes/mailguard.php`، اختبار t138.
- beta343/344: Site Shield — `includes/siteshield.php`، كارت فى صفحة Bot Guard، اختبار t139؛ 344 بتقفل كاش nginx للحساب المحمى.

## 4. حادثة حساب `ma` على dc1 (20 أكتوبر)
- الحساب `ma` (m.efadh.net، ea-php73، باقة VIP، 39GB، 105 قاعدة بيانات) = **أرشيف/ديمو**: 124 مجلد تحت public_html (101 OpenCart، 11 WordPress)، **صفر دومينات مضافة**، 66 مجلد مالمسهوش حد من أكتر من سنة. كله بيتفتح من `m.efadh.net/<مجلد>/`. الزيارات الوحيدة = سكانرات من Google Cloud وبوتات AI.
- اتلقى واتعزل (مع باكب tar قبل أى نقل) فى `/root/dc1-isolate-ma-cgibin-20261020-1414/`:
  - `apco/wp-includes/cgi-bin/`: Tiny File Manager WH1Z (1.9MB)، `cr64.cgi` = b374k CGI-Telnet (Perl، باسورد "crazy")، symlinks باسم error_log على لوجات Apache، مجلد c1 فيه نسخة WP كاملة + wp.zip 58MB.
  - `onstore/cgi-bin/`: `.htaccess` بيخلى `.ss` و `.pl` تشتغل CGI، استغلالات نواة جاهزة **CVE-2026-31429** و **CVE-2026-31431 (Copy Fail)** مع .git، ملف ELF مبنى `exp-cr`، `cr-64.ss` شيل Perl (أبريل–مايو 2026).
  - `a2z/cgi-bin/ALFA_DATA` (كيت Alfa symlink، يوليو 2025)، `toys/cgi-bin` (`wv42.php` phar stub، أبريل 2026)، `allgames/cgi-bin`، `almohsen/cgi-bin/.img`، `public_html/cgi-bin/cr.cgi`، `life/wp-includes/images/wlw/.htaccess` (+ `md5.sa`).
- المهاجم كان نشط آخر مرة 14 أبريل 2026 (من error_log بتاعه). لوجات Apache بترجع لأكتوبر بس.
- **فحص اختراق root (قراءة فقط): نظيف** — مفيش uid 0 إضافى، مفيش setuid غريب، rpm -Va نظيف، مفيش ld.so.preload، مفيش memfd، السوكتات معروفة، كل دخول root من مصر، dmesg نظيف.
- **النواة**: الشغالة `5.14.0-570.30.1` (بوت 28 فبراير 2026)، KernelCare بيرقّعها حى لمستوى `687.57.1` (744 CVE) **ومنهم Copy Fail**. مفيش ترقيع لـ CVE-2026-31429 (معلوماته العامة قليلة). الريستارت **مش عاجل**، نظافة فى نافذة صيانة.
- مفتاح SSH فى `/home/ma/.ssh/authorized_keys` (RSA من PuTTY، تعليق "server"، 30 أغسطس): المالك قال **سيبه**.

## 5. قرارات اتنفذت على dc1 (21 أكتوبر)
- سطر كرون root `0 3 * * * node /home/rbmwhats/public_html/app.js` **اتشال** (باكب `/root/dc1-decisions-20261021-0936/root-crontab.before`).
- `res.php` و `ser.php` (نفس البصمة `8f481983…`) فى tmp بتاع mohamedefadh و mohamedfaridefad **اتعزلوا** فى `/root/dc1-decisions-20261021-0936/`، واتعلّموا فى Learned Defense.
- Learned Defense على dc1: 49 درس، مشتركين على سيرفر الترخيص (الـ pool = 27). سيرفر الترخيص بيقبل نوع `name` (باكب `_archive/lessons_ext.php.pre-name.*`).
- إنذار كاذب معروف: `entropybanner.cgi` و `randhtml.cgi` (ELF، نفس md5 فى 12 متجر قديم) = ملفات cPanel القديمة. تحسين مقترح: ELF بنفس البصمة فى ≥3 مواقع = قالب مش اكتشاف (لسه مش مبنى).

## 6. PHP disable_functions على dc1 (20 أكتوبر ~17:19)
- اتطبق `disable_functions = system,pcntl_exec` على ea-php56/70/71/72/73/74/80/81/82/83/84. ea-php85 المجلد موجود بس الحزمة مش متسطبة. alt-php (CloudLinux Selector) آلية منفصلة متلمستش.
- الباكب: `/root/php-disable-functions-20261020-1719/before.txt` (كلها كانت فاضية).
- التراجع: `for v in $(ls -d /opt/cpanel/ea-php* | xargs -n1 basename); do whmapi1 php_ini_set_directives version=$v directive=disable_functions%3A; done`
- صيغة الـ API الشغالة: `directive=disable_functions%3Asystem%2Cpcntl_exec`.
- اللى اتساب مفتوح وليه: `popen` (PHPMailer وضع sendmail، WP Mail SMTP Pro على مواقع boefadh)، `exec`/`shell_exec`/`proc_open`/`passthru` (Laravel: symfony/process و artisan و scheduler من 18 كرون، phpseclib، Imunify).
- **مفيش إصدار PHP نظيف** (كل إصدار فيه Laravel أو OpenCart أو phpseclib)؛ الاستثناء لكل موقع مستحيل (PHP_INI_SYSTEM).
- mohamed.efadh.net بيرجّع 500 من 2020 (index.php ووردبريس من غير ووردبريس) — مش بسبب القفل.
- إصدارات PHP على dc1 محدثة لآخر الرسمى (8.2.34 / 8.3.35 / 8.4.26 يوم 19 أكتوبر). **إصدار أمنى حرج لـ PHP** معلن ليوم 21 أكتوبر 14:00 UTC (ثغرتين CVSS 9.2)؛ cPanel بيحدث ليلياً 23:16؛ 68 من 82 موقع على إصدارات بلا دعم رسمى (8.1 وأقدم) معتمدين على CloudLinux.
- الرودماب (HTML عربى): `D:\Flash\old site\whm\dc1-disable-functions-roadmap.html`. المراحل 2 (مراجعة 2,587 ملف كود مواقع)، 3 (تجميع Laravel على 8.2)، 4 (ميزة Security Health بـ Apply/Undo) **لسه**.

## 7. تكامل MailGuard (beta342)
- MailGuard 2.4.3 على dc1: `/opt/mailguard`، `/etc/mailguard/config.json` + `lists/*.list`، `/var/lib/mailguard/mailguard.sqlite3`، قفل `exim-rebuild.lock` (flock).
- من ناحيته (كوده): بيقرأ ويكتب `/etc/smpro_blocked_senders`؛ قاعدة Exim خاصة به للقائمة فى `/usr/local/cpanel/etc/exim/acls/ACL_MAIL_BLOCK/shared_sender_blocklist`؛ بيصلّح قاعدة SM Pro القديمة لو فى مكان غلط؛ بيقرأ GeoIP من `/var/lib/smpro/geoip`.
- من ناحية SM Pro (قراءة فقط): لوحة فى Spam & phishing، جدول الطبقات صادق (قائمة واحدة لمنتجين)، مفيش deny تانى لو قاعدة MailGuard موجودة، إعادة بناء Exim بقفل MailGuard، التعطيل بيقول لو MailGuard لسه بيحظر، كارت فى Security Health، Learned Defense بيثق فى ملفاته وبيعرض اللى نسب له إرسال بريد (مجلد maalem11: 299 إجراء).

## 8. Site Shield (beta343/344، شغال على dc1)
- الهدف: m.efadh.net (وأى دومين) تفضل مساراته شغالة للبشر، والسكانرات تتمنع. الحل: include لكل vhost فى `/etc/apache2/conf.d/userdata/{std,ssl}/2_4/<user>/<domain>/smpro-siteshield.conf`: `Require not ip` لكل بادئة من قوائم VPN (11,105) + هوستنج (44,595) بتاعة netkind، 403 لأدوات الفحص (User-Agent) ولمسارات التجسس (.env/.git/…)، وعناوين المالك (self-allow + firewall allow) بتعدى دايماً. Apache بيشوف العنوان الحقيقى عبر mod_remoteip (X-Real-IP من nginx).
- التركيب: write → `/scripts/rebuildhttpdconf` → `apachectl configtest` → `apachectl graceful`؛ لو الاختبار رفض بتتشال الملفات ويتعاد البناء. Dry-Run مابيركّبش. الحالة بتتقرى من httpd.conf المولّد.
- التحديث: `smpro_ss_refresh()` من `bin/geologin_tick.php` بعد تحديث القوائم.
- خطوات بعد الجيت: نشر → تنزيل على dc1 → تفعيل على m.efadh.net من صفحة Bot Guard (أو `smpro_ss_enable("m.efadh.net")`) → اختبار: مسار عادى 200، `/.env` 403، وطلب على `127.0.0.1:81` بهيدر `X-Real-IP: 34.185.66.194` (عنوان هوستنج) لازم 403.
- قرار المالك: **ب** (الدرع) + **ج** (المراقبة الهيكلية كل 10 دقايق). **مش** أرشفة.
- **اتنفذ 21 أكتوبر**: beta343 منشورة (commit 4d6bfd4) ومنزّلة على dc1؛ الدرع مفعّل على m.efadh.net (51,323 بادئة، 45 عنوان مالك مسموح). **اكتشاف**: كاش nginx بتاع الحساب كان بيسلّم الصفحة المخزنة للسكانر من غير ما Apache يشوف الطلب → اتقفل الكاش لحساب ma يدوى (`ea-nginx cache ma --enabled=0` + `clear_cache`)، والخطوة دى اتضافت للكود فى beta344 (قيد البناء). **التحقق**: من سيرفر الترخيص (هوستنج) → 403 على m.efadh.net و200 على efadh.net؛ من البيت → 200؛ User-Agent سكانر → 403؛ Bot Guard page بترندر. **حد معروف**: القوائم IPv4 فقط، زائر IPv6 مابيترفضش بالشبكة (اللاب على IPv6 جاب 200، وعلى IPv4 جاب 403).
- بعد تنزيل beta344 على dc1: سجّل `nginx_cache_off: true` لدومين m.efadh.net فى `/var/lib/smpro/siteshield.json` علشان الإزالة ترجّع الكاش.

## 9. قرارات لسه معلقة عند المالك
1. قفل `popen` (هيكسر WP Mail SMTP وضع sendmail).
2. ريستارت dc1 فى نافذة صيانة (مش عاجل).
3. ~~ترقية beta → stable~~ اتعملت 21 أكتوبر (beta344 = STABLE). dc2 بياخدها من كرون التحديث بتاعه.
4. `geowall` (الجدار المسبق للدول) لسه OFF.
5. حذف `/home2/old` مؤجل (لحد ما المالك يطلب).
6. WP Guard المرحلة 2 (virtual patches + قسم ثغرات كل 3 أيام): التقرير فى `D:\Flash\old site\whm\wpguard-vuln-section-report.md`؛ المالك يلصق فى جلسة WP Guard: `اقرا D:\Flash\old site\whm\wpguard-vuln-section-report.md ونفّذ المطلوب فيه`.
7. مصدر تسريب باسوردات 50 حساب على dc2 لسه مجهول.
8. متابعة وصول الإصدار الأمنى لـ PHP على dc1 (22 أكتوبر).
9. تحسين: ELF المتكرر بنفس البصمة = قالب (إنذار cPanel القديم).

## 10. توكنات الـ API وأبواب الحسابات (beta345، 21 أكتوبر)
- **باج اتصلح**: ملف توكنات cPanel مفاتيحه هاش والاسم جوه السجل، بينما الـ API مفاتيحه أسماء. الكود كان بيقارن الهاش بـ `reverse_trust_` فالمقارنة تفشل دايماً → كل الـ32 توكن ظهروا كأن المشغّل عملهم بأسماء هاش. الحل: ترتيب المصدرين بالاسم.
- **الواقع على dc1**: صفر توكن من المشغّل؛ 32 `reverse_trust_*` عملهم cPanel لنقل الحسابات (يناير 2025 → مايو 2026)، كل واحد بيقدر يعمل كل حاجة root ومابينتهيش؛ 10 منهم اتستخدموا، آخر استخدام 21 أكتوبر 02:22.
- **كل توكن بيعرض**: بيقدر يعمل إيه · اتعمل امتى · مين عمله ومن أى عنوان (access_log) · بينتهى امتى أو NEVER · آخر استخدام ومن فين (api_tokens_log) · مسموح من عناوين معينة. المجهول بيتكتب "غير معروف".
- **تعطيل**: زرار Disable لتوكنات WHM = `whmapi1 api_token_update token_name=X expires_at=<ماضى>` (بيحتفظ بالاسم والتاريخ، بيرفض reverse_trust). توكنات الحسابات: cPanel مابيوفرش تعطيل، الإلغاء بس.
- **FTP**: الحذف بيشيل اللوجن بس (`destroy=0`)، الملفات والمجلد مابيتلمسوش؛ الزرار والرسالة بيقولوا كده.
- **شرح الأبواب**: Shell start-up = سطر فى `~/.bashrc`/`~/.bash_profile`/`~/.profile` وبيشتغل مع كل شل (كرون و SSH كمان) فبيرجع بعد التنظيف. Contact e-mail = العنوان اللى بيروح له بريد الحساب وروابط إعادة تعيين كلمة السر.

## 11. حارس البايتات فى النشر (21 أكتوبر)
- **اللى حصل**: بناء قديم فى الخلفية أعاد بناء الـ tarball **بعد** النشر. بناءين من نفس الكود مش متطابقين بايت ببايت، فالملف المحلى لـ beta345 (`1661094706bb9a1d…`) بقى مختلف عن المخدوم (`4f5f4fecef057630…`). الملف المحلى وإيصال الجيت متفقين مع بعض، فإعادة نشر كانت هتعدّى كل الفحوص وتبدّل بايتات العملاء تحت نفس رقم الإصدار.
- **الحارس** (فى `packaging/PUBLISH.sh` قبل الرفع): يقرأ الإصدار المخدوم للقناة؛ لو نفس الرقم وبصمة مختلفة → رفض مع عرض البصمتين وطلب رقم إصدار جديد. نفس البايتات بالظبط لسه مسموحة (لإصلاح رفع ناقص). اتجرب حى ورفض beta345. اختبار `t141`.
- **القاعدة**: رقم الإصدار وعد بخصوص البايتات؛ إصدار واحد مايبقاش معناه بناءين.
- **المهم عملياً**: البناء **المخدوم** هو الحقيقة لـ beta345 (اتأكدنا منه حى على dc1). ماتعيدش نشر beta345 من الملف المحلى؛ أى تغيير = beta346.

## 12. beta346 (21 أكتوبر 23:21) — اللى اتضاف
- **System updates** (صفحة جديدة): فحص كل 6 ساعات (دايماً شغال)، عرض المعلق بنوعه، cPanel مقابل TIERS، النواة (الشغالة/على القرص/الترقيع الحى)، وضع يدوى أو تلقائى (ساعة محددة، مرة يومياً، بدون ريبوت)، تشخيص أعطال التنزيل وإصلاح الآمن منها (كاش، قفل عالق، قاعدة rpm، تخطى ريبو واحد معطّل)، فحص الخدمات بعد التحديث، 3 أنواع تنبيه. "ماقدرش يفحص" حالة مستقلة مش صفر.
- **هوك Safety Lock مع صيانة cPanel** (سبب مشكلة dc2): `005-smpro-safetylock-release` و `995-smpro-safetylock-relock` فى مجلدات هوك dnf اللى فيها `009-phpconf.pl`، وسطر فى `/scripts/preupcp` و `/scripts/postupcp`، سجل `/var/lib/smpro/php_harden/maint_release.json`، مؤقّت أمان ساعتين. متركّب على dc1 (مفيش ملفات مقفولة هناك)؛ الاختبار الحقيقى تحديث PHP الجماعى على dc2.
- **session.upload_progress = Off**: فحص فى Security Health مع Apply/Undo؛ اتطبق على dc1 (13 ملف php.ini).
- **توكنات الحسابات**: Revoke + Disable لأى توكن مهما كان عمره؛ Disable عبر `Cpanel::Security::Authn::APITokens::Write::cpanel` مع قراءة للتأكيد.
- **Learned Defense**: تصميم جديد (شريط حالة، اكتشافات مجمّعة بالحساب مع خطورة وفلاتر، عزل كل المطابقات التامة بضغطة، كروت Hunt/Teach/Settings).
- **PUBLISH.sh**: حارس البايتات كان بيوقف النشر صامت تحت `set -e` (استبدال أمر فاشل)؛ اتصلح.

## 13. حادثة drosat.com على dc2 (21 أكتوبر)
- العرض: 508 لكل الطلبات. السبب: سجل cPanel للدومين بقى `alt-php56` + FPM لخدمة مش شغالة (الساعة 21:45، غالباً هوك تحديث PHP وقت تحديث `alt-php-config`)، والتطبيق Laravel على 8.4. حدود LVE سليمة.
- الحل (المالك نفّذه): `whmapi1 php_set_vhost_versions version=alt-php84 vhost=drosat.com php_fpm=0` → 200. `alt-php84-php-fpm` مش شغالة على dc2؛ لو عايز FPM شغّلها الأول.
- المطلوب فى المنتج: لقطة لإصدارات PHP لكل دومين قبل أى تحديث ومقارنة بعده مع تنبيه (لسه).

## 14. beta347 (21 أكتوبر 23:45)
- **لقطة إصدار PHP لكل دومين** (درس drosat): الإصدار وحالة FPM بيتصوروا من API بتاع cPanel قبل وبعد أى تحديث من الصفحة وفى كل فحص دورى؛ أى دومين اتغير بيتعرض فى قسم "PHP version changes" مع قبل/بعد وزرار Put back (النتيجة بتتقرى من cPanel بعد التنفيذ)، وتنبيه على قناة المشاكل.
- **PHP Harden (قفل ملفات المواقع) مش مفعّل على dc1**: صفر من 92 موقع عنده ملف أساسى مقفول. التفعيل مستنى قرار المالك.
- فحص PHP→Shell الدائم لسه مش مكتوب.

## 15. beta348 (21 أكتوبر 23:55) — علامات NEW
- علامة NEW فى القائمة + فقرة "إيه الجديد" أعلى: System updates، Learned Defense، Compromise Check، Security Health، Bot Guard، Spam & phishing، Firewall. بتظهر مرة وتتمسح لما القسم يتفتح (سجل `smpro_new_features` فى menu.php؛ الحالة "اتشاف" نص مطابق فى localStorage، فأى وسم جديد بيرجّع العلامة).
- **312 حزمة PHP** (إعادة بناء CloudLinux لـ 8.1.34/8.2.34/8.3.35/8.4.26 من ريبو cl-ea4 = الترقيع الأمنى الحرج) ظهرت على dc1 الساعة 23:45؛ التطبيق مستنى قرار المالك.

## 16. beta349 (22 أكتوبر 00:44) — PHP2Shell وLearned Defense
- **PHP2Shell** = الثغرتين الحرجتين فى نواة PHP (CVE-2026-109618/109619، 21 أكتوبر، تنفيذ كود بدون دخول). كارت فى Security Health بيقول لكل بناء PHP: مرقّع (إصدار ≥ 8.2.35/8.3.36/8.4.27/8.5.12 **أو** changelog الحزمة بيذكر الـCVE لأن CloudLinux بيرقّع تحت نفس الرقم) / مخفف (upload_progress Off) / معرض / خامل، مع عدد المواقع والـhandler ولو فيه حزمة مرقّعة مستنية. الفحص بطىء فبيتعمل فى الخلفية (`bin/php2shell_probe.php` → كاش 6 ساعات) ومع كل فحص تحديثات؛ الصفحة بتقرأ الكاش بس.
- **حالة dc1**: التحديث الليلى بتاع cPanel (23:17) سطّب 312 حزمة = ترقيعات php2shell لكل ea-php (حتى 8.1). alt-php82/84 (دومين واحد) لسه مش مرقّع لكن مخفف. Apache 2.4.69 وcPanel 11.138.0.18 والنواة مرقّعة حى. 4 مواقع ووردبريس بنسخ قديمة (دور WP Guard).
- **Learned Defense**: فلاتر من السيرفر (خطورة/نوع/حساب/نص)، تجميع بالحساب/الخطورة/النوع/بدون، صفحات 25–200، تحديد متعدد مع عزل أو "غير ضار" جماعى.
- **قاعدة الدروس المشتركة**: 40 درس، الـpool 28 (البصمات بس لأن باقى الأنواع محتاجة تأكيد سيرفرين وdc1 هو الوحيد اللى بيأكد)؛ dc1 وdc2 بيتبادلوا كل 6 ساعات بدون أخطاء. اقتراح معلق: الهيدر والاسم يدخلوا من تأكيد واحد.
- **مصادر الثغرات المقترحة** (مجانية/رسمية/آلية): CISA KEV، NVD 2.0، GitHub Advisory، php.net، cPanel news، Apache httpd security JSON، nginx/Exim advisories، kernel CVE، Red Hat Security Data، AlmaLinux errata، KernelCare محلى، Wordfence Intelligence، EPSS. قسم "Vulnerability watch" لسه مش مبنى.
