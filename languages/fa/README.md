# Xray supports Reality / VLESS WebSocket/gRPC+TLS protocol + Nginx one-click installation script

[简体中文](/README.md) | [English](/languages/en/README.md) | [Français](/languages/fr/README.md) | [Русский](/languages/ru/README.md) | فارسی | [한국어](/languages/ko/README.md)

[![GitHub stars](https://img.shields.io/github/stars/hello-yunshu/Xray_bash_onekey?color=%230885ce)](https://github.com/hello-yunshu/Xray_bash_onekey/stargazers) [![GitHub forks](https://img.shields.io/github/forks/hello-yunshu/Xray_bash_onekey?color=%230885ce)](https://github.com/hello-yunshu/Xray_bash_onekey/network) [![GitHub issues](https://img.shields.io/github/issues/hello-yunshu/Xray_bash_onekey)](https://github.com/hello-yunshu/Xray_bash_onekey/issues)

> سپاس از اجازه توسعه آزاد و غیرتجاری توسط JetBrains

## راهنماي استفاده

* می‌توانید دستور `idleleo` را مستقیماً وارد کنید تا اسکریپت را مدیریت کنید. ( [مشاهده پیشینهٔ داستان `idleleo`](https://github.com/hello-yunshu/Xray_bash_onekey/wiki/Backstory#%D8%B1%D8%A7%D9%87-%D9%81%D8%B1%D8%A7%D9%85%D9%88%D8%B4%DA%A9%D9%86%D9%86%D8%AF%D9%87-%D8%A7%D9%84%D9%87%DB%8C-%D8%AF%D8%A7%D8%B3%D8%AA%D8%A7%D9%86-idleleo) )
* با استفاده از Qwen-MT-Plus AI ترجمه دقیق به چند زبان رو انجام بده.
* برای Reality، استفاده از Nginx به عنوان پیشگام توصیه می‌شود که در اسکریبت قابل نصب است.
* توصیه می‌شود fail2ban را فعال کنید که در اسکریпт قابل نصب است.
* از پیشنهاد لینک به اشتراک‌گذاری از [@DuckSoft](https://github.com/DuckSoft) [(beta)](https://github.com/XTLS/Xray-core/issues/91)، که Qv2ray، V2rayN، V2rayNG را پشتیبانی می‌کند استفاده کنید.
* از پیشنهاد پروژه [XTLS](https://github.com/XTLS/Xray-core/issues/158)، با دنبال کردن استاندارد [UUIDv5](https://tools.ietf.org/html/rfc4122#section-4.3)، می‌توانید رشته‌های سفارشی خود را به UUID VLESS مپ کنید.
* راهنمای نصب Reality: [راه اندازی سرور پروتکل Xray Reality](https://hey.run/archives/da-jian-xray-reality-xie-yi-fu-wu-qi).
* ریسک‌های پروتکل Reality: [ریسک‌های پروتکل Xray Reality](https://hey.run/archives/reality-xie-yi-de-feng-xian).
* سرعت‌دهی سرور با استفاده از پروتکل Reality: [سرعت‌دهی سرور با استفاده از "سلب‌معنایی" پروتکل Reality](https://hey.run/archives/use-reality).
* افزودن تنظیمات均衡 بارگذاری، راهنما: [XRay پیشرفته – راه اندازی تعادل بارگذاری سرور پشتیبان](https://hey.run/archives/xrayjin-jie-wan-fa---da-jian-hou-duan-fu-wu-qi-fu-zai-jun-heng).
* اضافه کردن پشتیبانی از پروتکل gRPC، جزئیات بیشتر: [XRay پیشرفته – استفاده از پروتکل gRPC](https://hey.run/archives/xrayjin-jie-wan-fa---shi-yong-grpcxie-yi).

## گروه تلگرام

* گروه تلگرام: [لینک را کلیک کنید](https://t.me/+48VSqv7xIIFmZDZl)

## آمادگی

* یک سرور آماده کنید که خارج از چین عمل می‌کند و IP عمومی دارد.
* برای نصب پروتکل Reality، یک دامنه را که به الزم معیارهای Xray منطبق است پیدا کنید.
* برای نسخه TLS، یک دامنه آماده کنید و رکورد A را اضافه کنید.
* [مستندات رسمی Xray](https://xtls.github.io) را بخوانید تا به طور کلی اطلاعات مربوط به Reality TLS WebSocket gRPC و اطلاعات مرتبط با Xray را واقع شوید و نیازهای دامنه برای هدف Reality را بشناسید.
* **به اطمینان از نصب curl**، کاربران CentOS باید اجرا کنند: `yum install -y curl`; کاربران Debian/Ubuntu باید اجرا کنند: `apt install -y curl`.

## روش نصب

کپی و اجرای دستور زیر:

البند زیر یک نسخه از متن با ترجمه بخش‌های فارسی به زبان پارسی است:

``` bash
bash <(curl -Ss https://raw.githubusercontent.com/hello-yunshu/Xray_bash_onekey/main/install.sh)
```

## نکات مهم

* اگر شما مقدار دقیق تنظیمات مختلف در اسکریبت را نمی‌دانید، به جز موارد ضروری، از مقادیر پیشفرض اسکریبت استفاده کنید (تمام موارد را با Enter تایید کنید).
* کاربران Cloudflare بعد از نصب برنامه CDN را فعال کنید.
* برای استفاده از این اسکریبت نیاز به داشتن دانش و تجربه اولیه Linux و درک اصول شبکه کامپیوتر دارید.
* در حال حاضر این اسکریپت برای Debian 9+ / Ubuntu 18.04+ / Centos7+ پشتیبانی می‌شود، برخی الگوهای Centos ممکن است مشکلات نسبتاً پیچیده در زمان کامپایل داشته باشند، بنابراین در صورت وجود مشکلات کامپایل، توصیه می‌شود به سیستم‌های قالب دیگر تغییر دهید.
* نویسنده فقط حمایت محدودی فراهم می‌کند، زیرا او خیلی بد است.
* لینک‌های به اشتراک‌گذاری در وضعیت آزمایشی هستند، عدم حمله به تغییرات آینده محتمل است، بنابراین خودتان مطمئن شوید که کلاینت شما آن را پشتیبانی می‌کند.
* نقشه‌گذاری رشته‌های سفارشی به UUIDv5 نیازمند پشتیبانی از سوی کلاینت است.

## تشکر

* این اسکریپت از <https://github.com/wulabing/V2Ray_ws-tls_bash_onekey> الهام گرفته است، از wulabing ممنون می‌شوم.
* پروژه تسهیل TCP در این اسکریپت از <https://github.com/ylx2016/Linux-NetSpeed> بهره می‌گیرد، از ylx2016 ممنون می‌شوم.

## گواهی‌نامه

اگر شما فایل‌های گواهی‌نامه برای دامنه‌ای که استفاده می‌کنید قبلاً دارید، فایل‌های crt و key را به نام xray.crt و xray.key در دایرکتوری /etc/idleleo/cert قرار دهید (در صورت عدم وجود دایرکتوری، آن را ایجاد کنید)، لطفاً به تنظیمات دسترسی فایل‌های گواهی‌نامه و مدت اعتبار آنها توجه کنید، اگر مدت اعتبار گواهی‌نامه سفارشی شما تمام شد، شما باید آن را به طور خودکار تمدید کنید.

اسکریپت قادر به تولید خودکار گواهی‌نامه Let's encrypted است، مدت اعتبار آن ۳ ماه است، نظریاً گواهی‌نامه‌های تولید شده خودکار امکان تمدید خودکار را دارند.

## مشاهده تنظیمات کلاینت

`cat /etc/idleleo/xray_info.txt`

## معرفی Xray

* Xray یک ابزار شبکهٔ پروکسی باز‌سورس عالی است که به شما کمک می‌کند تا اینترنت را با لذت بگذرانید و در حال حاضر برای تمامی سیستم‌عامل‌های Windows، Mac، Android، IOS و Linux موجود است.
* این اسکریپت یک اسکریپت تنظیم کامل یک کلید است که پس از انجام صحیح تمامی مراحل، می‌توانید تنظیمات خروجی را بر اساس نتایج تنظیم کلاینت خود استفاده کنید.
* لطفاً توجه داشته باشید: ما همچنان به طور قوی توصیه می‌کنیم شما تمام جنبه‌های فرآیند و اصول برنامه را بفهمید.

## پیشنهاد تنظیم فقط یک پروکسی روی یک سرور

* این اسکریپت به طور پیش‌فرض آخرین نسخه از مرکز Xray را نصب می‌کند.
* پیشنهاد می‌شود از порت ۴۴۳ به عنوان پورت اتصال استفاده کنید.
* محتوای مخفیه‌سازی می‌تواند توسط شما تغییر کند.

## نکات مهم دیگر

* توصیه می‌شود این اسکریپت را در محیط نظيف استفاده کنید، اگر شما نویسنده جدید هستید، از سیستم CentOS استفاده نکنید.
* قبل از اعمال این برنامه در محیط تولیدی، مطمئن شوید که آن کار می‌کند.
* این برنامه به Nginx برای اجرای برخی ویژگی‌ها بستگی دارد، کاربرانی که قبلاً با استفاده از [LNMP](https://lnmp.org) یا اسکریپت‌های مشابه دیگر Nginx را نصب کرده‌اند باید به توجه خاص به آن‌ها داشته باشند، استفاده از این اسکریپت ممکن است به خطاهای پیش‌بینی نشده منجر شود.
* کاربران سیستم CentOS باید از پیش درون مウォلفایر مراحل مربوط به برنامه را مجوز دهند (پیش‌فرض: ۸۰، ۴۴۳).

## روش راه‌اندازی

راه‌اندازی Xray: `systemctl start xray`

توقف Xray: `systemctl stop xray`

راه‌اندازی Nginx: `systemctl start nginx`

توقف Nginx: `systemctl stop nginx`

## دایرکتوری‌های مرتبط

تنظیمات سرور Xray: `/etc/idleleo/conf/xray/config.json`

دایرکتوری Nginx: `/usr/local/nginx`

فایل‌های گواهی‌نامه: `/etc/idleleo/cert/xray.key` و `/etc/idleleo/cert/xray.crt` لطفاً تنظیمات دسترسی به فایل‌های گواهی‌نامه را توجه کنید

فایل‌های اطلاعات تنظیمات و غیره: `/etc/idleleo`
