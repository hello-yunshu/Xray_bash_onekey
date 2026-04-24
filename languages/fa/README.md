# اسکریپت نصب خودکار Xray — Reality / VLESS WebSocket/gRPC+TLS + Nginx

[简体中文](/README.md) | [English](/languages/en/README.md) | [Français](/languages/fr/README.md) | [Русский](/languages/ru/README.md) | فارسی | [한국어](/languages/ko/README.md)

[![GitHub stars](https://img.shields.io/github/stars/hello-yunshu/Xray_bash_onekey?color=%230885ce)](https://github.com/hello-yunshu/Xray_bash_onekey/stargazers) [![GitHub forks](https://img.shields.io/github/forks/hello-yunshu/Xray_bash_onekey?color=%230885ce)](https://github.com/hello-yunshu/Xray_bash_onekey/network) [![GitHub issues](https://img.shields.io/github/issues/hello-yunshu/Xray_bash_onekey)](https://github.com/hello-yunshu/Xray_bash_onekey/issues)

> سپاس از اجازه توسعه آزاد و غیرتجاری توسط JetBrains

## ویژگی‌ها

* دستور `idleleo` را وارد کنید تا اسکریپت را مدیریت کنید ([مشاهده پیشینهٔ داستان `idleleo`](https://github.com/hello-yunshu/Xray_bash_onekey/wiki/%DA%86%D9%87%D8%B1%D9%87-%D9%88%D8%A7%D9%82%D8%B9%DB%8C-%D9%BE%D8%B4%D8%AA-%D9%85%D9%87))
* ترجمه دقیق چندزبانه با Qwen-MT-Plus AI
* پشتیبانی از پروتکل Reality با Nginx پیشگام توصیه‌شده (قابل نصب از طریق اسکریپت)
* حفاظت داخلی fail2ban (قابل نصب از طریق اسکریپت)
* استفاده از [پیشنهاد](https://github.com/XTLS/Xray-core/issues/91) لینک اشتراک‌گذاری [@DuckSoft](https://github.com/DuckSoft) (بتا)، سازگار با Qv2ray، V2rayN، V2rayNG
* استفاده از پیشنهاد پروژه [XTLS](https://github.com/XTLS/Xray-core/issues/158)، پیروی از استاندارد [UUIDv5](https://tools.ietf.org/html/rfc4122#section-4.3)، پشتیبانی از نگاشت رشته‌های سفارشی به UUID VLESS
* پشتیبانی از پروتکل gRPC: [استفاده از پروتکل gRPC](https://hey.run/archives/xrayjin-jie-wan-fa---shi-yong-grpcxie-yi)
* پشتیبانی از تعادل بار Reality / ws/gRPC:
  - [استقرار تعادل بار Reality](https://hey.run/archives/bushu-reality-balance)
  - [ساخت تعادل بار بک‌اند](https://hey.run/archives/xrayjin-jie-wan-fa---da-jian-hou-duan-fu-wu-qi-fu-zai-jun-heng)

## مطالعه بیشتر

* راهنمای نصب Reality: [راه‌اندازی سرور Xray Reality](https://hey.run/archives/da-jian-xray-reality-xie-yi-fu-wu-qi)
* خطرات پروتکل Reality: [خطرات پروتکل Xray Reality](https://hey.run/archives/reality-xie-yi-de-feng-xian)
* تسریع سرور با Reality: [تسریع سرور از طریق «آسیب‌پذیری» پروتکل Reality](https://hey.run/archives/use-reality)

## گروه تلگرام

* گروه بحث: [کلیک برای عضویت](https://t.me/+48VSqv7xIIFmZDZl)

## پیش‌نیازها

* یک سرور خارج از کشور با آدرس آی‌پی عمومی
* برای پروتکل Reality: یک دامنه هدف مطابق با الزامات Xray آماده کنید
* برای نسخه TLS: یک دامنه آماده کنید و رکورد A اضافه کنید
* [مستندات رسمی Xray](https://xtls.github.io) را بخوانید تا با Reality، TLS، WebSocket، gRPC و مفاهیم مرتبط Xray آشنا شوید
* **اطمینان از نصب curl**: کاربران CentOS دستور `yum install -y curl` را اجرا کنند؛ کاربران Debian/Ubuntu دستور `apt install -y curl` را اجرا کنند

## نصب سریع

```bash
bash <(curl -Ss https://raw.githubusercontent.com/hello-yunshu/Xray_bash_onekey/main/install.sh)
```

## نکات مهم

* اگر با تنظیمات آشنا نیستید، برای فیلدهای غیرضروری از مقادیر پیش‌فرض استفاده کنید (فقط Enter بزنید)
* کاربران Cloudflare فقط پس از اتمام نصب CDN را فعال کنند
* این اسکریپت به دانش پایه Linux و شبکه‌های کامپیوتری نیاز دارد
* پشتیبانی از Debian 12+ / Ubuntu 24.04+ / CentOS Stream 8+؛ برخی قالب‌های CentOS ممکن است مشکل کامپایل داشته باشند — در صورت بروز مشکل، تغییر سیستم‌عامل توصیه می‌شود
* توصیه می‌شود فقط یک پروکسی در هر سرور مستقر کنید و از پورت پیش‌فرض 443 استفاده کنید
* نگاشت رشته‌های سفارشی به UUIDv5 نیازمند پشتیبانی سمت کلاینت است
* از این اسکریپت در محیط تمیز استفاده کنید؛ مبتدیان از CentOS استفاده نکنند
* این برنامه به Nginx وابسته است — کاربرانی که Nginx را از طریق [LNMP](https://lnmp.org) یا اسکریپت‌های مشابه نصب کرده‌اند، به تداخلات احتمالی توجه کنند
* قبل از تأیید عملکرد، از این اسکریپت در محیط تولیدی استفاده نکنید
* نویسنده فقط پشتیبانی محدودی ارائه می‌دهد (چون خیلی باهوش نیست)

## تشکر

* بر اساس [wulabing/V2Ray_ws-tls_bash_onekey](https://github.com/wulabing/V2Ray_ws-tls_bash_onekey)
* اسکریپت تسریع TCP از [ylx2016/Linux-NetSpeed](https://github.com/ylx2016/Linux-NetSpeed)

## پیکربندی گواهی‌نامه

**گواهی سفارشی**: فایل‌های crt و key را به `xray.crt` و `xray.key` تغییر نام دهید و در مسیر `/etc/idleleo/cert` قرار دهید (در صورت عدم وجود، دایرکتوری را ایجاد کنید). به مجوزها و مدت اعتبار گواهی توجه کنید — گواهی‌های سفارشی پس از انقضا باید به صورت دستی تمدید شوند.

**گواهی خودکار**: اسکریپت از تولید خودکار گواهی Let's Encrypt پشتیبانی می‌کند (اعتبار ۳ ماهه)، با پشتیبانی نظری از تمدید خودکار.

## مشاهده تنظیمات کلاینت

```bash
cat /etc/idleleo/info/xray_info.inf
```

## درباره Xray

* Xray یک ابزار پروکسی شبکه متن‌باز عالی است که از Windows، macOS، Android، iOS، Linux و سایر پلتفرم‌ها پشتیبانی می‌کند
* این اسکریپت یک پیکربندی کامل یک‌کلیکی ارائه می‌دهد — پس از پایان موفقیت‌آمیز تمام فرآیندها، کلاینت خود را بر اساس نتایج خروجی تنظیم کنید
* **به شدت توصیه می‌شود** فرآیند کار و اصول برنامه را به طور کامل درک کنید

## مدیریت سرویس

| عمل | دستور |
|-----|-------|
| راه‌اندازی Xray | `systemctl start xray` |
| توقف Xray | `systemctl stop xray` |
| راه‌اندازی Nginx | `systemctl start nginx` |
| توقف Nginx | `systemctl stop nginx` |

## دایرکتوری‌ها

| مورد | مسیر |
|------|------|
| تنظیمات سرور Xray | `/etc/idleleo/conf/xray/config.json` |
| دایرکتوری Nginx | `/usr/local/nginx` |
| فایل‌های گواهی | `/etc/idleleo/cert/xray.key`, `/etc/idleleo/cert/xray.crt` |
| اطلاعات پیکربندی و غیره | `/etc/idleleo` |
