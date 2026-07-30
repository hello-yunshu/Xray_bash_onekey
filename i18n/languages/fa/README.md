# Xray اسکریپت نصب با یک کلیک — Reality / VLESS WebSocket/gRPC/xHTTP+TLS + Nginx

چینی ساده شده |[English](/i18n/languages/en/README.md) | [Français](/i18n/languages/fr/README.md) | [Русский](/i18n/languages/ru/README.md) | [فارسی](/i18n/languages/fa/README.md) | [한국어](/i18n/languages/ko/README.md)

[![GitHub stars](https://img.shields.io/github/stars/hello-yunshu/Xray_bash_onekey?color=%230885ce)](https://github.com/hello-yunshu/Xray_bash_onekey/stargazers) [![GitHub forks](https://img.shields.io/github/forks/hello-yunshu/Xray_bash_onekey?color=%230885ce)](https://github.com/hello-yunshu/Xray_bash_onekey/network) [![GitHub issues](https://img.shields.io/github/issues/hello-yunshu/Xray_bash_onekey)](https://github.com/hello-yunshu/Xray_bash_onekey/issues)

> Thanks for non-commercial open source development authorization by JetBrains

## ویژگی ها

* وارد کنید`idleleo`شما می توانید اسکریپت ها را مدیریت کنید ([查看 `idleleo` 背景故事](https://github.com/hello-yunshu/Xray_bash_onekey/wiki/%E8%BF%B7%E9%9B%BE%E5%90%8E%E7%9A%84%E7%9C%9F%E5%AE%B9)）
* برای دستیابی به ترجمه دقیق به چندین زبان، از Qwen-MT-Plus AI استفاده کنید
* از پروتکل Reality پشتیبانی می کند، توصیه می شود از پیشوند Nginx استفاده کنید (قابل نصب در اسکریپت)
* از انتقال WebSocket، gRPC، xHTTP پشتیبانی می کند، می توانید انتقال تک یا`ws+gRPC+xHTTP`هر دو را فعال کنید
* محافظت داخلی fail2ban (قابل نصب در اسکریپت)
* آمار ترافیک Xray داخلی، مسدود کردن ترافیک، به‌روزرسانی قانون GeoIP/GeoSite و به‌روزرسانی منظم
* پشتیبانی از اسکریپت ها، Xray، Nginx، به روز رسانی خودکار گواهی، و ارائه نسخه پشتیبان و بازیابی کامل
* استفاده کنید[@DuckSoft](https://github.com/DuckSoft)لینک به اشتراک گذاری[提案](https://github.com/XTLS/Xray-core/issues/91)(beta)، سازگار با Qv2ray، V2rayN، V2rayNG
* استفاده کنید[XTLS](https://github.com/XTLS/Xray-core/issues/158)پیشنهاد، پیگیری[UUIDv5](https://tools.ietf.org/html/rfc4122#section-4.3)استاندارد، از نگاشت رشته سفارشی به VLESS UUID پشتیبانی می کند
* از پروتکل gRPC پشتیبانی می کند:[使用 gRPC 协议](https://hey.run/posts/xrayjin-jie-wan-fa---shi-yong-grpcxie-yi)
* از تعادل بار Reality / ws/gRPC/xHTTP پشتیبانی می کند:
  - [部署 Reality 负载均衡](https://hey.run/posts/bushu-reality-balance)
  - [搭建后端负载均衡](https://hey.run/posts/xrayjin-jie-wan-fa---da-jian-hou-duan-fu-wu-qi-fu-zai-jun-heng)
* حالت Reality + Nginx به طور پیش فرض فعال است. SNI Guard: SNI ناشناخته، SNI خالی و استثنا TLS وارد باطن Xray Reality نمی شود. استراتژی جداسازی (ssl_reject_handshake) به طور پیش فرض پذیرفته شده است. کاربران پیشرفته می‌توانند به سایت بازگشتی decoy خودساخته یا مستقیماً TCP رد شده تغییر دهند. این عملکرد برای کاهش تشخیص فعال و قرار گرفتن در معرض پیکربندی نادرست استفاده می شود و استتار کامل را دنبال نمی کند.

## در ادامه مطلب

* Reality راهنمای نصب:[搭建 Xray Reality 服务器](https://hey.run/posts/da-jian-xray-reality-xie-yi-fu-wu-qi)
* Reality خطر پروتکل:[Xray Reality 协议的风险](https://hey.run/posts/reality-xie-yi-de-feng-xian)
* Reality سرور تسریع شده:[利用 Reality 协议"漏洞"加速服务器](https://hey.run/posts/use-reality)

## گروه Telegram

* گروه ارتباط:[点击加入](https://t.me/+48VSqv7xIIFmZDZl)

## آماده سازی

* یک سرور خارج از کشور با شبکه عمومی IP
* پروتکل Reality را نصب کنید: باید یک نام دامنه مورد نظر تهیه کنید که شرایط Xray را برآورده کند.
* نسخه TLS را نصب کنید: نام دامنه را آماده کنید و رکورد A را اضافه کنید
* خواندن[Xray 官方文档](https://xtls.github.io)مفاهیم مرتبط Reality، TLS، WebSocket، gRPC و Xray را درک کنید
* ** مطمئن شوید که curl نصب شده است: CentOS اجرای کاربر`yum install -y curl`;Debian/Ubuntu اجرای کاربر`apt install -y curl`

## نصب سریع

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/hello-yunshu/Xray_bash_onekey/main/install.sh)
```

## حالت نصب

| مدل | نشان دادن |
|------|------|
| Reality + Nginx | حالت پیشنهادی، می‌توانید پروتکل ساده ws/gRPC/xHTTP را در صورت نیاز برای تعادل بار وصل کنید |
| Nginx + TLS | ws/gRPC/xHTTP را پشتیبانی کنید، به طور خودکار برای گواهی Let's Encrypt درخواست و تمدید کنید |
| ws/gRPC/xHTTP ONLY | حالت ورودی مستقل بدون TLS، عمدتاً در سناریوهای باطن یا تعادل بار استفاده می شود |
| XTLS ONLY | فقط در سناریوهای خاص مانند انتقال ترافیک استفاده می شود |
| Docker | Xray، Nginx و اسکریپت اصلی در تصویر از قبل نصب شده اند. |

هنگام نصب حالت های مرتبط ws/gRPC/xHTTP اختیاری است`ws`、`gRPC`、`xHTTP`یا`ws+gRPC+xHTTP`. اسکریپت به ترتیب پورت، مسیر، لینک اشتراک گذاری و کد QR مربوطه را ایجاد می کند. Clash در حال حاضر xHTTP را پشتیبانی نمی کند، و اسکریپت در خروجی پیکربندی درخواست می کند.

## دستورات رایج

| عمل کنند | سفارش دهید |
|------|------|
| منوی مدیریت را باز کنید | `idleleo` |
| مشاهده راهنما | `idleleo --help` |
| حالت Reality را نصب کنید | `idleleo --install-reality` |
| حالت TLS را نصب کنید | `idleleo --install-tls` |
| نصب ws/gRPC/xHTTP ONLY | `idleleo --install-none` |
| مشاهده اطلاعات نصب | `idleleo --show` |
| به روز رسانی اسکریپت | `idleleo --update` |
| به روز رسانی Xray | `idleleo --xray-update` |
| به روز رسانی Nginx | `idleleo --nginx-update` |
| تنظیم Fail2ban | `idleleo --set-fail2ban` |
| مسدود کردن ترافیک را تنظیم کنید | `idleleo --traffic-blocker` |
| مشاهده ترافیک پورت بلادرنگ | `idleleo --port-traffic` |

## Docker استقرار

از استقرار با استفاده از Docker پشتیبانی می کند، تصویر با Xray و Nginx از قبل نصب شده است، و تمام عملکردهای اسکریپت اصلی را می توان مستقیماً در ظرف استفاده کرد. جزئیات را ببینید[Docker 部署指南](/docker/DOCKER.md)。

```bash
git clone https://github.com/hello-yunshu/Xray_bash_onekey.git
cd Xray_bash_onekey
docker compose up -d
docker attach xray-onekey
```

## AI Skill استقرار

از استقرار خودکار Xray از طریق ابزارهای AI مانند Trae بدون تعامل دستی پشتیبانی می کند. جزئیات را ببینید[Xray_bash_onekey_skill](https://github.com/hello-yunshu/Xray_bash_onekey_skill)。

روش سنتی نیاز به SSH برای رفتن به سرور، اجرای اسکریپت نصب و پاسخ به سوالات تعاملی یکی یکی دارد. روش Skill فقط باید به AI نیازهای شما را بگوید، و AI به طور خودکار یک اسکریپت غیر تعاملی ایجاد کرده و اجرا می کند و مستقیماً پیوند VLESS را برمی گرداند.

**حالت های پشتیبانی شده**: Reality / TLS / ws ONLY / XTLS ONLY

**نحوه استفاده**: در ابزار AI که از Skill پشتیبانی می کند، مستقیماً بگویید "Help me build Xray on server" و AI به طور خودکار اطلاعات را جمع آوری می کند، اسکریپت ها را تولید می کند، استقرار را انجام می دهد و اطلاعات اتصال را برمی گرداند.

## موارد قابل توجه

* اگر معنای هر تنظیم را متوجه نمی‌شوید، لطفاً از مقدار پیش‌فرض به جز فیلدهای الزامی استفاده کنید (فقط Enter را فشار دهید)
* Cloudflare کاربران لطفاً پس از اتمام نصب CDN را باز کنند.
* این اسکریپت به دانش اولیه Linux و دانش شبکه کامپیوتری نیاز دارد
* پشتیبانی از Debian 12+ / Ubuntu 24.04+ / CentOS Stream 10+، برخی از قالب های CentOS ممکن است مشکلات کامپایل داشته باشند، توصیه می شود در صورت مواجهه با مشکل، سیستم را تغییر دهید.
* توصیه می شود که یک سرور تنها یک عامل را مستقر کرده و از پورت پیش فرض 443 استفاده کند
* نگاشت رشته سفارشی به UUIDv5 نیاز به پشتیبانی مشتری دارد
* استفاده از آن در محیط خالص توصیه می شود. تازه کارها نباید از CentOS استفاده کنند
* این برنامه به Nginx بستگی دارد، گذشت[LNMP](https://lnmp.org)کاربرانی که اسکریپت Nginx را نصب کرده اند، لطفاً از تداخل احتمالی آگاه باشند.
* پیوند مشترک xHTTP برای مشتریانی است که xHTTP را پشتیبانی می کنند. خروجی پیکربندی Clash از xHTTP رد می شود
* از این اسکریپت در یک محیط تولیدی بدون بررسی اولیه در دسترس بودن استفاده نکنید
* نویسنده فقط پشتیبانی محدودی ارائه می دهد (زیرا او خیلی احمق است)

## قدردانی

* بر اساس[wulabing/V2Ray_ws-tls_bash_onekey](https://github.com/wulabing/V2Ray_ws-tls_bash_onekey)توسعه دهد
* TCP اسکریپت شتاب به نقل از[ylx2016/Linux-NetSpeed](https://github.com/ylx2016/Linux-NetSpeed)

## پیکربندی گواهی

**گواهی سفارشی**: فایل های crt و key را به ترتیب نام گذاری کنید.`xray.crt`و`xray.key`، قرار دهید`/etc/idleleo/cert`دایرکتوری (اگر دایرکتوری وجود ندارد، ابتدا آن را ایجاد کنید). لطفا به مرجع گواهی و مدت اعتبار توجه کنید. پس از انقضای گواهی سفارشی، باید خودتان آن را تمدید کنید.

**گواهی خودکار**: اسکریپت از تولید خودکار گواهی های Let's Encrypt (معتبر به مدت 3 ماه) پشتیبانی می کند و از نظر تئوری از تمدید خودکار پشتیبانی می کند.

## مشاهده پیکربندی مشتری

```bash
cat /etc/idleleo/info/xray_info.inf
```

## Xray مقدمه

* Xray یک ابزار پروکسی شبکه منبع باز عالی است که از Windows، macOS، Android، iOS، Linux و دیگر پلتفرم های کامل پشتیبانی می کند.
* این اسکریپت یک اسکریپت پیکربندی کامل با یک کلیک است. پس از اینکه تمام فرآیندها به طور معمول تکمیل شدند، می توان از مشتری با توجه به نتایج خروجی استفاده کرد.
* **به شدت توصیه می شود** درک جامع از جریان کار و اصول برنامه

## مدیریت خدمات

| عمل کنند | سفارش دهید |
|------|------|
| شروع Xray | `systemctl start xray` |
| توقف Xray | `systemctl stop xray` |
| شروع Nginx | `systemctl start nginx` |
| توقف Nginx | `systemctl stop nginx` |

## کاتالوگ مرتبط

| محتوا | مسیر |
|------|------|
| دایرکتوری صفحه اصلی | `/etc/idleleo` |
| پیکربندی Xray | `/etc/idleleo/conf/xray/config.json` |
| پیکربندی Nginx | `/etc/idleleo/conf/nginx/` |
| اطلاعات نصب | `/etc/idleleo/conf/install_config.json` |
| فایل گواهی | `/etc/idleleo/cert/xray.key`、`/etc/idleleo/cert/xray.crt` |
| دایرکتوری ورود به سیستم | `/etc/idleleo/logs/`、`/var/log/xray/` |
| فهرست راهنمای نصب Nginx | `/usr/local/nginx` |
| دستورات اداری | `/usr/bin/idleleo` |
