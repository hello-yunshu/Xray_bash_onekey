# راهنمای استقرار Docker

[简体中文](/DOCKER.md) | [English](/languages/en/DOCKER.md) | [Français](/languages/fr/DOCKER.md) | [Русский](/languages/ru/DOCKER.md) | فارسی | [한국어](/languages/ko/DOCKER.md)

این راهنما نحوه اجرای اسکریپت نصب خودکار Xray با Docker را توضیح می‌دهد. ایمیج شامل Xray و Nginx پیش‌نصب‌شده است و تمام قابلیت‌های اسکریپت اصلی در کانتینر در دسترس هستند.

## شروع سریع

### ۱. کلون و ساخت

```bash
git clone https://github.com/hello-yunshu/Xray_bash_onekey.git
cd Xray_bash_onekey
docker compose up -d
```

### ۲. ورود به منوی نصب تعاملی

```bash
docker attach xray-onekey
```

در اولین اجرا، اسکریپت نصب به طور خودکار راه‌اندازی می‌شود. دستورالعمل‌ها را برای تکمیل پیکربندی دنبال کنید. پس از خروج از منو، کانتینر به طور خودکار وارد حالت دیمون می‌شود.

### ۳. مدیریت بعدی

```bash
docker exec -it xray-onekey idleleo
```

## حالت‌های اجرا

| حالت | توضیح | دستور |
|------|--------|-------|
| `idleleo` (پیش‌فرض) | راه‌اندازی سرویس‌ها و ورود به منوی مدیریت | `docker compose up -d` + `docker attach xray-onekey` |
| `start` | فقط راه‌اندازی سرویس‌ها (حالت دیمون) | `command: start` را در `docker-compose.yml` تغییر دهید |
| `shell` | راه‌اندازی سرویس‌ها و ورود به پوسته | `docker exec -it xray-onekey bash` |

## عملیات مدیریت

تمام دستورات اسکریپت اصلی در دسترس هستند:

```bash
docker exec -it xray-onekey idleleo          # منوی مدیریت
docker exec -it xray-onekey idleleo -s        # مشاهده اطلاعات نصب
docker exec -it xray-onekey idleleo -x        # به‌روزرسانی Xray
docker exec -it xray-onekey idleleo -n        # به‌روزرسانی Nginx
docker exec -it xray-onekey idleleo -h        # نمایش راهنما
```

## استفاده از docker run

```bash
docker build -t xray-onekey .

docker run -d --name xray-onekey   --network host   --cap-add NET_ADMIN   -e TZ=Asia/Shanghai   -v xray-conf:/etc/idleleo/conf   -v xray-cert:/etc/idleleo/cert   -v xray-info:/etc/idleleo/info   -v xray-logs:/var/log/xray   -v acme-data:/root/.acme.sh   -it xray-onekey
```

## ماندگاری داده‌ها

| حجم | مسیر کانتینر | توضیح |
|-----|-------------|--------|
| `xray-conf` | `/etc/idleleo/conf` | فایل‌های پیکربندی Xray و Nginx |
| `xray-cert` | `/etc/idleleo/cert` | فایل‌های گواهی SSL |
| `xray-info` | `/etc/idleleo/info` | اطلاعات اتصال و فایل‌های وضعیت |
| `xray-logs` | `/var/log/xray` | فایل‌های لاگ Xray |
| `acme-data` | `/root/.acme.sh` | داده‌های صدور گواهی acme.sh |

## پیکربندی شبکه

کانتینر از `network_mode: host` استفاده می‌کند و مستقیماً از شبکه میزبان استفاده می‌کند:

* حالت Reality نیاز به دیدن آی‌پی واقعی کلاینت دارد
* حالت TLS نیاز به اتصال مستقیم به پورت‌های ۴۴۳/۸۰ دارد
* از سربار عملکرد ناشی از NAT اضافی جلوگیری می‌کند

## نکات مهم

* کانتینر از `fake-systemctl` به جای systemd استفاده می‌کند؛ دستورات `systemctl` به طور عادی کار می‌کنند
* یک نگهبان داخلی هر ۳۰ ثانیه وضعیت سرویس‌ها را بررسی کرده و در صورت خرابی به طور خودکار راه‌اندازی مجدد می‌کند
* پس از خروج از منوی مدیریت، کانتینر به طور خودکار وارد حالت دیمون می‌شود — سرویس‌ها به کار خود ادامه می‌دهند
* مدیریت فایروال در سطح میزبان توصیه می‌شود
* تمدید خودکار گواهی در کانتینر کار می‌کند (مطمئن شوید پورت ۸۰ قابل دسترسی است)

## عیب‌یابی

```bash
docker logs xray-onekey                    # مشاهده لاگ‌های کانتینر
docker exec -it xray-onekey bash           # ورود به کانتینر
docker exec -it xray-onekey idleleo -s     # مشاهده اطلاعات نصب
```

### بازنشانی کامل

```bash
docker compose down
docker volume rm xray-conf xray-cert xray-info xray-logs acme-data
docker compose up -d
```
