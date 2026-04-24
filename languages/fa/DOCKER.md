# راهنمای استقرار Docker

[简体中文](/DOCKER.md) | [English](/languages/en/DOCKER.md) | [Français](/languages/fr/DOCKER.md) | [Русский](/languages/ru/DOCKER.md) | فارسی | [한국어](/languages/ko/DOCKER.md)

این سند نحوه استقرار اسکریپت نصب خودکار Xray با استفاده از Docker را توضیح می‌دهد.

## پیش‌نیازها

* Docker و Docker Compose نصب شده
* یک سرور با آدرس آی‌پی عمومی
* برای پروتکل Reality: یک دامنه هدف مطابق با الزامات Xray آماده کنید
* برای نسخه TLS: یک دامنه آماده کنید و رکورد A اضافه کنید

## شروع سریع

### ۱. کلون کردن مخزن

```bash
git clone https://github.com/hello-yunshu/Xray_bash_onekey.git
cd Xray_bash_onekey
```

### ۲. ساخت و راه‌اندازی کانتینر

```bash
docker compose up -d
```

### ۳. ورود به منوی نصب تعاملی

```bash
docker attach xray-onekey
```

در اولین اجرا، کانتینر به طور خودکار اسکریپت نصب را راه‌اندازی می‌کند. دستورالعمل‌ها را برای تکمیل پیکربندی دنبال کنید.

## حالت‌های اجرا

کانتینر حالت‌های اجرای زیر را پشتیبانی می‌کند:

| حالت | توضیح | دستور |
|------|--------|-------|
| `idleleo` (پیش‌فرض) | راه‌اندازی سرویس‌ها و ورود به منوی مدیریت تعاملی | `docker compose up -d` |
| `start` | فقط راه‌اندازی سرویس‌ها (حالت دیمون) | `command: start` را در `docker-compose.yml` تغییر دهید |
| `shell` | راه‌اندازی سرویس‌ها و ورود به پوسته | `docker exec -it xray-onekey bash` |

## عملیات مدیریت

### ورود به منوی مدیریت

```bash
docker exec -it xray-onekey idleleo
```

### بررسی وضعیت سرویس‌ها

```bash
docker exec -it xray-onekey systemctl status xray
docker exec -it xray-onekey systemctl status nginx
```

### راه‌اندازی مجدد سرویس‌ها

```bash
docker exec -it xray-onekey systemctl restart xray
docker exec -it xray-onekey systemctl restart nginx
```

### مشاهده تنظیمات کلاینت

```bash
docker exec -it xray-onekey cat /etc/idleleo/info/xray_info.inf
```

### مشاهده لاگ‌ها

```bash
docker exec -it xray-onekey cat /var/log/xray/access.log
docker exec -it xray-onekey cat /var/log/xray/error.log
```

## استفاده از docker run (جایگزین docker compose)

```bash
docker build -t xray-onekey .

docker run -d --name xray-onekey \
  --network host \
  --cap-add NET_ADMIN \
  -e TZ=Asia/Shanghai \
  -v xray-conf:/etc/idleleo/conf \
  -v xray-cert:/etc/idleleo/cert \
  -v xray-info:/etc/idleleo/info \
  -v xray-logs:/var/log/xray \
  -v acme-data:/root/.acme.sh \
  -it xray-onekey
```

## ماندگاری داده‌ها

کانتینر از حجم‌های Docker برای ماندگاری داده‌ها استفاده می‌کند. پیکربندی هنگام بازسازی کانتینرها حفظ می‌شود:

| حجم | مسیر کانتینر | توضیح |
|-----|-------------|--------|
| `xray-conf` | `/etc/idleleo/conf` | فایل‌های پیکربندی Xray و Nginx |
| `xray-cert` | `/etc/idleleo/cert` | فایل‌های گواهی SSL |
| `xray-info` | `/etc/idleleo/info` | اطلاعات اتصال و فایل‌های وضعیت |
| `xray-logs` | `/var/log/xray` | فایل‌های لاگ Xray |
| `acme-data` | `/root/.acme.sh` | داده‌های صدور گواهی acme.sh |

## گواهی‌های سفارشی

فایل‌های `xray.crt` و `xray.key` را در مسیر میزبان مربوط به حجم گواهی‌ها قرار دهید. از `docker volume inspect xray-cert` برای یافتن مسیر میزبان استفاده کنید.

## پیکربندی شبکه

کانتینر به طور پیش‌فرض از `network_mode: host` استفاده می‌کند، یعنی مستقیماً از شبکه میزبان استفاده می‌کند. این برای سرویس‌های پروکسی Xray حیاتی است:

* حالت Reality نیاز به دیدن آی‌پی واقعی کلاینت دارد
* حالت TLS نیاز به اتصال مستقیم به پورت‌های ۴۴۳/۸۰ دارد
* از سربار عملکرد ناشی از NAT اضافی جلوگیری می‌کند

## نکات مهم

* کانتینر از `fake-systemctl` به جای systemd استفاده می‌کند؛ دستورات `systemctl` به طور عادی کار می‌کنند
* مدیریت فایروال در سطح میزبان به جای داخل کانتینر توصیه می‌شود
* یک نگهبان داخلی هر ۳۰ ثانیه وضعیت سرویس‌ها را بررسی کرده و در صورت خرابی به طور خودکار راه‌اندازی مجدد می‌کند
* تمدید خودکار گواهی در کانتینر کار می‌کند (مطمئن شوید پورت ۸۰ قابل دسترسی است)
* fail2ban در صورت نیاز از طریق منوی مدیریت قابل نصب است

## عیب‌یابی

### کانتینر راه‌اندازی نمی‌شود

```bash
docker logs xray-onekey
```

### سرویس‌ها کار نمی‌کنند

```bash
docker exec -it xray-onekey systemctl status xray
docker exec -it xray-onekey systemctl start xray
```

### ورود مجدد به منوی نصب

```bash
docker exec -it xray-onekey idleleo
```

### بازنشانی کامل

```bash
docker compose down
docker volume rm xray-conf xray-cert xray-info xray-logs acme-data
docker compose up -d
```
