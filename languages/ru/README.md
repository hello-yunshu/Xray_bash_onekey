# Скрипт автоматической установки Xray — Reality / VLESS WebSocket/gRPC/xHTTP+TLS + Nginx

[简体中文](/README.md) | [English](/languages/en/README.md) | [Français](/languages/fr/README.md) | Русский | [فارسی](/languages/fa/README.md) | [한국어](/languages/ko/README.md)

[![GitHub stars](https://img.shields.io/github/stars/hello-yunshu/Xray_bash_onekey?color=%230885ce)](https://github.com/hello-yunshu/Xray_bash_onekey/stargazers) [![GitHub forks](https://img.shields.io/github/forks/hello-yunshu/Xray_bash_onekey?color=%230885ce)](https://github.com/hello-yunshu/Xray_bash_onekey/network) [![GitHub issues](https://img.shields.io/github/issues/hello-yunshu/Xray_bash_onekey)](https://github.com/hello-yunshu/Xray_bash_onekey/issues)

> Спасибо за разрешение на некоммерческое развитие открытого исходного кода JetBrains

## Возможности

* Введите `idleleo` для управления скриптом ([Узнать предысторию `idleleo`](https://github.com/hello-yunshu/Xray_bash_onekey/wiki/%D0%98%D1%81%D1%82%D0%B8%D0%BD%D0%BD%D0%BE%D0%B5-%D0%9B%D0%B8%D1%86%D0%BE-%D0%97%D0%B0-%D0%A2%D1%83%D0%BC%D0%B0%D0%BD%D0%BE%D0%BC))
* Точный многоязычный перевод на базе Qwen-MT-Plus AI
* Поддержка протокола Reality с рекомендуемым фронтендом Nginx (устанавливается через скрипт)
* Поддержка транспортов WebSocket, gRPC и xHTTP: можно включить один транспорт или `ws+gRPC+xHTTP` одновременно
* Встроенная защита fail2ban (устанавливается через скрипт)
* Встроенная статистика трафика Xray, блокировка трафика, обновление правил GeoIP/GeoSite и обновления по расписанию
* Поддержка автообновления скрипта, Xray, Nginx и сертификатов, а также полного резервного копирования и восстановления
* Использует [предложение](https://github.com/XTLS/Xray-core/issues/91) ссылки для обмена от [@DuckSoft](https://github.com/DuckSoft) (beta), совместимое с Qv2ray, V2rayN, V2rayNG
* Использует предложение проекта [XTLS](https://github.com/XTLS/Xray-core/issues/158), следуя стандарту [UUIDv5](https://tools.ietf.org/html/rfc4122#section-4.3), поддерживая маппинг пользовательских строк в UUID VLESS
* Поддержка протокола gRPC: [Использование протокола gRPC](https://hey.run/archives/xrayjin-jie-wan-fa---shi-yong-grpcxie-yi)
* Поддержка балансировки нагрузки Reality / ws/gRPC/xHTTP:
  - [Развёртывание балансировщика нагрузки Reality](https://hey.run/archives/bushu-reality-balance)
  - [Создание балансировщика нагрузки бэкенда](https://hey.run/archives/xrayjin-jie-wan-fa---da-jian-hou-duan-fu-wu-qi-fu-zai-jun-heng)

## Дополнительные материалы

* Руководство по установке Reality: [Настройка сервера Xray Reality](https://hey.run/archives/da-jian-xray-reality-xie-yi-fu-wu-qi)
* Риски протокола Reality: [Риски протокола Xray Reality](https://hey.run/archives/reality-xie-yi-de-feng-xian)
* Ускорение сервера с помощью Reality: [Ускорение сервера через «уязвимость» протокола Reality](https://hey.run/archives/use-reality)

## Группа Telegram

* Группа обсуждения: [Нажмите, чтобы присоединиться](https://t.me/+48VSqv7xIIFmZDZl)

## Требования

* Заграничный сервер с публичным IP-адресом
* Для протокола Reality: подготовьте целевой домен, соответствующий требованиям Xray
* Для режима TLS: подготовьте домен и добавьте A-запись
* Прочитайте [официальную документацию Xray](https://xtls.github.io), чтобы понять Reality, TLS, WebSocket, gRPC и связанные концепции Xray
* **Убедитесь, что установлен curl**: пользователи CentOS выполняют `yum install -y curl`; пользователи Debian/Ubuntu выполняют `apt install -y curl`

## Быстрая установка

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/hello-yunshu/Xray_bash_onekey/main/install.sh)
```

## Режимы установки

| Режим | Описание |
|-------|----------|
| Reality + Nginx | Рекомендуемый режим, с опциональными вспомогательными транспортами ws/gRPC/xHTTP для балансировки нагрузки |
| Nginx + TLS | Поддерживает ws/gRPC/xHTTP и автоматически выпускает и продлевает сертификаты Let's Encrypt |
| ws/gRPC/xHTTP ONLY | Автономный входящий режим без TLS, в основном для серверных сценариев или балансировки нагрузки |
| XTLS ONLY | Только для ретрансляции трафика и других специальных сценариев |
| Docker | Образ с предустановленными Xray, Nginx и основным скриптом |

При установке режимов ws/gRPC/xHTTP можно выбрать `ws`, `gRPC`, `xHTTP` или `ws+gRPC+xHTTP`. Скрипт создаёт соответствующие порты, пути, ссылки для обмена и QR-коды. Clash пока не поддерживает xHTTP, и скрипт укажет это в сгенерированном выводе конфигурации.

## Частые команды

| Действие | Команда |
|----------|---------|
| Открыть меню управления | `idleleo` |
| Показать справку | `idleleo --help` |
| Установить режим Reality | `idleleo --install-reality` |
| Установить режим TLS | `idleleo --install-tls` |
| Установить ws/gRPC/xHTTP ONLY | `idleleo --install-none` |
| Показать сведения об установке | `idleleo --show` |
| Обновить скрипт | `idleleo --update` |
| Обновить Xray | `idleleo --xray-update` |
| Обновить Nginx | `idleleo --nginx-update` |
| Настроить Fail2ban | `idleleo --set-fail2ban` |
| Настроить блокировку трафика | `idleleo --traffic-blocker` |
| Смотреть трафик портов в реальном времени | `idleleo --port-traffic` |

## Развёртывание Docker

Поддерживается развёртывание через Docker. Образ поставляется с предустановленными Xray и Nginx, все функции оригинального скрипта доступны в контейнере. Подробности см. в [Руководстве по развёртыванию Docker](/languages/ru/DOCKER.md).

```bash
git clone https://github.com/hello-yunshu/Xray_bash_onekey.git
cd Xray_bash_onekey
docker compose up -d
docker attach xray-onekey
```

## Важные замечания

* Если вы не знакомы с настройками, используйте значения по умолчанию для необязательных полей (просто нажимайте Enter)
* Пользователям Cloudflare следует включать CDN только после завершения установки
* Этот скрипт требует базовых знаний Linux и компьютерных сетей
* Поддерживаются Debian 12+ / Ubuntu 24.04+ / CentOS Stream 10+; некоторые шаблоны CentOS могут иметь проблемы с компиляцией — при возникновении проблем рекомендуется сменить ОС
* Рекомендуется развёртывать только один прокси на сервер и использовать порт 443 по умолчанию
* Сопоставление пользовательских строк с UUIDv5 требует поддержки на стороне клиента
* Используйте этот скрипт в чистой среде; новичкам не рекомендуется использовать CentOS
* Эта программа зависит от Nginx — пользователи, установившие Nginx через [LNMP](https://lnmp.org) или аналогичные скрипты, должны учитывать возможные конфликты
* Ссылки xHTTP предназначены для клиентов с поддержкой xHTTP; вывод конфигурации Clash пропускает xHTTP
* Не используйте этот скрипт в рабочей среде, не проверив его работоспособность
* Автор предоставляет ограниченную поддержку (потому что не очень умён)

## Благодарности

* Основано на [wulabing/V2Ray_ws-tls_bash_onekey](https://github.com/wulabing/V2Ray_ws-tls_bash_onekey)
* Скрипт ускорения TCP из [ylx2016/Linux-NetSpeed](https://github.com/ylx2016/Linux-NetSpeed)

## Настройка сертификатов

**Пользовательский сертификат**: Переименуйте файлы crt и key в `xray.crt` и `xray.key`, затем поместите их в каталог `/etc/idleleo/cert` (создайте его при отсутствии). Обратите внимание на права доступа и срок действия — пользовательские сертификаты необходимо продлевать вручную после истечения срока.

**Автоматический сертификат**: Скрипт поддерживает автоматическую генерацию сертификатов Let's Encrypt (действительны 3 месяца), с теоретической поддержкой автоматического продления.

## Просмотр конфигурации клиента

```bash
cat /etc/idleleo/info/xray_info.inf
```

## О Xray

* Xray — отличный инструмент сетевого прокси с открытым исходным кодом, поддерживающий Windows, macOS, Android, iOS, Linux и другие платформы
* Этот скрипт обеспечивает полную настройку в один клик — после успешного завершения всех процессов просто настройте клиент по результатам вывода
* **Настоятельно рекомендуется** полностью понять рабочий процесс и принципы программы

## Управление службами

| Действие | Команда |
|----------|---------|
| Запустить Xray | `systemctl start xray` |
| Остановить Xray | `systemctl stop xray` |
| Запустить Nginx | `systemctl start nginx` |
| Остановить Nginx | `systemctl stop nginx` |

## Каталоги

| Элемент | Путь |
|---------|------|
| Конфигурация сервера Xray | `/etc/idleleo/conf/xray/config.json` |
| Каталог Nginx | `/usr/local/nginx` |
| Файлы сертификатов | `/etc/idleleo/cert/xray.key`, `/etc/idleleo/cert/xray.crt` |
| Информация о конфигурации и т.д. | `/etc/idleleo` |
