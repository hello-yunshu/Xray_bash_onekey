# Xray Скрипт установки в один клик — Reality / VLESS WebSocket/gRPC/xHTTP+TLS + Nginx

Упрощенный китайский |[English](/i18n/languages/en/README.md) | [Français](/i18n/languages/fr/README.md) | [Русский](/i18n/languages/ru/README.md) | [فارسی](/i18n/languages/fa/README.md) | [한국어](/i18n/languages/ko/README.md)

[![GitHub stars](https://img.shields.io/github/stars/hello-yunshu/Xray_bash_onekey?color=%230885ce)](https://github.com/hello-yunshu/Xray_bash_onekey/stargazers) [![GitHub forks](https://img.shields.io/github/forks/hello-yunshu/Xray_bash_onekey?color=%230885ce)](https://github.com/hello-yunshu/Xray_bash_onekey/network) [![GitHub issues](https://img.shields.io/github/issues/hello-yunshu/Xray_bash_onekey)](https://github.com/hello-yunshu/Xray_bash_onekey/issues)

> Thanks for non-commercial open source development authorization by JetBrains

## Функции

* входить`idleleo`Вы можете управлять скриптами ([查看 `idleleo` 背景故事](https://github.com/hello-yunshu/Xray_bash_onekey/wiki/%E8%BF%B7%E9%9B%BE%E5%90%8E%E7%9A%84%E7%9C%9F%E5%AE%B9)）
* Используйте Qwen-MT-Plus AI для точного перевода на несколько языков.
* Поддерживает протокол Reality, рекомендуется использовать префикс Nginx (можно установить в скрипт)
* Поддерживает передачу WebSocket, gRPC, xHTTP, вы можете выбрать одну передачу или`ws+gRPC+xHTTP`Включить оба
* Встроенная защита fail2ban (устанавливается внутри скрипта)
* Встроенная статистика трафика Xray, блокировка трафика, обновление правил GeoIP/GeoSite и регулярное обновление.
* Поддерживает сценарии Xray, Nginx, автоматическое обновление сертификатов и обеспечивает полное резервное копирование и восстановление.
* использовать[@DuckSoft](https://github.com/DuckSoft)ссылка для обмена[提案](https://github.com/XTLS/Xray-core/issues/91)(beta), совместим с Qv2ray, V2rayN, V2rayNG
* использовать[XTLS](https://github.com/XTLS/Xray-core/issues/158)предложение, следуйте[UUIDv5](https://tools.ietf.org/html/rfc4122#section-4.3)Стандарт, поддерживает пользовательское сопоставление строк с VLESS UUID.
* Поддерживает протокол gRPC:[使用 gRPC 协议](https://hey.run/posts/xrayjin-jie-wan-fa---shi-yong-grpcxie-yi)
* Поддерживает балансировку нагрузки Reality/ws/gRPC/xHTTP:
  - [部署 Reality 负载均衡](https://hey.run/posts/bushu-reality-balance)
  - [搭建后端负载均衡](https://hey.run/posts/xrayjin-jie-wan-fa---da-jian-hou-duan-fu-wu-qi-fu-zai-jun-heng)
* Режим Reality + Nginx включен по умолчанию. SNI Guard: неизвестный SNI, пустой SNI и исключение TLS не попадут в серверную часть Xray Reality. Стратегия изоляции (ssl_reject_handshake) применяется по умолчанию. Опытные пользователи могут переключиться на самостоятельно созданный резервный сайт decoy или напрямую TCP Отказано. Эта функция используется для уменьшения активного обнаружения и воздействия неправильной конфигурации и не обеспечивает идеальную маскировку.

## Дальнейшее чтение

* Reality Руководство по установке:[搭建 Xray Reality 服务器](https://hey.run/posts/da-jian-xray-reality-xie-yi-fu-wu-qi)
* Reality Риск протокола:[Xray Reality 协议的风险](https://hey.run/posts/reality-xie-yi-de-feng-xian)
* Reality Ускоренный сервер:[利用 Reality 协议"漏洞"加速服务器](https://hey.run/posts/use-reality)

## Telegram группа

* Группа связи:[点击加入](https://t.me/+48VSqv7xIIFmZDZl)

## Подготовка

* Зарубежный сервер с общедоступной сетью IP
* Установите протокол Reality: вам необходимо подготовить целевое доменное имя, соответствующее требованиям Xray.
* Установите версию TLS: подготовьте доменное имя и добавьте запись A.
* читать[Xray 官方文档](https://xtls.github.io), понимать понятия, связанные с Reality, TLS, WebSocket, gRPC и Xray.
* **Убедитесь, что curl установлен: CentOS пользовательское выполнение.`yum install -y curl`;Debian/Ubuntu Пользовательское выполнение`apt install -y curl`

## Быстрая установка

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/hello-yunshu/Xray_bash_onekey/main/install.sh)
```

## Режим установки

| модель | иллюстрировать |
|------|------|
| Reality + Nginx | Рекомендуемый режим: вы можете подключить простой протокол ws/gRPC/xHTTP, необходимый для балансировки нагрузки. |
| Nginx + TLS | Поддержка ws/gRPC/xHTTP, автоматическая подача заявки и продление сертификата Let's Encrypt |
| ws/gRPC/xHTTP ONLY | Независимый входящий режим без TLS, в основном используется в сценариях серверной части или балансировки нагрузки. |
| XTLS ONLY | Используется только в определенных сценариях, таких как передача трафика. |
| Docker | Xray, Nginx и основной скрипт предустановлены в образе |

Необязательно при установке режимов, связанных с ws/gRPC/xHTTP.`ws`、`gRPC`、`xHTTP`или`ws+gRPC+xHTTP`. Скрипт сгенерирует соответствующий порт, путь, ссылку для совместного использования и QR-код соответственно; Clash в настоящее время не поддерживает xHTTP, и сценарий выдаст запрос в выходных данных конфигурации.

## Общие команды

| действовать | Заказ |
|------|------|
| Откройте меню администратора | `idleleo` |
| Посмотреть справку | `idleleo --help` |
| Установите режим Reality | `idleleo --install-reality` |
| Установите режим TLS | `idleleo --install-tls` |
| Установите ws/gRPC/xHTTP ONLY | `idleleo --install-none` |
| Просмотр информации об установке | `idleleo --show` |
| обновить скрипт | `idleleo --update` |
| Обновление Xray | `idleleo --xray-update` |
| Обновление Nginx | `idleleo --nginx-update` |
| Установить Fail2ban | `idleleo --set-fail2ban` |
| Настроить блокировку трафика | `idleleo --traffic-blocker` |
| Просмотр трафика порта в реальном времени | `idleleo --port-traffic` |

## Docker Развертывание

Поддерживает развертывание с помощью Docker, образ предварительно установлен с Xray и Nginx, а все функции исходного скрипта можно использовать непосредственно в контейнере. Посмотреть подробности[Docker 部署指南](/docker/DOCKER.md)。

```bash
git clone https://github.com/hello-yunshu/Xray_bash_onekey.git
cd Xray_bash_onekey
docker compose up -d
docker attach xray-onekey
```

## AI Skill Развертывание

Поддерживает автоматическое развертывание Xray с помощью инструментов AI, таких как Trae, без ручного взаимодействия. Посмотреть подробности[Xray_bash_onekey_skill](https://github.com/hello-yunshu/Xray_bash_onekey_skill)。

Традиционный метод требует, чтобы SSH зашел на сервер, запустил сценарий установки и ответил на интерактивные вопросы один за другим; методу Skill нужно только сообщить AI о ваших потребностях, а AI автоматически сгенерирует неинтерактивный скрипт и выполнит его, напрямую возвращая ссылку VLESS.

**Поддерживаемые режимы**: Reality / TLS / ws ONLY / XTLS ONLY

**Как использовать**: прямо скажите «Помогите мне собрать Xray на сервере» в инструменте AI, поддерживающем Skill, и AI автоматически соберет информацию, сгенерирует сценарии, выполнит развертывание и вернет информацию о соединении.

## На что следует обратить внимание

* Если вы не понимаете значение каждого параметра, используйте значение по умолчанию, за исключением обязательных полей (просто нажмите Enter).
* Cloudflare Пользователи, откройте CDN после завершения установки.
* Этот сценарий требует базовых знаний Linux и знаний компьютерной сети.
* Поддерживает Debian 12+ / Ubuntu 24.04+ / CentOS Stream 10+, некоторые шаблоны CentOS могут иметь проблемы с компиляцией, при возникновении проблем рекомендуется сменить систему
* Рекомендуется на одном сервере развернуть только один агент и использовать порт по умолчанию 443.
* Пользовательское сопоставление строк с UUIDv5 требует поддержки клиента.
* Рекомендуется использовать его в чистой среде; новичкам не следует использовать CentOS
* Эта программа зависит от Nginx, прошло[LNMP](https://lnmp.org)Пользователям, установившим скрипт Nginx, обратите внимание на возможные конфликты.
* Общая ссылка xHTTP предназначена для клиентов, поддерживающих xHTTP; В выводе конфигурации Clash будет пропущен xHTTP.
* Не используйте этот сценарий в производственной среде без предварительной проверки доступности.
* Автор предоставляет лишь ограниченную поддержку (потому что он слишком глуп)

## Благодарности

* на основе[wulabing/V2Ray_ws-tls_bash_onekey](https://github.com/wulabing/V2Ray_ws-tls_bash_onekey)развивать
* Сценарий ускорения TCP, цитата из[ylx2016/Linux-NetSpeed](https://github.com/ylx2016/Linux-NetSpeed)

## Конфигурация сертификата

**Пользовательский сертификат**: назовите файлы crt и key соответственно.`xray.crt`и`xray.key`, Путин`/etc/idleleo/cert`Каталог (если каталог не существует, сначала создайте его). Обратите внимание на центр сертификации и срок действия. По истечении срока действия пользовательского сертификата вам необходимо продлить его самостоятельно.

**Автоматический сертификат**: скрипт поддерживает автоматическое создание сертификатов Let's Encrypt (действителен в течение 3 месяцев) и теоретически поддерживает автоматическое продление.

## Просмотр конфигурации клиента

```bash
cat /etc/idleleo/info/xray_info.inf
```

## Xray Введение

* Xray — отличный сетевой прокси-инструмент с открытым исходным кодом, который поддерживает Windows, macOS, Android, iOS, Linux и другие полные платформы.
* Этот сценарий представляет собой сценарий полной настройки одним щелчком мыши. После того, как все процессы завершатся нормально, клиент можно использовать в соответствии с полученными результатами.
* **НАСТОЯТЕЛЬНО РЕКОМЕНДУЕТСЯ** Полное понимание рабочего процесса и принципов программы.

## Управление услугами

| действовать | Заказ |
|------|------|
| Начать Xray | `systemctl start xray` |
| Остановить Xray | `systemctl stop xray` |
| Начать Nginx | `systemctl start nginx` |
| Остановить Nginx | `systemctl stop nginx` |

## Сопутствующий каталог

| содержание | путь |
|------|------|
| Домашний каталог | `/etc/idleleo` |
| Xray конфигурация | `/etc/idleleo/conf/xray/config.json` |
| Nginx конфигурация | `/etc/idleleo/conf/nginx/` |
| Информация по установке | `/etc/idleleo/conf/install_config.json` |
| файл сертификата | `/etc/idleleo/cert/xray.key`、`/etc/idleleo/cert/xray.crt` |
| Каталог журналов | `/etc/idleleo/logs/`、`/var/log/xray/` |
| Nginx каталог установки | `/usr/local/nginx` |
| Административные команды | `/usr/bin/idleleo` |
