# Руководство по развёртыванию Docker

[简体中文](/DOCKER.md) | [English](/languages/en/DOCKER.md) | [Français](/languages/fr/DOCKER.md) | Русский | [فارسی](/languages/fa/DOCKER.md) | [한국어](/languages/ko/DOCKER.md)

В этом документе описывается развёртывание скрипта автоматической установки Xray с использованием Docker.

## Требования

* Установленные Docker и Docker Compose
* Сервер с публичным IP-адресом
* Для протокола Reality: подготовьте целевой домен, соответствующий требованиям Xray
* Для версии с TLS: подготовьте домен и добавьте A-запись

## Быстрый старт

### 1. Клонирование репозитория

```bash
git clone https://github.com/hello-yunshu/Xray_bash_onekey.git
cd Xray_bash_onekey
```

### 2. Сборка и запуск контейнера

```bash
docker compose up -d
```

### 3. Вход в интерактивное меню установки

```bash
docker attach xray-onekey
```

При первом запуске контейнер автоматически запустит скрипт установки. Следуйте подсказкам для завершения настройки.

## Режимы работы

Контейнер поддерживает следующие режимы работы:

| Режим | Описание | Команда |
|-------|----------|---------|
| `idleleo` (по умолчанию) | Запуск служб и вход в интерактивное меню управления | `docker compose up -d` |
| `start` | Только запуск служб (режим демона) | Измените `command: start` в `docker-compose.yml` |
| `shell` | Запуск служб и вход в оболочку | `docker exec -it xray-onekey bash` |

## Управление

### Вход в меню управления

```bash
docker exec -it xray-onekey idleleo
```

### Проверка статуса служб

```bash
docker exec -it xray-onekey systemctl status xray
docker exec -it xray-onekey systemctl status nginx
```

### Перезапуск служб

```bash
docker exec -it xray-onekey systemctl restart xray
docker exec -it xray-onekey systemctl restart nginx
```

### Просмотр конфигурации клиента

```bash
docker exec -it xray-onekey cat /etc/idleleo/info/xray_info.inf
```

### Просмотр журналов

```bash
docker exec -it xray-onekey cat /var/log/xray/access.log
docker exec -it xray-onekey cat /var/log/xray/error.log
```

## Использование docker run (альтернатива docker compose)

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

## Сохранение данных

Контейнер использует тома Docker для сохранения данных. Конфигурация сохраняется при пересоздании контейнеров:

| Том | Путь в контейнере | Описание |
|-----|-------------------|----------|
| `xray-conf` | `/etc/idleleo/conf` | Файлы конфигурации Xray и Nginx |
| `xray-cert` | `/etc/idleleo/cert` | Файлы SSL-сертификатов |
| `xray-info` | `/etc/idleleo/info` | Информация о подключении и файлы состояния |
| `xray-logs` | `/var/log/xray` | Файлы журналов Xray |
| `acme-data` | `/root/.acme.sh` | Данные выпуска сертификатов acme.sh |

## Пользовательские сертификаты

Поместите файлы `xray.crt` и `xray.key` по пути хоста, соответствующему тому сертификатов. Используйте `docker volume inspect xray-cert` для определения пути на хосте.

## Сетевая конфигурация

Контейнер по умолчанию использует `network_mode: host`, то есть напрямую использует сеть хоста. Это критически важно для прокси-сервисов Xray:

* Режиму Reality необходимо видеть реальный IP клиента
* Режиму TLS требуется прямая привязка к портам 443/80
* Избегает дополнительных накладных расходов на трансляцию NAT

## Важные замечания

* В контейнере используется `fake-systemctl` вместо systemd; команды `systemctl` работают нормально
* Управление брандмауэром рекомендуется на уровне хоста, а не внутри контейнера
* Встроенный сторожевой таймер проверяет статус служб каждые 30 секунд и автоматически перезапускает их при сбое
* Автоматическое продление сертификатов работает в контейнере (убедитесь, что порт 80 доступен)
* fail2ban можно установить через меню управления при необходимости

## Устранение неполадок

### Контейнер не запускается

```bash
docker logs xray-onekey
```

### Службы не работают

```bash
docker exec -it xray-onekey systemctl status xray
docker exec -it xray-onekey systemctl start xray
```

### Повторный вход в меню установки

```bash
docker exec -it xray-onekey idleleo
```

### Полный сброс

```bash
docker compose down
docker volume rm xray-conf xray-cert xray-info xray-logs acme-data
docker compose up -d
```
