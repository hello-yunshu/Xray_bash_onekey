# Руководство по развёртыванию Docker

[简体中文](/DOCKER.md) | [English](/languages/en/DOCKER.md) | [Français](/languages/fr/DOCKER.md) | Русский | [فارسی](/languages/fa/DOCKER.md) | [한국어](/languages/ko/DOCKER.md)

В этом руководстве описывается запуск скрипта автоматической установки Xray с использованием Docker. Образ поставляется с предустановленными Xray и Nginx, все функции оригинального скрипта доступны в контейнере.

## Быстрый старт

### 1. Клонирование и сборка

```bash
git clone https://github.com/hello-yunshu/Xray_bash_onekey.git
cd Xray_bash_onekey
docker compose up -d
```

### 2. Вход в интерактивное меню установки

```bash
docker attach xray-onekey
```

При первом запуске скрипт установки запускается автоматически. Следуйте подсказкам для завершения настройки. После выхода из меню контейнер автоматически переходит в режим демона.

### 3. Последующее управление

```bash
docker exec -it xray-onekey idleleo
```

## Режимы работы

| Режим | Описание | Команда |
|-------|----------|---------|
| `idleleo` (по умолчанию) | Запуск служб и вход в меню управления | `docker compose up -d` + `docker attach xray-onekey` |
| `start` | Только запуск служб (режим демона) | Измените `command: start` в `docker-compose.yml` |
| `shell` | Запуск служб и вход в оболочку | `docker exec -it xray-onekey bash` |

## Управление

Все команды оригинального скрипта доступны:

```bash
docker exec -it xray-onekey idleleo          # Меню управления
docker exec -it xray-onekey idleleo -s        # Просмотр информации об установке
docker exec -it xray-onekey idleleo -x        # Обновление Xray
docker exec -it xray-onekey idleleo -n        # Обновление Nginx
docker exec -it xray-onekey idleleo -h        # Справка
```

## Использование docker run

```bash
docker build -t xray-onekey .

docker run -d --name xray-onekey   --network host   --cap-add NET_ADMIN   -e TZ=Asia/Shanghai   -v xray-conf:/etc/idleleo/conf   -v xray-cert:/etc/idleleo/cert   -v xray-info:/etc/idleleo/info   -v xray-logs:/var/log/xray   -v acme-data:/root/.acme.sh   -it xray-onekey
```

## Сохранение данных

| Том | Путь в контейнере | Описание |
|-----|-------------------|----------|
| `xray-conf` | `/etc/idleleo/conf` | Файлы конфигурации Xray и Nginx |
| `xray-cert` | `/etc/idleleo/cert` | Файлы SSL-сертификатов |
| `xray-info` | `/etc/idleleo/info` | Информация о подключении и файлы состояния |
| `xray-logs` | `/var/log/xray` | Файлы журналов Xray |
| `acme-data` | `/root/.acme.sh` | Данные выпуска сертификатов acme.sh |

## Сетевая конфигурация

Контейнер использует `network_mode: host`, напрямую используя сеть хоста:

* Режиму Reality необходимо видеть реальный IP клиента
* Режиму TLS требуется прямая привязка к портам 443/80
* Избегает дополнительных накладных расходов на трансляцию NAT

## Важные замечания

* В контейнере используется `fake-systemctl` вместо systemd; команды `systemctl` работают нормально
* Встроенный сторожевой таймер проверяет статус служб каждые 30 секунд и автоматически перезапускает их при сбое
* После выхода из меню управления контейнер автоматически переходит в режим демона — службы продолжают работать
* Управление брандмауэром рекомендуется на уровне хоста
* Автоматическое продление сертификатов работает в контейнере (убедитесь, что порт 80 доступен)

## Устранение неполадок

```bash
docker logs xray-onekey                    # Просмотр журналов контейнера
docker exec -it xray-onekey bash           # Вход в контейнер
docker exec -it xray-onekey idleleo -s     # Просмотр информации об установке
```

### Полный сброс

```bash
docker compose down
docker volume rm xray-conf xray-cert xray-info xray-logs acme-data
docker compose up -d
```
