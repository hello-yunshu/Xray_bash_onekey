# Docker Deployment Guide

[简体中文](/DOCKER.md) | English | [Français](/languages/fr/DOCKER.md) | [Русский](/languages/ru/DOCKER.md) | [فارسی](/languages/fa/DOCKER.md) | [한국어](/languages/ko/DOCKER.md)

This guide describes how to run the Xray one-click script using Docker. The image comes with Xray and Nginx pre-installed, and all original script features are available inside the container.

## Quick Start

### 1. Clone and Build

```bash
git clone https://github.com/hello-yunshu/Xray_bash_onekey.git
cd Xray_bash_onekey
docker compose up -d
```

### 2. Enter Interactive Installation Menu

```bash
docker attach xray-onekey
```

On first run, the installation script launches automatically. Follow the prompts to complete the configuration. After exiting the menu, the container enters daemon mode automatically.

### 3. Subsequent Management

```bash
docker exec -it xray-onekey idleleo
```

## Running Modes

| Mode | Description | Command |
|------|-------------|---------|
| `idleleo` (default) | Start services and enter management menu | `docker compose up -d` + `docker attach xray-onekey` |
| `start` | Start services only (daemon mode) | Modify `command: start` in `docker-compose.yml` |
| `shell` | Start services and enter shell | `docker exec -it xray-onekey bash` |

## Management Operations

All original script commands are available:

```bash
docker exec -it xray-onekey idleleo          # Management menu
docker exec -it xray-onekey idleleo -s        # View installation info
docker exec -it xray-onekey idleleo -x        # Update Xray
docker exec -it xray-onekey idleleo -n        # Update Nginx
docker exec -it xray-onekey idleleo -h        # Show help
```

## Using docker run

```bash
docker build -t xray-onekey .

docker run -d --name xray-onekey   --network host   --cap-add NET_ADMIN   -e TZ=Asia/Shanghai   -v xray-conf:/etc/idleleo/conf   -v xray-cert:/etc/idleleo/cert   -v xray-info:/etc/idleleo/info   -v xray-logs:/var/log/xray   -v acme-data:/root/.acme.sh   -it xray-onekey
```

## Data Persistence

| Volume | Container Path | Description |
|--------|---------------|-------------|
| `xray-conf` | `/etc/idleleo/conf` | Xray and Nginx configuration files |
| `xray-cert` | `/etc/idleleo/cert` | SSL certificate files |
| `xray-info` | `/etc/idleleo/info` | Connection info and status files |
| `xray-logs` | `/var/log/xray` | Xray log files |
| `acme-data` | `/root/.acme.sh` | acme.sh certificate issuance data |

## Network Configuration

The container uses `network_mode: host`, directly using the host network:

* Reality mode requires seeing the real client IP
* TLS mode requires direct binding to ports 443/80
* Avoids additional NAT forwarding performance overhead

## Important Notes

* The container uses `fake-systemctl` instead of systemd; `systemctl` commands work normally
* A built-in watchdog checks service status every 30 seconds and auto-restarts on failure
* After exiting the management menu, the container enters daemon mode automatically — services keep running
* Firewall management is recommended at the host level
* Automatic certificate renewal works inside the container (ensure port 80 is accessible)

## Troubleshooting

```bash
docker logs xray-onekey                    # View container logs
docker exec -it xray-onekey bash           # Enter container
docker exec -it xray-onekey idleleo -s     # View installation info
```

### Complete Reset

```bash
docker compose down
docker volume rm xray-conf xray-cert xray-info xray-logs acme-data
docker compose up -d
```
