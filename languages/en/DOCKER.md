# Docker Deployment Guide

[简体中文](/DOCKER.md) | English | [Français](/languages/fr/DOCKER.md) | [Русский](/languages/ru/DOCKER.md) | [فارسی](/languages/fa/DOCKER.md) | [한국어](/languages/ko/DOCKER.md)

This document describes how to deploy the Xray one-click script using Docker.

## Prerequisites

* Docker and Docker Compose installed
* A server with a public IP address
* For Reality protocol: prepare a target domain that meets Xray's requirements
* For TLS version: prepare a domain and add an A record

## Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/hello-yunshu/Xray_bash_onekey.git
cd Xray_bash_onekey
```

### 2. Build and Start the Container

```bash
docker compose up -d
```

### 3. Enter the Interactive Installation Menu

```bash
docker attach xray-onekey
```

On first run, the container will automatically launch the installation script. Follow the prompts to complete the configuration.

## Running Modes

The container supports the following running modes:

| Mode | Description | Command |
|------|-------------|---------|
| `idleleo` (default) | Start services and enter interactive management menu | `docker compose up -d` |
| `start` | Start services only (daemon mode) | Modify `command: start` in `docker-compose.yml` |
| `shell` | Start services and enter a shell | `docker exec -it xray-onekey bash` |

## Management Operations

### Enter Management Menu

```bash
docker exec -it xray-onekey idleleo
```

### Check Service Status

```bash
docker exec -it xray-onekey systemctl status xray
docker exec -it xray-onekey systemctl status nginx
```

### Restart Services

```bash
docker exec -it xray-onekey systemctl restart xray
docker exec -it xray-onekey systemctl restart nginx
```

### View Client Configuration

```bash
docker exec -it xray-onekey cat /etc/idleleo/info/xray_info.inf
```

### View Logs

```bash
docker exec -it xray-onekey cat /var/log/xray/access.log
docker exec -it xray-onekey cat /var/log/xray/error.log
```

## Using docker run (Alternative to docker compose)

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

## Data Persistence

The container uses Docker Volumes to persist data. Configuration is preserved when containers are recreated:

| Volume | Container Path | Description |
|--------|---------------|-------------|
| `xray-conf` | `/etc/idleleo/conf` | Xray and Nginx configuration files |
| `xray-cert` | `/etc/idleleo/cert` | SSL certificate files |
| `xray-info` | `/etc/idleleo/info` | Connection info and status files |
| `xray-logs` | `/var/log/xray` | Xray log files |
| `acme-data` | `/root/.acme.sh` | acme.sh certificate issuance data |

## Custom Certificates

Place `xray.crt` and `xray.key` files in the host path corresponding to the certificate volume. Use `docker volume inspect xray-cert` to find the host path.

## Network Configuration

The container uses `network_mode: host` by default, which means it directly uses the host network. This is essential for Xray proxy services:

* Reality mode requires seeing the real client IP
* TLS mode requires direct binding to ports 443/80
* Avoids additional NAT forwarding performance overhead

## Important Notes

* The container uses `fake-systemctl` instead of systemd; `systemctl` commands work normally
* Firewall management is recommended at the host level rather than inside the container
* A built-in watchdog checks service status every 30 seconds and automatically restarts on failure
* Automatic certificate renewal works inside the container (ensure port 80 is accessible)
* fail2ban can be installed via the management menu if needed

## Troubleshooting

### Container Fails to Start

```bash
docker logs xray-onekey
```

### Services Not Running

```bash
docker exec -it xray-onekey systemctl status xray
docker exec -it xray-onekey systemctl start xray
```

### Re-enter Installation Menu

```bash
docker exec -it xray-onekey idleleo
```

### Complete Reset

```bash
docker compose down
docker volume rm xray-conf xray-cert xray-info xray-logs acme-data
docker compose up -d
```
