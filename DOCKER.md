# Docker 部署指南

简体中文 | [English](/languages/en/DOCKER.md) | [Français](/languages/fr/DOCKER.md) | [Русский](/languages/ru/DOCKER.md) | [فارسی](/languages/fa/DOCKER.md) | [한국어](/languages/ko/DOCKER.md)

本文档介绍如何使用 Docker 部署 Xray 一键脚本。

## 前提条件

* 已安装 Docker 和 Docker Compose
* 服务器具备公网 IP
* 安装 Reality 协议：需准备符合 Xray 要求的目标域名
* 安装 TLS 版本：需准备域名并添加 A 记录

## 快速启动

### 1. 克隆仓库

```bash
git clone https://github.com/hello-yunshu/Xray_bash_onekey.git
cd Xray_bash_onekey
```

### 2. 构建并启动容器

```bash
docker compose up -d
```

### 3. 进入交互式安装菜单

```bash
docker attach xray-onekey
```

首次运行时，容器会自动启动安装脚本，按照提示完成配置即可。

## 运行模式

容器支持以下运行模式：

| 模式 | 说明 | 命令 |
|------|------|------|
| `idleleo`（默认） | 启动服务并进入交互式管理菜单 | `docker compose up -d` |
| `start` | 仅启动服务（守护模式） | 修改 `docker-compose.yml` 中的 `command: start` |
| `shell` | 启动服务并进入 Shell | `docker exec -it xray-onekey bash` |

## 管理操作

### 进入管理菜单

```bash
docker exec -it xray-onekey idleleo
```

### 查看服务状态

```bash
docker exec -it xray-onekey systemctl status xray
docker exec -it xray-onekey systemctl status nginx
```

### 重启服务

```bash
docker exec -it xray-onekey systemctl restart xray
docker exec -it xray-onekey systemctl restart nginx
```

### 查看客户端配置

```bash
docker exec -it xray-onekey cat /etc/idleleo/info/xray_info.inf
```

### 查看日志

```bash
docker exec -it xray-onekey cat /var/log/xray/access.log
docker exec -it xray-onekey cat /var/log/xray/error.log
```

## 使用 docker run（替代 docker compose）

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

## 数据持久化

容器使用 Docker Volume 保存数据，重建容器后配置不会丢失：

| Volume | 容器路径 | 说明 |
|--------|---------|------|
| `xray-conf` | `/etc/idleleo/conf` | Xray 和 Nginx 配置文件 |
| `xray-cert` | `/etc/idleleo/cert` | SSL 证书文件 |
| `xray-info` | `/etc/idleleo/info` | 连接信息和状态文件 |
| `xray-logs` | `/var/log/xray` | Xray 日志文件 |
| `acme-data` | `/root/.acme.sh` | acme.sh 证书签发数据 |

## 自定义证书

将 `xray.crt` 和 `xray.key` 文件放入证书 Volume 对应的宿主机路径。使用 `docker volume inspect xray-cert` 查看宿主机路径。

## 网络配置

容器默认使用 `network_mode: host`，即直接使用宿主机网络。这对 Xray 代理服务至关重要：

* Reality 模式需要看到真实客户端 IP
* TLS 模式需要直接绑定 443/80 端口
* 避免额外的 NAT 转发性能损耗

## 注意事项

* 容器内使用 `fake-systemctl` 替代 systemd，`systemctl` 命令可正常使用
* 防火墙建议在宿主机层面管理，而非容器内
* 容器内置看门狗（watchdog），每 30 秒检查服务状态，异常时自动重启
* 证书自动续签在容器内可正常工作（需确保 80 端口可访问）
* 如需使用 fail2ban，可通过管理菜单安装

## 故障排查

### 容器无法启动

```bash
docker logs xray-onekey
```

### 服务未运行

```bash
docker exec -it xray-onekey systemctl status xray
docker exec -it xray-onekey systemctl start xray
```

### 重新进入安装菜单

```bash
docker exec -it xray-onekey idleleo
```

### 完全重置

```bash
docker compose down
docker volume rm xray-conf xray-cert xray-info xray-logs acme-data
docker compose up -d
```
