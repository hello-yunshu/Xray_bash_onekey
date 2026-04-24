# Docker 部署指南

简体中文 | [English](/languages/en/DOCKER.md) | [Français](/languages/fr/DOCKER.md) | [Русский](/languages/ru/DOCKER.md) | [فارسی](/languages/fa/DOCKER.md) | [한국어](/languages/ko/DOCKER.md)

本文档介绍如何使用 Docker 运行 Xray 一键脚本。镜像预装了 Xray 和 Nginx，容器内可直接使用原脚本的所有功能。

## 快速启动

### 1. 克隆仓库并构建

```bash
git clone https://github.com/hello-yunshu/Xray_bash_onekey.git
cd Xray_bash_onekey
docker compose up -d
```

### 2. 进入交互式安装菜单

```bash
docker attach xray-onekey
```

首次运行会自动启动安装脚本，按照提示完成配置即可。退出菜单后容器自动进入守护模式。

### 3. 后续管理

```bash
docker exec -it xray-onekey idleleo
```

## 运行模式

| 模式 | 说明 | 命令 |
|------|------|------|
| `idleleo`（默认） | 启动服务并进入管理菜单 | `docker compose up -d` + `docker attach xray-onekey` |
| `start` | 仅启动服务（守护模式） | 修改 `docker-compose.yml` 中 `command: start` |
| `shell` | 启动服务并进入 Shell | `docker exec -it xray-onekey bash` |

## 管理操作

所有原脚本命令均可使用：

```bash
docker exec -it xray-onekey idleleo          # 管理菜单
docker exec -it xray-onekey idleleo -s        # 查看安装信息
docker exec -it xray-onekey idleleo -x        # 更新 Xray
docker exec -it xray-onekey idleleo -n        # 更新 Nginx
docker exec -it xray-onekey idleleo -h        # 查看帮助
```

## 使用 docker run

```bash
docker build -t xray-onekey .

docker run -d --name xray-onekey   --network host   --cap-add NET_ADMIN   -e TZ=Asia/Shanghai   -v xray-conf:/etc/idleleo/conf   -v xray-cert:/etc/idleleo/cert   -v xray-info:/etc/idleleo/info   -v xray-logs:/var/log/xray   -v acme-data:/root/.acme.sh   -it xray-onekey
```

## 数据持久化

| Volume | 容器路径 | 说明 |
|--------|---------|------|
| `xray-conf` | `/etc/idleleo/conf` | Xray 和 Nginx 配置文件 |
| `xray-cert` | `/etc/idleleo/cert` | SSL 证书文件 |
| `xray-info` | `/etc/idleleo/info` | 连接信息和状态文件 |
| `xray-logs` | `/var/log/xray` | Xray 日志文件 |
| `acme-data` | `/root/.acme.sh` | acme.sh 证书签发数据 |

## 网络配置

容器使用 `network_mode: host`，直接使用宿主机网络：

* Reality 模式需要看到真实客户端 IP
* TLS 模式需要直接绑定 443/80 端口
* 避免额外的 NAT 转发性能损耗

## 注意事项

* 容器内使用 `fake-systemctl` 替代 systemd，`systemctl` 命令可正常使用
* 内置看门狗每 30 秒检查服务状态，异常时自动重启
* 退出管理菜单后容器自动进入守护模式，服务不会中断
* 防火墙建议在宿主机层面管理
* 证书自动续签在容器内可正常工作（需确保 80 端口可访问）

## 故障排查

```bash
docker logs xray-onekey                    # 查看容器日志
docker exec -it xray-onekey bash           # 进入容器
docker exec -it xray-onekey idleleo -s     # 查看安装信息
```

### 完全重置

```bash
docker compose down
docker volume rm xray-conf xray-cert xray-info xray-logs acme-data
docker compose up -d
```
