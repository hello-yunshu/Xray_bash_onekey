# Xray One-Click Installation Script — Reality / VLESS WebSocket/gRPC+TLS + Nginx

[简体中文](/README.md) | English | [Français](/languages/fr/README.md) | [Русский](/languages/ru/README.md) | [فارسی](/languages/fa/README.md) | [한국어](/languages/ko/README.md)

[![GitHub stars](https://img.shields.io/github/stars/hello-yunshu/Xray_bash_onekey?color=%230885ce)](https://github.com/hello-yunshu/Xray_bash_onekey/stargazers) [![GitHub forks](https://img.shields.io/github/forks/hello-yunshu/Xray_bash_onekey?color=%230885ce)](https://github.com/hello-yunshu/Xray_bash_onekey/network) [![GitHub issues](https://img.shields.io/github/issues/hello-yunshu/Xray_bash_onekey)](https://github.com/hello-yunshu/Xray_bash_onekey/issues)

> Thanks for non-commercial open source development authorization by JetBrains

## Features

* Type `idleleo` to manage the script ([View the backstory of `idleleo`](https://github.com/hello-yunshu/Xray_bash_onekey/wiki/The-True-Face-Behind-the-Fog))
* Powered by Qwen-MT-Plus AI for accurate multilingual translation
* Supports Reality protocol with recommended Nginx frontend (installable via script)
* Built-in fail2ban protection (installable via script)
* Adopts the share link [proposal](https://github.com/XTLS/Xray-core/issues/91) by [@DuckSoft](https://github.com/DuckSoft) (beta), compatible with Qv2ray, V2rayN, V2rayNG
* Adopts the [XTLS](https://github.com/XTLS/Xray-core/issues/158) proposal, following the [UUIDv5](https://tools.ietf.org/html/rfc4122#section-4.3) standard, supporting custom string mapping to VLESS UUID
* Supports gRPC protocol: [Using gRPC Protocol](https://hey.run/archives/xrayjin-jie-wan-fa---shi-yong-grpcxie-yi)
* Supports Reality / ws/gRPC load balancing:
  - [Deploy Reality Load Balancer](https://hey.run/archives/bushu-reality-balance)
  - [Build Backend Load Balancer](https://hey.run/archives/xrayjin-jie-wan-fa---da-jian-hou-duan-fu-wu-qi-fu-zai-jun-heng)

## Further Reading

* Reality installation guide: [Setting Up Xray Reality Server](https://hey.run/archives/da-jian-xray-reality-xie-yi-fu-wu-qi)
* Reality protocol risks: [Risks of Xray Reality Protocol](https://hey.run/archives/reality-xie-yi-de-feng-xian)
* Accelerating server with Reality: [Accelerate Server Using Reality Protocol "Vulnerability"](https://hey.run/archives/use-reality)

## Telegram Group

* Discussion group: [Click to join](https://t.me/+48VSqv7xIIFmZDZl)

## Prerequisites

* An overseas server with a public IP address
* For Reality protocol: prepare a target domain that meets Xray's requirements
* For TLS version: prepare a domain and add an A record
* Read the [Xray official documentation](https://xtls.github.io) to understand Reality, TLS, WebSocket, gRPC, and related Xray concepts
* **Ensure curl is installed**: CentOS users run `yum install -y curl`; Debian/Ubuntu users run `apt install -y curl`

## Quick Install

```bash
bash <(curl -Ss https://raw.githubusercontent.com/hello-yunshu/Xray_bash_onekey/main/install.sh)
```

## Docker Deployment

Docker deployment is supported. The image comes with Xray and Nginx pre-installed, and all original script features are available inside the container. See the [Docker Deployment Guide](/languages/en/DOCKER.md) for details.

```bash
git clone https://github.com/hello-yunshu/Xray_bash_onekey.git
cd Xray_bash_onekey
docker compose up -d
docker attach xray-onekey
```

## Important Notes

* If you are unfamiliar with the settings, use the default values for all non-required fields (just press Enter throughout)
* Cloudflare users should enable CDN only after installation is complete
* This script requires basic Linux knowledge and computer networking fundamentals
* Supports Debian 12+ / Ubuntu 24.04+ / CentOS Stream 8+; some CentOS templates may have compilation issues — consider switching to another OS if problems occur
* It is recommended to deploy only one proxy per server and use the default port 443
* Custom string mapping to UUIDv5 requires client-side support
* Use this script in a clean environment; beginners should avoid CentOS
* This program depends on Nginx — users who have installed Nginx via [LNMP](https://lnmp.org) or similar scripts should be aware of potential conflicts
* Do not use this script in production environments before verifying its functionality
* The author provides limited support (because they're not very smart)

## Acknowledgments

* Based on [wulabing/V2Ray_ws-tls_bash_onekey](https://github.com/wulabing/V2Ray_ws-tls_bash_onekey)
* TCP acceleration script from [ylx2016/Linux-NetSpeed](https://github.com/ylx2016/Linux-NetSpeed)

## Certificate Configuration

**Custom Certificate**: Rename your crt and key files to `xray.crt` and `xray.key`, then place them in the `/etc/idleleo/cert` directory (create it if it doesn't exist). Note the certificate permissions and validity period — custom certificates must be renewed manually after expiration.

**Auto Certificate**: The script supports automatic Let's Encrypt certificate generation (valid for 3 months), with theoretical support for auto-renewal.

## View Client Configuration

```bash
cat /etc/idleleo/info/xray_info.inf
```

## About Xray

* Xray is an excellent open-source network proxy tool supporting Windows, macOS, Android, iOS, Linux, and more
* This script provides one-click complete configuration — once all processes finish successfully, simply configure your client using the output
* **Strongly recommended** to fully understand the program's workflow and principles

## Service Management

| Action | Command |
|--------|---------|
| Start Xray | `systemctl start xray` |
| Stop Xray | `systemctl stop xray` |
| Start Nginx | `systemctl start nginx` |
| Stop Nginx | `systemctl stop nginx` |

## Directories

| Item | Path |
|------|------|
| Xray server config | `/etc/idleleo/conf/xray/config.json` |
| Nginx directory | `/usr/local/nginx` |
| Certificate files | `/etc/idleleo/cert/xray.key`, `/etc/idleleo/cert/xray.crt` |
| Config info etc. | `/etc/idleleo` |
