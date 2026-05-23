# Xray One-Click Installation Script — Reality / VLESS WebSocket/gRPC/xHTTP+TLS + Nginx

[简体中文](/README.md) | English | [Français](/i18n/languages/fr/README.md) | [Русский](/i18n/languages/ru/README.md) | [فارسی](/i18n/languages/fa/README.md) | [한국어](/i18n/languages/ko/README.md)

[![GitHub stars](https://img.shields.io/github/stars/hello-yunshu/Xray_bash_onekey?color=%230885ce)](https://github.com/hello-yunshu/Xray_bash_onekey/stargazers) [![GitHub forks](https://img.shields.io/github/forks/hello-yunshu/Xray_bash_onekey?color=%230885ce)](https://github.com/hello-yunshu/Xray_bash_onekey/network) [![GitHub issues](https://img.shields.io/github/issues/hello-yunshu/Xray_bash_onekey)](https://github.com/hello-yunshu/Xray_bash_onekey/issues)

> Thanks for non-commercial open source development authorization by JetBrains

## Features

* Type `idleleo` to manage the script ([View the backstory of `idleleo`](https://github.com/hello-yunshu/Xray_bash_onekey/wiki/The-True-Face-Behind-the-Fog))
* Powered by Qwen-MT-Plus AI for accurate multilingual translation
* Supports Reality protocol with recommended Nginx frontend (installable via script)
* Supports WebSocket, gRPC, and xHTTP transport, with either a single transport or `ws+gRPC+xHTTP` enabled together
* Built-in fail2ban protection (installable via script)
* Built-in Xray traffic statistics, traffic blocking, GeoIP/GeoSite rule updates, and scheduled updates
* Supports automatic updates for the script, Xray, Nginx, and certificates, with full backup and restore
* Adopts the share link [proposal](https://github.com/XTLS/Xray-core/issues/91) by [@DuckSoft](https://github.com/DuckSoft) (beta), compatible with Qv2ray, V2rayN, V2rayNG
* Adopts the [XTLS](https://github.com/XTLS/Xray-core/issues/158) proposal, following the [UUIDv5](https://tools.ietf.org/html/rfc4122#section-4.3) standard, supporting custom string mapping to VLESS UUID
* Supports gRPC protocol: [Using gRPC Protocol](https://hey.run/archives/xrayjin-jie-wan-fa---shi-yong-grpcxie-yi)
* Supports Reality / ws/gRPC/xHTTP load balancing:
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
* For TLS mode: prepare a domain and add an A record
* Read the [Xray official documentation](https://xtls.github.io) to understand Reality, TLS, WebSocket, gRPC, and related Xray concepts
* **Ensure curl is installed**: CentOS users run `yum install -y curl`; Debian/Ubuntu users run `apt install -y curl`

## Quick Install

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/hello-yunshu/Xray_bash_onekey/main/install.sh)
```

## Installation Modes

| Mode | Description |
|------|-------------|
| Reality + Nginx | Recommended mode, with optional ws/gRPC/xHTTP auxiliary transports for load balancing |
| Nginx + TLS | Supports ws/gRPC/xHTTP and automatically issues and renews Let's Encrypt certificates |
| ws/gRPC/xHTTP ONLY | Standalone inbound mode without TLS, mainly for backend or load-balancing scenarios |
| XTLS ONLY | For traffic relay and other specific scenarios only |
| Docker | Image with Xray, Nginx, and the main script pre-installed |

When installing ws/gRPC/xHTTP-related modes, you can choose `ws`, `gRPC`, `xHTTP`, or `ws+gRPC+xHTTP`. The script generates the corresponding ports, paths, share links, and QR codes. Clash does not currently support xHTTP, and the script will note this in the generated configuration output.

## Common Commands

| Action | Command |
|--------|---------|
| Open management menu | `idleleo` |
| Show help | `idleleo --help` |
| Install Reality mode | `idleleo --install-reality` |
| Install TLS mode | `idleleo --install-tls` |
| Install ws/gRPC/xHTTP ONLY | `idleleo --install-none` |
| Show installation info | `idleleo --show` |
| Update script | `idleleo --update` |
| Update Xray | `idleleo --xray-update` |
| Update Nginx | `idleleo --nginx-update` |
| Configure Fail2ban | `idleleo --set-fail2ban` |
| Configure traffic blocking | `idleleo --traffic-blocker` |
| View real-time port traffic | `idleleo --port-traffic` |

## Docker Deployment

Docker deployment is supported. The image comes with Xray and Nginx pre-installed, and all original script features are available inside the container. See the [Docker Deployment Guide](/i18n/languages/en/DOCKER.md) for details.

```bash
git clone https://github.com/hello-yunshu/Xray_bash_onekey.git
cd Xray_bash_onekey
docker compose up -d
docker attach xray-onekey
```

## AI Skill Deployment

Supports automatic Xray deployment via AI tools (e.g., Trae) without manual interaction. See [Xray_bash_onekey_skill](https://github.com/hello-yunshu/Xray_bash_onekey_skill) for details.

The traditional approach requires SSH into the server, running the installation script, and answering interactive questions one by one; the Skill approach only needs you to tell the AI your requirements, and it automatically generates a non-interactive script, executes it, and returns the VLESS link directly.

**Supported modes**: Reality / TLS / ws ONLY / XTLS ONLY

**Usage**: In an AI tool that supports Skills, simply say "Help me set up Xray on my server", and the AI will automatically collect information, generate the script, execute the deployment, and return connection info.

## Important Notes

* If you are unfamiliar with the settings, use the default values for all non-required fields (just press Enter throughout)
* Cloudflare users should enable CDN only after installation is complete
* This script requires basic Linux knowledge and computer networking fundamentals
* Supports Debian 12+ / Ubuntu 24.04+ / CentOS Stream 10+; some CentOS templates may have compilation issues — consider switching to another OS if problems occur
* It is recommended to deploy only one proxy per server and use the default port 443
* Custom string mapping to UUIDv5 requires client-side support
* Use this script in a clean environment; beginners should avoid CentOS
* This program depends on Nginx — users who have installed Nginx via [LNMP](https://lnmp.org) or similar scripts should be aware of potential conflicts
* xHTTP share links are for clients that support xHTTP; Clash configuration output skips xHTTP
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
| Main directory | `/etc/idleleo` |
| Xray config | `/etc/idleleo/conf/xray/config.json` |
| Nginx config | `/etc/idleleo/conf/nginx/` |
| Install info | `/etc/idleleo/info/install_config.json` |
| Certificate files | `/etc/idleleo/cert/xray.key`, `/etc/idleleo/cert/xray.crt` |
| Log directories | `/etc/idleleo/logs/`, `/var/log/xray/` |
| Nginx directory | `/usr/local/nginx` |
| Management command | `/usr/bin/idleleo` |
