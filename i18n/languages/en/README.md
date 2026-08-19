# Xray Management Script — Reality / VLESS WebSocket/gRPC/xHTTP+TLS + Nginx

Simplified Chinese |[English](/i18n/languages/en/README.md) | [Français](/i18n/languages/fr/README.md) | [Русский](/i18n/languages/ru/README.md) | [فارسی](/i18n/languages/fa/README.md) | [한국어](/i18n/languages/ko/README.md)

[![GitHub stars](https://img.shields.io/github/stars/hello-yunshu/Xray_bash_onekey?color=%230885ce)](https://github.com/hello-yunshu/Xray_bash_onekey/stargazers) [![GitHub forks](https://img.shields.io/github/forks/hello-yunshu/Xray_bash_onekey?color=%230885ce)](https://github.com/hello-yunshu/Xray_bash_onekey/network) [![GitHub issues](https://img.shields.io/github/issues/hello-yunshu/Xray_bash_onekey)](https://github.com/hello-yunshu/Xray_bash_onekey/issues)

> Thanks for non-commercial open source development authorization by JetBrains

## Features

* enter`idleleo`Open the Xray management menu to manage installation, services, security settings, etc.
* Use Qwen-MT-Plus AI to achieve accurate translation in multiple languages
* Supports Reality protocol, it is recommended to use Nginx prefix (can be installed in the script)
* Supports WebSocket, gRPC, xHTTP transmission, you can choose single transmission or`ws+gRPC+xHTTP`Enable both
* Supports IPv4 / IPv6 dual stack: can automatically detect public network export capabilities during installation, record independent verification based on domain name A/AAAA and generate corresponding sharing links and Clash configurations
* Built-in fail2ban protection (installable within script)
* Built-in Xray traffic statistics, traffic blocking, GeoIP/GeoSite rule update and regular update
* Supports scripts, Xray, Nginx and certificate updates, and provides backup and failure rollback for critical updates
* The current running configuration will be automatically backed up before reinstallation and mode switching, and the original configuration will be restored in case of failure.
* Reconfiguration provides three safe paths: configuration-preserving redeployment, standard template reconstruction, and mode switching.
* use[@DuckSoft](https://github.com/DuckSoft)'s sharing link[提案](https://github.com/XTLS/Xray-core/issues/91)(beta), compatible with Qv2ray, V2rayN, V2rayNG
* use[XTLS](https://github.com/XTLS/Xray-core/issues/158)proposal, follow[UUIDv5](https://tools.ietf.org/html/rfc4122#section-4.3)Standard, supports custom string mapping to VLESS UUID
* Supports gRPC protocol:[使用 gRPC 协议](https://hey.run/posts/xrayjin-jie-wan-fa---shi-yong-grpcxie-yi)
* Supports Reality / ws/gRPC/xHTTP load balancing:
  - [部署 Reality 负载均衡](https://hey.run/posts/bushu-reality-balance)
  - [搭建后端负载均衡](https://hey.run/posts/xrayjin-jie-wan-fa---da-jian-hou-duan-fu-wu-qi-fu-zai-jun-heng)
* Reality + Nginx mode is enabled by default. SNI Guard: unknown SNI, empty SNI and exception TLS will not enter the Xray Reality backend. The isolation strategy (ssl_reject_handshake) is adopted by default. Advanced users can switch to self-built decoy site fallback or directly TCP Denied. This function is used to reduce active detection and misconfiguration exposure, and does not pursue perfect camouflage.

## Further reading

* `idleleo`Naming backstory:[迷雾后的真容](https://github.com/hello-yunshu/Xray_bash_onekey/wiki/%E8%BF%B7%E9%9B%9C%E5%90%8E%E7%9A%84%E7%9C%9F%E5%AE%B9)
* Reality Installation Guide:[搭建 Xray Reality 服务器](https://hey.run/posts/da-jian-xray-reality-xie-yi-fu-wu-qi)
* Reality Protocol Risk:[Xray Reality 协议的风险](https://hey.run/posts/reality-xie-yi-de-feng-xian)
* Reality Accelerated server:[利用 Reality 协议"漏洞"加速服务器](https://hey.run/posts/use-reality)

## Telegram group

* Communication group:[点击加入](https://t.me/+48VSqv7xIIFmZDZl)

## Preparation

* An overseas server with public network IP
* Install Reality protocol: You need to prepare a target domain name that meets the requirements of Xray
* Install TLS version: You need to prepare the domain name and correctly configure A and/or AAAA records according to the available network of the server; for dual-stack environments, it is recommended to configure the correct A and AAAA at the same time. The script supports automatic detection of IPv4/IPv6 network capabilities. When dual stack is available, the corresponding client entry can be generated at the same time.
* read[Xray 官方文档](https://xtls.github.io), understand Reality, TLS, WebSocket, gRPC and Xray related concepts
* **Make sure curl is installed: CentOS user execution`yum install -y curl`;Debian/Ubuntu User execution`apt install -y curl`

## Quick installation

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/hello-yunshu/Xray_bash_onekey/main/install.sh)
```

## Installation mode

| model | illustrate |
|------|------|
| Reality + Nginx | Recommended mode, you can attach ws/gRPC/xHTTP simple protocol as needed for load balancing |
| Nginx + TLS | Support ws/gRPC/xHTTP, automatically apply for and renew Let's Encrypt certificate |
| ws/gRPC/xHTTP ONLY | Independent inbound mode without TLS, mainly used in backend or load balancing scenarios |
| XTLS ONLY | Only used in specific scenarios such as traffic transfer |
| Docker | Xray, Nginx and the main script are pre-installed in the image |

Optional when installing ws/gRPC/xHTTP related modes`ws`、`gRPC`、`xHTTP`or`ws+gRPC+xHTTP`. The script will generate the corresponding port, path, sharing link and QR code respectively; Clash currently does not support xHTTP, and the script will prompt in the configuration output.

## Reconfiguration instructions

When the installed environment is installed again, the script will automatically back up the current running configuration and provide three reconfiguration paths:

| path | illustrate | limit |
|------|------|------|
| Preserve configuration redeployment | Keep custom routing/outbounds/DNS and multi-user configuration, modify only user-selected fields (ports, paths, UUID, Reality parameters, etc.) | Transmission structure changes (such as ws → gRPC) are not supported. If you need to change the transmission combination, please use the standard template to rebuild it. |
| Standard template reconstruction | Generate standard template configuration using current reusable parameters, custom routing/outbounds/DNS may be removed | It is not mandatory that the number of users remains unchanged |
| Mode switch | Switch to a different protocol mode (such as Reality → TLS). By default, only the main user UUID/email is reused. | Other users will not be automatically migrated and will be clearly prompted before switching. |

If any step in the reconfiguration process fails (configuration writing, service startup, health check, etc.), it will automatically roll back to the original backup configuration. The backup directory uses a unique timestamp to support multiple consecutive reconfigurations without conflicting with each other.

## Common commands

| operate | Order |
|------|------|
| Open the admin menu | `idleleo` |
| View help | `idleleo --help` |
| Install Reality mode | `idleleo --install-reality` |
| Install TLS mode | `idleleo --install-tls` |
| Install ws/gRPC/xHTTP ONLY | `idleleo --install-none` |
| View installation information | `idleleo --show` |
| update script | `idleleo --update` |
| Update Xray | `idleleo --xray-update` |
| Update Nginx | `idleleo --nginx-update` |
| Set Fail2ban | `idleleo --set-fail2ban` |
| Set up traffic blocking | `idleleo --traffic-blocker` |
| View real-time port traffic | `idleleo --port-traffic` |

## RillML Xray AI Operation and maintenance assistant

RillML (Rill) provides Xray with local adaptive intelligent operations and maintenance capabilities.

The built-in local AI operation and maintenance assistant monitors the health status of Xray/Nginx in real time, automatically diagnoses faults and gives treatment suggestions, without the need for external API. Main menu input`9`or execute`idleleo --rill-agent`Enter.

**Core Competencies**

* Monitoring: Real-time observation of Xray/Nginx service and configuration status
* Diagnosis: Locate the root cause of the fault, with confidence recommendations (high/medium/low/insufficient evidence)
* Judgment: Automatically determine the fault type and give processing suggestions. The instructions clearly indicate that automatic processing is allowed or only suggestions are provided.
* Mode: Intelligent judgment / observation only / safe deactivation, the system will not be changed until automatic modification is turned on

**Commonly used commands**

| operate | Order |
|------|------|
| Open the AI operation and maintenance assistant menu | `idleleo --rill-agent` |
| Install or repair the AI judgment engine | `idleleo --rill-agent-install` |
| Check the AI judgment status | `idleleo --rill-agent-status` |
| Run AI troubleshooting | `idleleo --rill-agent-diagnose` |
| Verification AI judgment engine | `idleleo --rill-agent-verify` |
| Security deactivation AI judgment | `idleleo --rill-agent-safe-disable` |
| Uninstall Rill AI engine | `idleleo --rill-agent-uninstall` |

AI The judgment engine is still in the testing stage. It is recommended to focus on diagnostic suggestions. The system will not be automatically modified by default.

## Docker Deployment

Supports deployment using Docker, the image is pre-installed with Xray and Nginx, and all functions of the original script can be used directly in the container. See details[Docker 部署指南](/docker/DOCKER.md)。

```bash
git clone https://github.com/hello-yunshu/Xray_bash_onekey.git
cd Xray_bash_onekey
docker compose up -d
docker attach xray-onekey
```

## AI Skill Deployment

Supports automatic deployment of Xray via AI tools such as Trae without manual interaction. See details[Xray_bash_onekey_skill](https://github.com/hello-yunshu/Xray_bash_onekey_skill)。

The traditional method requires SSH to go to the server, run the installation script, and answer interactive questions one by one; the Skill method only needs to tell AI your needs, and AI will automatically generate a non-interactive script and execute it, directly returning the VLESS link.

**Supported modes**: Reality / TLS / ws ONLY / XTLS ONLY

**How ​​to use**: Directly say "Help me build Xray on the server" in the AI tool that supports Skill, and AI will automatically collect information, generate scripts, perform deployment and return connection information.

## Things to note

* If you don’t understand the meaning of each setting, please use the default value except for required fields (just press Enter)
* Cloudflare Users please open CDN after installation is complete.
* This script requires basic knowledge of Linux and computer network knowledge
* Supports Debian 12+ / Ubuntu 24.04+ / CentOS Stream 10+, some CentOS templates may have compilation problems, it is recommended to change the system when encountering problems
* It is recommended that a single server deploy only a single agent and use the default port 443
* Custom string mapping to UUIDv5 requires client support
* It is recommended to use it in a pure environment; novices should not use CentOS
* This program depends on Nginx, passed[LNMP](https://lnmp.org)Users who have installed the script Nginx please be aware of potential conflicts.
* xHTTP shared link is for clients that support xHTTP; Clash configuration output will skip xHTTP
* Do not use this script in a production environment without first verifying availability
* Author: Yun Shu, providing limited support only

## Acknowledgments

* based on[wulabing/V2Ray_ws-tls_bash_onekey](https://github.com/wulabing/V2Ray_ws-tls_bash_onekey)develop
* TCP acceleration script quoted from[ylx2016/Linux-NetSpeed](https://github.com/ylx2016/Linux-NetSpeed)

## Certificate configuration

**Custom certificate**: Name the crt and key files respectively.`xray.crt`and`xray.key`, put in`/etc/idleleo/cert`Directory (if the directory does not exist, create it first). Please pay attention to the certificate authority and validity period. After the custom certificate expires, you need to renew it yourself.

**Automatic certificate**: The script supports automatically generating Let's Encrypt certificates (valid for 3 months), and theoretically supports automatic renewal.

## View client configuration

```bash
cat /etc/idleleo/info/xray_info.inf
```

## Xray Introduction

* Xray is an excellent open source network proxy tool that supports Windows, macOS, Android, iOS, Linux and other full platforms
* This script is a one-click complete configuration script. After all processes are completed normally, the client can be used according to the output results.
* **STRONGLY RECOMMENDED** A comprehensive understanding of the program’s workflow and principles

## Service management

| operate | Order |
|------|------|
| Start Xray | `systemctl start xray` |
| Stop Xray | `systemctl stop xray` |
| Start Nginx | `systemctl start nginx` |
| Stop Nginx | `systemctl stop nginx` |

## Related catalog

| content | path |
|------|------|
| Home directory | `/etc/idleleo` |
| Xray configuration | `/etc/idleleo/conf/xray/config.json` |
| Nginx configuration | `/etc/idleleo/conf/nginx/` |
| Installation information | `/etc/idleleo/conf/install_config.json` |
| certificate file | `/etc/idleleo/cert/xray.key`、`/etc/idleleo/cert/xray.crt` |
| Log directory | `/etc/idleleo/logs/`、`/var/log/xray/` |
| Nginx installation directory | `/usr/local/nginx` |
| Administrative commands | `/usr/bin/idleleo` |
