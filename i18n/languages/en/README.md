# Xray management script — Reality / VLESS WebSocket/gRPC/xHTTP+TLS + Nginx

Current version: **3.3.1**

Simplified Chinese |[English](/i18n/languages/en/README.md) | [Français](/i18n/languages/fr/README.md) | [Русский](/i18n/languages/ru/README.md) | [فارسی](/i18n/languages/fa/README.md) | [한국어](/i18n/languages/ko/README.md)

[![GitHub stars](https://img.shields.io/github/stars/hello-yunshu/Xray_bash_onekey?color=%230885ce)](https://github.com/hello-yunshu/Xray_bash_onekey/stargazers) [![GitHub forks](https://img.shields.io/github/forks/hello-yunshu/Xray_bash_onekey?color=%230885ce)](https://github.com/hello-yunshu/Xray_bash_onekey/network) [![GitHub issues](https://img.shields.io/github/issues/hello-yunshu/Xray_bash_onekey)](https://github.com/hello-yunshu/Xray_bash_onekey/issues)

> Thanks for non-commercial open source development authorization by JetBrains

## Functional Features

* Input`idleleo`Open the Xray management menu to manage installations, services, security settings, etc.
* It uses Qwen-MT-Plus AI to achieve precise multilingual translation.
* Supports the Reality protocol; it is recommended to use it with an Nginx frontend (which can be installed within the script).
* Supports WebSocket , gRPC , and xHTTP transport, with options for single transport or`ws+gRPC+xHTTP`Enable simultaneously
* Supports dual-stack IPv4 / IPv6: During installation, it can automatically detect the public network egress capability, perform independent verification for each domain name via A/AAAA, and generate corresponding share links and Clash configurations.
* Built-in fail2ban protection (can be installed within the script)
* Built-in Xray traffic statistics, traffic blocking, GeoIP/GeoSite rule updates, and scheduled updates.
* Supports scripts, Xray, Nginx, and certificate updates, and provides backups and rollback in case of critical updates.
* Before reinstallation and mode switching, the current running configuration will be automatically backed up, and in case of failure, the original configuration will be restored.
* Reconfiguration provides three secure paths: re-deployment with the original configuration, reconstruction using a standard template, and mode switching.
* Adopted[@DuckSoft](https://github.com/DuckSoft)The sharing link[Proposal](https://github.com/XTLS/Xray-core/issues/91)(beta), compatible with Qv2ray, V2rayN, V2rayNG
* Adopted[XTLS](https://github.com/XTLS/Xray-core/issues/158)Proposal, follow[UUIDv5](https://tools.ietf.org/html/rfc4122#section-4.3)Standard, supports mapping custom strings to VLESS UUID
* Supports the gRPC protocol:[Using the gRPC protocol](https://hey.run/posts/xrayjin-jie-wan-fa---shi-yong-grpcxie-yi)
* Supports Reality / ws/gRPC/xHTTP load balancing:
  - [Deploy Reality load balancing](https://hey.run/posts/bushu-reality-balance)
  - [Set up backend load balancing](https://hey.run/posts/xrayjin-jie-wan-fa---da-jian-hou-duan-fu-wu-qi-fu-zai-jun-heng)
* Reality + Nginx mode enables SNI Guard by default: unknown SNI, empty SNI, and abnormal TLS will not be routed to the Xray Reality backend; the default isolation policy (ssl_reject_handshake) is used. Advanced users can switch to a custom decoy site fallback or directly reject TCP connections. This feature is designed to reduce active probing and exposure due to misconfigurations and does not aim for perfect camouflage.

## Further reading

* `idleleo`Naming background story:[The true face behind the mist](https://github.com/hello-yunshu/Xray_bash_onekey/wiki/%E8%BF%B7%E9%9B%9C%E5%90%8E%E7%9A%84%E7%9C%9F%E5%AE%B9)
* Reality Installation Guide:[Build a Xray Reality server](https://hey.run/posts/da-jian-xray-reality-xie-yi-fu-wu-qi)
* Reality Protocol Risk:[Xray Reality The risks of the agreement in the REALITY](https://hey.run/posts/reality-xie-yi-de-feng-xian)
* Reality Accelerated server:[Exploiting the "vulnerability" of the Reality protocol to accelerate the server.](https://hey.run/posts/use-reality)

## Telegram group

* Communication group:[Click to join](https://t.me/+48VSqv7xIIFmZDZl)

## Preparatory work

* A foreign server with a public IP
* Install the Reality protocol: You need to prepare a target domain name that meets the requirements of Xray.
* Install the TLS version: You need to prepare a domain name and correctly configure the A and/or AAAA records based on the server's available network; in a dual-stack environment, it is recommended to also configure the correct A and AAAA. The script supports automatic detection of IPv4/IPv6 network capabilities and can generate corresponding client entry points simultaneously when dual-stack is available.
* Reading[Xray official documentation](https://xtls.github.io), understand the concepts related to Reality, TLS, WebSocket, gRPC, and Xray
* **Ensure curl is installed**: CentOS users execute`yum install -y curl`;Debian/Ubuntu user executes`apt install -y curl`

## Quick installation

```bash
bash <(curl -fsSL https://github.com/hello-yunshu/Xray_bash_onekey/releases/latest/download/install.sh)
```

## Installation mode

| Mode | Description |
|------|------|
| Reality + Nginx | Recommended mode, which can optionally include the ws/gRPC/xHTTP simple protocol for load balancing. |
| Nginx + TLS | Supports ws/gRPC/xHTTP, automatically applies for and renews Let's Encrypt certificates. |
| ws/gRPC/xHTTP ONLY | Independent inbound mode without TLS, primarily used in backend or load balancing scenarios. |
| Transit node | Independent server role, used only for single-target Nginx Stream forwarding with TCP, and does not install Xray. |
| Docker | The image comes pre-installed with Xray, Nginx, and the main script. |

When installing the ws/gRPC/xHTTP-related mode, you can choose.`ws`, `gRPC`, `xHTTP`Or`ws+gRPC+xHTTP`The script will generate the corresponding port, path, share link, and QR code; Clash currently does not support xHTTP, and the script will display a prompt in the configuration output.

## Reconfiguration Instructions

When the script is run again in an already installed environment, it will automatically back up the current running configuration and provide three reconfiguration options:

| Path | Description | Restriction |
|------|------|------|
| Retain configuration and redeploy | Retain custom routing/outbounds/DNS and multi-user configurations, modifying only the fields selected by the user (such as port, path, UUID, Reality parameters, etc.). | Structure changes during transmission are not supported (e.g., ws → gRPC). To modify the transmission configuration, please recreate it using the standard template. |
| Standard template reconstruction | Use the current reusable parameters to generate a standard template configuration; the custom routing/outbounds/DNS may be removed. | It does not require the number of users to remain unchanged. |
| Mode switching | Switch to a different protocol mode (e.g., Reality → TLS), by default only reusing the primary user UUID/email | Other users will not be automatically migrated; a clear prompt will appear before the switch. |

Any failure during the reconfiguration process—such as configuration write, service startup, or health checks—will automatically trigger a rollback to the backed-up original configuration. The backup directory uses a unique timestamp, enabling multiple consecutive reconfigurations without conflicts.

## Common commands

| Operation | Command |
|------|------|
| Open the management menu | `idleleo` |
| View Help | `idleleo --help` |
| Install Reality mode in REALITY. | `idleleo --install-reality` |
| Install TLS mode | `idleleo --install-tls` |
| Install ws/gRPC/xHTTP ONLY | `idleleo --install-none` |
| Installing the transit node | `idleleo --install-relay` |
| Uninstall script and Xray/Nginx | `idleleo --purge` |
| View installation information | `idleleo --show` |
| Update script | `idleleo --update` |
| Update Xray | `idleleo --xray-update` |
| Update Nginx | `idleleo --nginx-update` |
| Set Fail2ban | `idleleo --set-fail2ban` |
| Set traffic blocking | `idleleo --traffic-blocker` |
| View real-time port traffic | `idleleo --port-traffic` |

## Upgrade Instructions

### 3.2.9 / 3.2.10 / 3.2.11 → 3.3.x

Automatic updates for the old Shell will not carry over to minor;`idleleo --update auto_update`Will explicitly skip and retain.
Old version, and it will not report success silently. Please use the interactive two-step upgrade:

```bash
bash /etc/idleleo/install.sh --update          # 交互终端，选择 Y
bash /etc/idleleo/install.sh --xray-update     # 再更新 Xray
```

The automated environment must be explicitly confirmed:

```bash
bash /etc/idleleo/install.sh --update --yes                  # 同一 minor
bash /etc/idleleo/install.sh --update --yes --allow-major    # 跨 minor
```

`--yes`Only updates within the same minor are automatically confirmed; for updates across minor, explicit addition is still required.`--allow-major`.
`--allow-major`Only removes the cross-minor restriction; it does not replace Y/N confirmation (non-interactive scenarios still require it).
At the same time, give`--yes`). It is recommended to run this first before upgrading.`idleleo --backup`3.3.1 Permissions for the backup file
For 0600.

### 3.3.0 → 3.3.1

Update in the management menu “Update Wizard → Update Script”, or execute:

```bash
bash /etc/idleleo/install.sh --update
```

3.3.1 Fixed offline uninstallation remnants, backup/log permissions, the missing Xray, and failed identity records installer.
Shell metadata rollback protection. The upgrade will not modify existing Xray configurations; REALITY`minClientVer`Replenish as before.
Rule execution for version 3.3.0.

3.3.1 Releasing a new version will keep the version number unchanged. Nodes that have already installed the old 3.3.1 will not be updated through this.`-u`Automatically obtain the new installer.
(The same version is considered to be the latest);`-x`Only update the Xray core; do not update the Shell script. When new packages are needed,
Please reinstall or manually overwrite.`/etc/idleleo/install.sh`.

### Old version of XTLS mode

Starting from version 3.3.0, the legacy XTLS mode has been removed. Existing XTLS services can still run after upgrading, but they cannot be reinstalled via script or otherwise.
Switch modes; when you need to continue managing, please back up and uninstall first, then redeploy the Reality/TLS/ relay mode.

### Automatic update

Automatic updates only automatically upgrade Shell within the same minor; for cross-minor, you need to manually perform the two steps mentioned above. Xray and
Automatic updates for Nginx are still performed based on API metadata; the failure log contains`component`, `version`, `installer_ref`, `installer_sha`and`failed_at`Fields (representing the component, target version, installer reference, installer hash, and failure time, respectively).

## RillML Xray AI Operations Assistant

RillML (short for Rill) provides on-premises adaptive intelligent operations and maintenance capabilities for Xray.

Built-in local AI operations and maintenance assistant, real-time monitoring of Xray/Nginx health status, automatic fault diagnosis and providing handling suggestions, no external API required. Enter in the main menu.`9`Or execute`idleleo --rill-agent`Enter.

**Core Competencies**

* Monitoring: Real-time observation of the Xray/Nginx service and configuration status.
* Diagnosis: Identify the root cause of the fault, with a confidence level recommendation (High / Medium / Low / Insufficient Evidence).
* Diagnosis: Automatically identifies the fault type and provides troubleshooting recommendations, with clear indications in the description specifying whether automatic resolution is permitted or if only suggestions are provided.
* Mode: Intelligent Judgment / Observe Only / Safety Disable. The system will not be modified before automatic adjustment is enabled.

**Common Commands**

| Operation | Command |
|------|------|
| Open the AI Operations Assistant menu | `idleleo --rill-agent` |
| Install or repair the AI judgment engine | `idleleo --rill-agent-install` |
| View AI judgment status | `idleleo --rill-agent-status` |
| Run AI fault diagnosis | `idleleo --rill-agent-diagnose` |
| Validate the AI judgment engine | `idleleo --rill-agent-verify` |
| Safe Deactivation of AI Judgment | `idleleo --rill-agent-safe-disable` |
| Uninstall the Rill AI engine. | `idleleo --rill-agent-uninstall` |

The AI judgment engine is currently still in the testing phase; it is recommended to rely primarily on diagnostic recommendations, and by default, it will not automatically modify the system.

## Deploy Docker

Supports deployment using Docker; the image comes pre-installed with Xray and Nginx, allowing you to use all the original script’s features directly within the container. See details here.[Docker Deployment Guide](/docker/DOCKER.md).

```bash
git clone https://github.com/hello-yunshu/Xray_bash_onekey.git
cd Xray_bash_onekey
docker compose up -d
docker attach xray-onekey
```

## AI Skill deployment

Supports automatic deployment of Xray via AI tools (such as Trae), without manual interaction. See details.[Xray_bash_onekey_skill](https://github.com/hello-yunshu/Xray_bash_onekey_skill).

The traditional method requires SSH to the server, running the installation script, and answering interactive questions one by one; the Skill method only requires you to tell the AI your requirements, and the AI will automatically generate a non-interactive script and execute it, directly returning the VLESS link.

**Supported modes**: Reality / TLS / ws ONLY / transit node

**How to use**: In an AI tool that supports Skill, simply say "Help me set up Xray on the server," and the AI will automatically gather information, generate a script, execute the deployment, and return the connection details.

## Important Notes

* When you are unsure of the meaning of each setting, please use the default values for all non-required fields (simply press Enter throughout).
* Cloudflare users, please enable CDN after the installation is complete.
* This script requires basic knowledge of Linux and general computer networking concepts.
* Supports Debian 12+ / Ubuntu 24.04+ / CentOS Stream 10+, some CentOS templates may have compilation issues; it is recommended to switch systems if you encounter problems.
* It is recommended to deploy only one agent per server, using the default port 443.
* Mapping a custom string to UUIDv5 requires client support.
* It is recommended to use in a clean environment; beginners should not use CentOS.
* This program depends on Nginx, which has been passed.[LNMP](https://lnmp.org)Please note potential conflicts for users who have already installed the script via Nginx.
* xHTTP share links are suitable for clients that support xHTTP; Clash configuration output will skip xHTTP.
* Do not use this script in a production environment before verifying its availability.
* Author: Yun Shu, limited support only.

## Acknowledgments

* Based on[wulabing/V2Ray_ws-tls_bash_onekey](https://github.com/wulabing/V2Ray_ws-tls_bash_onekey)Development
* TCP The acceleration script is referenced from[ylx2016/Linux-NetSpeed](https://github.com/ylx2016/Linux-NetSpeed)

## Certificate configuration

**Custom Certificate**: Rename the crt and key files to`xray.crt`and`xray.key`, put in`/etc/idleleo/cert`Directory (create it first if it does not exist). Please pay attention to the certificate permissions and validity period; you will need to renew custom certificates yourself once they expire.

**Automatic Certificate**: The script supports automatically generating a Let's Encrypt certificate (valid for 3 months) and, in theory, supports automatic renewal.

## View client configuration

```bash
cat /etc/idleleo/info/xray_info.inf
```

## Xray Introduction

* Xray is an excellent open-source network proxy tool that supports all platforms, including Windows, macOS, Android, iOS, and Linux.
* This script is a one-click full configuration script. After all processes complete successfully, configure the client according to the output results to start using it.
* **Strongly recommended** to gain a comprehensive understanding of the program's workflow and principles.

## Service Management

| Operation | Command |
|------|------|
| Start Xray | `systemctl start xray` |
| Stop Xray | `systemctl stop xray` |
| Start Nginx | `systemctl start nginx` |
| Stop Nginx | `systemctl stop nginx` |

## Related directory

| Content | Path |
|------|------|
| Home directory | `/etc/idleleo` |
| Xray Configuration | `/etc/idleleo/conf/xray/config.json` |
| Nginx Configuration | `/etc/idleleo/conf/nginx/` |
| Installation Information | `/etc/idleleo/conf/install_config.json` |
| Certificate file | `/etc/idleleo/cert/xray.key`, `/etc/idleleo/cert/xray.crt` |
| Log directory | `/etc/idleleo/logs/`, `/var/log/xray/` |
| Nginx installation directory | `/usr/local/nginx` |
| Management commands | `/usr/bin/idleleo` |

Probe testing: Verifying the new terminology and quality gate links.
