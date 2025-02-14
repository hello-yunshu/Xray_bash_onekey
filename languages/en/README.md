# Xray supports Reality / VLESS WebSocket/gRPC+TLS protocol + Nginx one-click installation script

[简体中文](/README.md) | English | [Русский](/languages/ru/README.md) | [فارسی](/languages/fa/README.md) | [한국어](/languages/ko/README.md)

[![GitHub stars](https://img.shields.io/github/stars/hello-yunshu/Xray_bash_onekey?color=%230885ce)](https://github.com/hello-yunshu/Xray_bash_onekey/stargazers) [![GitHub forks](https://img.shields.io/github/forks/hello-yunshu/Xray_bash_onekey?color=%230885ce)](https://github.com/hello-yunshu/Xray_bash_onekey/network) [![GitHub issues](https://img.shields.io/github/issues/hello-yunshu/Xray_bash_onekey)](https://github.com/hello-yunshu/Xray_bash_onekey/issues)

> Thanks for non-commercial open source development authorization by JetBrains

## Usage Instructions

* You can directly input the command: `idleleo` to manage the script.
* Use Qwen AI for accurate translations in multiple languages.
* It is recommended to use Nginx as a reverse proxy for Reality, which can be installed in the script.
* It is recommended to enable fail2ban, which can be installed in the script.
* Using the share link from [@DuckSoft](https://github.com/DuckSoft)'s proposal [(beta)](https://github.com/XTLS/Xray-core/issues/91), supporting Qv2ray, V2rayN, V2rayNG.
* Using the proposal from the [XTLS](https://github.com/XTLS/Xray-core/issues/158) project, following the [UUIDv5](https://tools.ietf.org/html/rfc4122#section-4.3) standard, you can map custom strings to VLESS UUID.
* Reality installation guide: [Setting up Xray Reality Protocol Server](https://hey.run/archives/da-jian-xray-reality-xie-yi-fu-wu-qi).
* Risks of Reality protocol: [Risks of Xray Reality Protocol](https://hey.run/archives/reality-xie-yi-de-feng-xian).
* Accelerating server using Reality protocol: [Accelerate Server Using Reality Protocol "Vulnerability"](https://hey.run/archives/li-yong-reality-xie-yi-lou-dong-jia-su-fu-wu-qi).
* Adding load balancing configuration, tutorial: [XRay Advanced Play - Setting Up Backend Server Load Balancing](https://hey.run/archives/xrayjin-jie-wan-fa---da-jian-hou-duan-fu-wu-qi-fu-zai-jun-heng).
* Adding support for gRPC protocol, see details: [XRay Advanced Play - Using gRPC Protocol](https://hey.run/archives/xrayjin-jie-wan-fa---shi-yong-grpcxie-yi).

## Telegram Group

* Telegram discussion group: <https://t.me/idleleo_chat>

## Preparation

* Prepare a server running outside China with a public IP.
* If installing Reality protocol, find a domain name that meets Xray's requirements.
* If installing TLS version, prepare a domain name and add an A record.
* Read the [Xray official documentation](https://xtls.github.io) to understand Reality TLS WebSocket gRPC and related information about Xray, including the domain name requirements for Reality target.
* **Ensure curl is installed**, CentOS users run: `yum install -y curl`; Debian/Ubuntu users run: `apt install -y curl`.

## Installation Method

Copy and run:

``` bash
bash <(curl -Ss https://www.idleleo.com/install.sh)
```

## Notes

* If you do not understand the specific meanings of each setting in the script, except for required fields, please use the default values provided by the script (press Enter all the way through).
* Cloudflare users should enable CDN functionality after installation.
* Using this script requires basic Linux knowledge and experience, understanding of computer network basics, and basic computer operations.
* Currently supports Debian 9+ / Ubuntu 18.04+ / Centos7+, some Centos templates may have difficult-to-handle compilation issues; it is suggested to switch to other system templates if compilation issues occur.
* The author provides limited support, as they are quite笨.
* The sharing link is an experimental version, future changes are possible, please confirm whether your client supports it.
* Mapping custom strings to UUIDv5 requires client support.

## Acknowledgments

* This script originates from <https://github.com/wulabing/V2Ray_ws-tls_bash_onekey>, thank wulabing.
* The TCP acceleration script project referenced in this script comes from <https://github.com/ylx2016/Linux-NetSpeed>, thank ylx2016.

## Certificate

If you already have certificate files for the domain you are using, rename the crt and key files to xray.crt and xray.key and place them in the /etc/idleleo/cert directory (create the directory if it does not exist). Please note the permissions and validity period of the certificate file; self-signed certificates need to be renewed manually after expiration.

The script supports automatically generating Let's Encrypt certificates, valid for 3 months, theoretically these certificates support automatic renewal.

## View Client Configuration

`cat /etc/idleleo/xray_info.txt`

## Introduction to Xray

* Xray is an excellent open-source network proxy tool that helps you enjoy internet smoothly, currently supporting Windows, Mac, Android, IOS, Linux, etc.
* This script is a one-click complete configuration script; once all processes run normally, set up the client according to the output results to use.
* Note: We still strongly recommend that you fully understand the entire program's workflow and principles.

## Suggest Single Proxy per Server

* This script defaults to installing the latest version of Xray core.
* It is recommended to use the default port 443 as the connection port.
* The disguise content can be replaced at will.

## Other Notes

* It is recommended to use this script in a clean environment; beginners are advised not to use the Centos system.
* Before applying this program to production environments, ensure it works correctly.
* This program depends on Nginx to implement related functions; users who have previously installed Nginx using [LNMP](https://lnmp.org) or similar scripts should pay special attention, as using this script may cause unpredictable errors.
* Centos system users should pre-open relevant ports in the firewall (default: 80, 443).

## Startup Methods

Start Xray: `systemctl start xray`

Stop Xray: `systemctl stop xray`

Start Nginx: `systemctl start nginx`

Stop Nginx: `systemctl stop nginx`

## Related Directories

Xray server configuration: `/etc/idleleo/conf/xray/config.json`

Nginx directory: `/usr/local/nginx`

Certificate files: `/etc/idleleo/cert/xray.key` and `/etc/idleleo/cert/xray.crt`, please note the permission settings of the certificate file

Configuration information files, etc.: `/etc/idleleo`
