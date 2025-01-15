# One-click Installation Script for Xray with Reality / VLESS WebSocket/gRPC+TLS Protocol + Nginx

[简体中文](README.md) | [English](languages/en/README.md)

[![GitHub stars](https://img.shields.io/github/stars/hello-yunshu/Xray_bash_onekey?color=%230885ce)](https://github.com/hello-yunshu/Xray_bash_onekey/stargazers) [![GitHub forks](https://img.shields.io/github/forks/hello-yunshu/Xray_bash_onekey?color=%230885ce)](https://github.com/hello-yunshu/Xray_bash_onekey/network) [![GitHub issues](https://img.shields.io/github/issues/hello-yunshu/Xray_bash_onekey)](https://github.com/hello-yunshu/Xray_bash_onekey/issues)

> Thanks for non-commercial open source development authorization by JetBrains

## Instructions

* You can directly enter the command: `idleleo` to manage the script.
* It is recommended to use Nginx frontend for Reality, which can be installed in the script.
* It is recommended to enable fail2ban, which can be installed in the script.
* Using the sharing link [proposal](https://github.com/XTLS/Xray-core/issues/91) (beta) from [@DuckSoft](https://github.com/DuckSoft), supporting Qv2ray, V2rayN, V2rayNG.
* Using the proposal from [XTLS](https://github.com/XTLS/Xray-core/issues/158) project, following the [UUIDv5](https://tools.ietf.org/html/rfc4122#section-4.3) standard, custom strings can be mapped to VLESS UUID.
* Reality installation instructions: [Setting up Xray Reality Protocol Server](https://hey.run/archives/da-jian-xray-reality-xie-yi-fu-wu-qi).
* Risks of Reality protocol: [Risks of Xray Reality Protocol](https://hey.run/archives/reality-xie-yi-de-feng-xian).
* Accelerating server using Reality protocol: [Accelerating Server Using Reality Protocol "Vulnerability"](https://hey.run/archives/li-yong-reality-xie-yi-lou-dong-jia-su-fu-wu-qi).
* Added load balancing configuration, tutorial: [XRay Advanced Usage – Setting up Backend Server Load Balancing](https://hey.run/archives/xrayjin-jie-wan-fa---da-jian-hou-duan-fu-wu-qi-fu-zai-jun-heng).
* Added gRPC protocol support, details can be found at: [Xray Advanced Usage – Using gRPC Protocol](https://hey.run/archives/xrayjin-jie-wan-fa---shi-yong-grpcxie-yi).

## Telegram Group

* Telegram chat group: <https://t.me/idleleo_chat>

## Preparation

* Prepare a server running outside mainland China with a public IP.
* For Reality protocol installation, find a domain name that meets Xray requirements.
* For TLS version installation, prepare a domain name and add the A record.
* Read [Xray official documentation](https://xtls.github.io) to understand Reality TLS WebSocket gRPC and Xray related information, understand Reality target domain requirements.
* **Install curl**, Centos users run: `yum install -y curl`; Debian/Ubuntu users run: `apt install -y curl`.

## Installation Method

Copy and run:

``` bash
bash <(curl -Ss https://www.idleleo.com/install.sh)
```

## Notes

* If you don't understand the specific meaning of each setting in the script, except for required items, please use the default values provided by the script (press Enter all the way).
* Cloudflare users please enable CDN function after installation is complete.
* Using this script requires Linux basics and experience, understanding of computer network knowledge, and basic computer operations.
* Currently supports Debian 9+ / Ubuntu 18.04+ / Centos7+. Some Centos templates may have difficult compilation issues, it is recommended to switch to other system templates when encountering compilation problems.
* The author provides limited support, as they are too inexperienced.
* The sharing link is an experimental version, future changes are possible, please confirm client support yourself.
* Custom string mapping to UUIDv5 requires client support.

## Acknowledgments

* This script is derived from <https://github.com/wulabing/V2Ray_ws-tls_bash_onekey> Thanks to wulabing
* TCP acceleration script project in this script references <https://github.com/ylx2016/Linux-NetSpeed> Thanks to ylx2016

## Certificate

If you already have the certificate files for your domain name, you can name the crt and key files as xray.crt and xray.key and place them in the /etc/idleleo/cert directory (create the directory if it doesn't exist), please note the certificate file permissions and validity period, custom certificates need to be renewed manually after expiration.

The script supports automatic generation of Let's Encrypted certificates, valid for 3 months, theoretically supporting automatic renewal.

## View Client Configuration

`cat /etc/idleleo/xray_info.txt`

## Xray Introduction

* Xray is an excellent open-source network proxy tool that can help you enjoy the internet smoothly, currently supporting Windows, Mac, Android, IOS, Linux and other operating systems.
* This script is a one-click complete configuration script. After all processes run normally, you can directly set up the client according to the output results.
* Please note: We still strongly recommend that you fully understand the entire program's workflow and principles.

## Recommend Setting Up Single Proxy on Single Server

* This script installs the latest version of Xray core by default.
* It is recommended to use the default port 443 as the connection port.
* The disguise content can be replaced as needed.

## Other Notes

* Recommended to use this script in a clean environment. If you are a beginner, please do not use Centos system.
* Please do not apply this program to production environment before confirming this script is actually usable.
* This program depends on Nginx to implement related functions. Users who have installed Nginx using [LNMP](https://lnmp.org) or other similar Nginx scripts should pay special attention, using this script may cause unpredictable errors.
* Centos system users please allow program-related ports (default: 80, 443) in the firewall in advance.

## Start Method

Start Xray: `systemctl start xray`

Stop Xray: `systemctl stop xray`

Start Nginx: `systemctl start nginx`

Stop Nginx: `systemctl stop nginx`

## Related Directories

Xray server configuration: `/etc/idleleo/conf/xray/config.json`

Nginx directory: `/usr/local/nginx`

Certificate files: `/etc/idleleo/cert/xray.key` and `/etc/idleleo/cert/xray.crt` please note certificate permission settings

Configuration information files etc: `/etc/idleleo`
