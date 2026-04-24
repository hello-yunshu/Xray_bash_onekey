# Xray 一键安装脚本 — Reality / VLESS WebSocket/gRPC+TLS + Nginx

简体中文 | [English](/languages/en/README.md) | [Français](/languages/fr/README.md) | [Русский](/languages/ru/README.md) | [فارسی](/languages/fa/README.md) | [한국어](/languages/ko/README.md)

[![GitHub stars](https://img.shields.io/github/stars/hello-yunshu/Xray_bash_onekey?color=%230885ce)](https://github.com/hello-yunshu/Xray_bash_onekey/stargazers) [![GitHub forks](https://img.shields.io/github/forks/hello-yunshu/Xray_bash_onekey?color=%230885ce)](https://github.com/hello-yunshu/Xray_bash_onekey/network) [![GitHub issues](https://img.shields.io/github/issues/hello-yunshu/Xray_bash_onekey)](https://github.com/hello-yunshu/Xray_bash_onekey/issues)

> Thanks for non-commercial open source development authorization by JetBrains

## 功能特性

* 输入 `idleleo` 即可管理脚本（[查看 `idleleo` 背景故事](https://github.com/hello-yunshu/Xray_bash_onekey/wiki/%E8%BF%B7%E9%9B%BE%E5%90%8E%E7%9A%84%E7%9C%9F%E5%AE%B9)）
* 采用 Qwen-MT-Plus AI 实现多语言精准翻译
* 支持 Reality 协议，建议搭配 Nginx 前置（脚本内可安装）
* 内置 fail2ban 防护（脚本内可安装）
* 采用 [@DuckSoft](https://github.com/DuckSoft) 的分享链接[提案](https://github.com/XTLS/Xray-core/issues/91)（beta），兼容 Qv2ray、V2rayN、V2rayNG
* 采用 [XTLS](https://github.com/XTLS/Xray-core/issues/158) 提案，遵循 [UUIDv5](https://tools.ietf.org/html/rfc4122#section-4.3) 标准，支持自定义字符串映射至 VLESS UUID
* 支持 gRPC 协议：[使用 gRPC 协议](https://hey.run/archives/xrayjin-jie-wan-fa---shi-yong-grpcxie-yi)
* 支持 Reality / ws/gRPC 负载均衡：
  - [部署 Reality 负载均衡](https://hey.run/archives/bushu-reality-balance)
  - [搭建后端负载均衡](https://hey.run/archives/xrayjin-jie-wan-fa---da-jian-hou-duan-fu-wu-qi-fu-zai-jun-heng)

## 延伸阅读

* Reality 安装指南：[搭建 Xray Reality 服务器](https://hey.run/archives/da-jian-xray-reality-xie-yi-fu-wu-qi)
* Reality 协议风险：[Xray Reality 协议的风险](https://hey.run/archives/reality-xie-yi-de-feng-xian)
* Reality 加速服务器：[利用 Reality 协议"漏洞"加速服务器](https://hey.run/archives/use-reality)

## Telegram 群组

* 交流群：[点击加入](https://t.me/+48VSqv7xIIFmZDZl)

## 准备工作

* 一台境外服务器，具备公网 IP
* 安装 Reality 协议：需准备符合 Xray 要求的目标域名
* 安装 TLS 版本：需准备域名并添加 A 记录
* 阅读 [Xray 官方文档](https://xtls.github.io)，了解 Reality、TLS、WebSocket、gRPC 及 Xray 相关概念
* **确保已安装 curl**：CentOS 用户执行 `yum install -y curl`；Debian/Ubuntu 用户执行 `apt install -y curl`

## 快速安装

```bash
bash <(curl -Ss https://raw.githubusercontent.com/hello-yunshu/Xray_bash_onekey/main/install.sh)
```

## 注意事项

* 不了解各项设置含义时，除必填项外请使用默认值（全程回车即可）
* Cloudflare 用户请在安装完成后再开启 CDN
* 本脚本需要 Linux 基础知识及计算机网络常识
* 支持 Debian 12+ / Ubuntu 24.04+ / CentOS Stream 8+，部分 CentOS 模板可能存在编译问题，建议遇到问题时更换系统
* 建议单服务器仅部署单个代理，使用默认 443 端口
* 自定义字符串映射至 UUIDv5 需要客户端支持
* 推荐在纯净环境下使用；新手请勿使用 CentOS
* 本程序依赖 Nginx，已通过 [LNMP](https://lnmp.org) 等脚本安装过 Nginx 的用户请注意潜在冲突
* 请勿在未验证可用性前将本脚本用于生产环境
* 作者仅提供有限支持（因为太笨了）

## 鸣谢

* 基于 [wulabing/V2Ray_ws-tls_bash_onekey](https://github.com/wulabing/V2Ray_ws-tls_bash_onekey) 开发
* TCP 加速脚本引用自 [ylx2016/Linux-NetSpeed](https://github.com/ylx2016/Linux-NetSpeed)

## 证书配置

**自定义证书**：将 crt 和 key 文件分别命名为 `xray.crt` 和 `xray.key`，放入 `/etc/idleleo/cert` 目录（目录不存在则先创建）。请注意证书权限及有效期，自定义证书过期后需自行续签。

**自动证书**：脚本支持自动生成 Let's Encrypt 证书（有效期 3 个月），理论上支持自动续签。

## 查看客户端配置

```bash
cat /etc/idleleo/info/xray_info.inf
```

## Xray 简介

* Xray 是一款优秀的开源网络代理工具，支持 Windows、macOS、Android、iOS、Linux 等全平台
* 本脚本为一键完整配置脚本，所有流程正常完成后，按输出结果设置客户端即可使用
* **强烈建议**全面了解程序的工作流程及原理

## 服务管理

| 操作 | 命令 |
|------|------|
| 启动 Xray | `systemctl start xray` |
| 停止 Xray | `systemctl stop xray` |
| 启动 Nginx | `systemctl start nginx` |
| 停止 Nginx | `systemctl stop nginx` |

## 相关目录

| 内容 | 路径 |
|------|------|
| Xray 服务端配置 | `/etc/idleleo/conf/xray/config.json` |
| Nginx 目录 | `/usr/local/nginx` |
| 证书文件 | `/etc/idleleo/cert/xray.key`、`/etc/idleleo/cert/xray.crt` |
| 配置信息等 | `/etc/idleleo` |
