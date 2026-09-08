# Xray 管理脚本 — Reality / VLESS WebSocket/gRPC/xHTTP+TLS + Nginx

简体中文 | [English](/i18n/languages/en/README.md) | [Français](/i18n/languages/fr/README.md) | [Русский](/i18n/languages/ru/README.md) | [فارسی](/i18n/languages/fa/README.md) | [한국어](/i18n/languages/ko/README.md)

[![GitHub stars](https://img.shields.io/github/stars/hello-yunshu/Xray_bash_onekey?color=%230885ce)](https://github.com/hello-yunshu/Xray_bash_onekey/stargazers) [![GitHub forks](https://img.shields.io/github/forks/hello-yunshu/Xray_bash_onekey?color=%230885ce)](https://github.com/hello-yunshu/Xray_bash_onekey/network) [![GitHub issues](https://img.shields.io/github/issues/hello-yunshu/Xray_bash_onekey)](https://github.com/hello-yunshu/Xray_bash_onekey/issues)

> Thanks for non-commercial open source development authorization by JetBrains

## 功能特性

* 输入 `idleleo` 打开 Xray 管理菜单，管理安装、服务、安全设置等
* 采用 Qwen-MT-Plus AI 实现多语言精准翻译
* 支持 Reality 协议，建议搭配 Nginx 前置（脚本内可安装）
* 支持 WebSocket、gRPC、xHTTP 传输，可选择单一传输或 `ws+gRPC+xHTTP` 同时启用
* 支持 IPv4 / IPv6 双栈：安装时可自动检测公网出口能力，按域名 A/AAAA 记录独立校验并生成对应分享链接与 Clash 配置
* 내장된 fail2ban 보호(스크립트 내에 설치 가능)
* 内置 Xray 流量统计、流量阻断、GeoIP/GeoSite 规则更新及定时更新
* 支持脚本、Xray、Nginx 和证书更新，并为关键更新提供备份与失败回滚
* 重新安装和模式切换前会自动备份当前运行配置，失败时恢复原配置
* 重配置提供三条安全路径：保留配置重新部署、标准模板重建、模式切换
* 采用 [@DuckSoft](https://github.com/DuckSoft) 的分享链接[提案](https://github.com/XTLS/Xray-core/issues/91)（beta），兼容 Qv2ray、V2rayN、V2rayNG
* 采用 [XTLS](https://github.com/XTLS/Xray-core/issues/158) 提案，遵循 [UUIDv5](https://tools.ietf.org/html/rfc4122#section-4.3) 标准，支持自定义字符串映射至 VLESS UUID
* 支持 gRPC 协议：[使用 gRPC 协议](https://hey.run/posts/xrayjin-jie-wan-fa---shi-yong-grpcxie-yi)
* 支持 Reality / ws/gRPC/xHTTP 负载均衡：
  - [部署 Reality 负载均衡](https://hey.run/posts/bushu-reality-balance)
  - [搭建后端负载均衡](https://hey.run/posts/xrayjin-jie-wan-fa---da-jian-hou-duan-fu-wu-qi-fu-zai-jun-heng)
* Reality + Nginx 模式默认启用 SNI Guard：未知 SNI、空 SNI 与异常 TLS 不会进入 Xray Reality 后端，默认采用隔离策略（ssl_reject_handshake），高级用户可切换为自建 decoy 站点回落或直接 TCP 拒绝。该功能用于减少主动探测与误配置暴露，不追求完美伪装

## 延伸阅读

* `idleleo` 命名背景故事：[迷雾后的真容](https://github.com/hello-yunshu/Xray_bash_onekey/wiki/%E8%BF%B7%E9%9B%9C%E5%90%8E%E7%9A%84%E7%9C%9F%E5%AE%B9)
* Reality 安装指南：[搭建 Xray Reality 服务器](https://hey.run/posts/da-jian-xray-reality-xie-yi-fu-wu-qi)
* Reality 协议风险：[Xray Reality 协议的风险](https://hey.run/posts/reality-xie-yi-de-feng-xian)
* Reality 加速服务器：[利用 Reality 协议"漏洞"加速服务器](https://hey.run/posts/use-reality)

## Telegram 群组

* 交流群：[点击加入](https://t.me/+48VSqv7xIIFmZDZl)

## 准备工作

* 一台境外服务器，具备公网 IP
* 安装 Reality 协议：需准备符合 Xray 要求的目标域名
* 安装 TLS 版本：需准备域名，并根据服务器可用网络正确配置 A 和/或 AAAA 记录；双栈环境建议同时配置正确的 A 与 AAAA。脚本支持自动检测 IPv4/IPv6 网络能力，双栈可用时可同时生成对应客户端入口
* 阅读 [Xray 官方文档](https://xtls.github.io)，了解 Reality、TLS、WebSocket、gRPC 及 Xray 相关概念
* **确保已安装 curl**：CentOS 用户执行 `yum install -y curl`；Debian/Ubuntu 用户执行 `apt install -y curl`

## 快速安装

```bash
bash <(curl -fsSL https://github.com/hello-yunshu/Xray_bash_onekey/releases/latest/download/install.sh)
```

## 安装模式

| 模式 | 说明 |
|------|------|
| Reality + Nginx | 推荐模式，可按需附加 ws/gRPC/xHTTP 简单协议用于负载均衡 |
| Nginx + TLS | 支持 ws/gRPC/xHTTP，自动申请并续期 Let's Encrypt 证书 |
| ws/gRPC/xHTTP ONLY | 无 TLS 的独立入站模式，主要用于后端或负载均衡场景 |
| XTLS ONLY | 仅用于流量中转等特定场景 |
| Docker | 镜像内预装 Xray、Nginx 与主脚本 |

安装 ws/gRPC/xHTTP 相关模式时，可选择 `ws`、`gRPC`、`xHTTP` 或 `ws+gRPC+xHTTP`。脚本会分别生成对应端口、路径、分享链接和二维码；Clash 目前不支持 xHTTP，脚本会在配置输出中提示。

## 重配置说明

已安装的环境再次运行安装时，脚本会自动备份当前运行配置，并提供三条重配置路径：

| 路径 | 说明 | 限制 |
|------|------|------|
| 保留配置重新部署 | 保留自定义 routing/outbounds/DNS 和多用户配置，仅修改用户选择的字段（端口、路径、UUID、Reality 参数等） | 不支持传输结构变更（如 ws → gRPC），需改传输组合请使用标准模板重建 |
| 标准模板重建 | 使用当前可复用参数生成标准模板配置，自定义 routing/outbounds/DNS 可能被移除 | 不强制要求用户数量不变 |
| 模式切换 | 切换到不同协议模式（如 Reality → TLS），默认只复用主用户 UUID/email | 其他用户不自动迁移，切换前会明确提示 |

重配置过程中任何步骤失败（配置写入、服务启动、健康检查等）都会自动回滚到备份的原配置。备份目录使用唯一时间戳，支持连续多次重配置互不冲突。

## 常用命令

| 操作 | 命令 |
|------|------|
| 打开管理菜单 | `idleleo` |
| 查看帮助 | `idleleo --help` |
| 安装 Reality 模式 | `idleleo --install-reality` |
| 安装 TLS 模式 | `idleleo --install-tls` |
| 安装 ws/gRPC/xHTTP ONLY | `idleleo --install-none` |
| 查看安装信息 | `idleleo --show` |
| 更新脚本 | `idleleo --update` |
| 更新 Xray | `idleleo --xray-update` |
| 更新 Nginx | `idleleo --nginx-update` |
| 设置 Fail2ban | `idleleo --set-fail2ban` |
| 设置流量阻断 | `idleleo --traffic-blocker` |
| 查看端口实时流量 | `idleleo --port-traffic` |

## RillML Xray AI 运维助手

RillML（简称 Rill）为 Xray 提供本地自适应智能运维能力。

内置本地 AI 运维助手，实时监控 Xray/Nginx 健康状态，自动诊断故障并给出处理建议，无需外部 API。主菜单输入 `9` 或执行 `idleleo --rill-agent` 进入。

**核心能力**

* 监控：实时观测 Xray/Nginx 服务与配置状态
* 诊断：定位故障根因，附置信度建议（高 / 中 / 低 / 证据不足）
* 判断：自动判断故障类型并给出处理建议，说明中明确标注允许自动处理或仅提供建议
* 模式：智能判断 / 仅观察 / 安全停用，未开启自动修改前不会更改系统

**常用命令**

| 操作 | 命令 |
|------|------|
| 打开 AI 运维助手菜单 | `idleleo --rill-agent` |
| 安装或修复 AI 判断引擎 | `idleleo --rill-agent-install` |
| 查看 AI 判断状态 | `idleleo --rill-agent-status` |
| 运行 AI 故障诊断 | `idleleo --rill-agent-diagnose` |
| 校验 AI 判断引擎 | `idleleo --rill-agent-verify` |
| 安全停用 AI 判断 | `idleleo --rill-agent-safe-disable` |
| 卸载 Rill AI 引擎 | `idleleo --rill-agent-uninstall` |

AI 判断引擎目前仍处于测试阶段，建议以诊断建议为主，默认不会自动修改系统。

## Docker 部署

支持使用 Docker 部署，镜像预装 Xray 和 Nginx，容器内可直接使用原脚本所有功能。详见 [Docker 部署指南](/docker/DOCKER.md)。

```bash
git clone https://github.com/hello-yunshu/Xray_bash_onekey.git
cd Xray_bash_onekey
docker compose up -d
docker attach xray-onekey
```

## AI Skill 部署

支持通过 AI 工具（如 Trae）自动部署 Xray，无需手动交互。详见 [Xray_bash_onekey_skill](https://github.com/hello-yunshu/Xray_bash_onekey_skill)。

传统方式需要 SSH 到服务器、运行安装脚本、逐个回答交互式问题；Skill 方式只需告诉 AI 你的需求，AI 会自动生成非交互式脚本并执行，直接返回 VLESS 链接。

**지원되는 모드**: Reality / TLS / ws ONLY / XTLS ONLY

**使用方式**：在支持 Skill 的 AI 工具中直接说"帮我在服务器上搭建 Xray"，AI 会自动收集信息、生成脚本、执行部署并返回连接信息。

## 注意事项

* 不了解各项设置含义时，除必填项外请使用默认值（全程回车即可）
* Cloudflare 用户请在安装完成后再开启 CDN
* 本脚本需要 Linux 基础知识及计算机网络常识
* 支持 Debian 12+ / Ubuntu 24.04+ / CentOS Stream 10+，部分 CentOS 模板可能存在编译问题，建议遇到问题时更换系统
* 建议单服务器仅部署单个代理，使用默认 443 端口
* 自定义字符串映射至 UUIDv5 需要客户端支持
* 순수한 환경에서 사용하는 것을 권장합니다. 초보자는 CentOS을 사용하면 안 됩니다.
* 本程序依赖 Nginx，已通过 [LNMP](https://lnmp.org)Nginx 스크립트를 설치한 사용자는 잠재적인 충돌에 유의하시기 바랍니다.
* xHTTP 分享链接适用于支持 xHTTP 的客户端；Clash 配置输出会跳过 xHTTP
* 请勿在未验证可用性前将本脚本用于生产环境
* 作者：云舒，仅提供有限支持

## 감사의 말

* 기반으로[wulabing/V2Ray_ws-tls_bash_onekey](https://github.com/wulabing/V2Ray_ws-tls_bash_onekey) 开发
* TCP에서 인용된 가속 스크립트[ylx2016/Linux-NetSpeed](https://github.com/ylx2016/Linux-NetSpeed)

## 인증서 구성

**맞춤 인증서**: crt 및 key 파일의 이름을 각각 지정합니다.`xray.crt`그리고`xray.key`, 넣다`/etc/idleleo/cert`디렉토리(디렉토리가 없으면 먼저 작성하십시오). 인증기관 및 유효기간에 주의하시기 바랍니다. 사용자 정의 인증서가 만료된 후에는 직접 갱신해야 합니다.

**자동 인증서**: 스크립트는 Let's Encrypt 인증서(3개월 동안 유효) 자동 생성을 지원하며 이론적으로 자동 갱신을 지원합니다.

## 클라이언트 구성 보기

```bash
cat /etc/idleleo/info/xray_info.inf
```

## Xray 소개

* Xray은 Windows, macOS, Android, iOS, Linux 및 기타 전체 플랫폼을 지원하는 뛰어난 오픈 소스 네트워크 프록시 도구입니다.
* 이 스크립트는 원클릭 완전한 구성 스크립트입니다. 모든 과정이 정상적으로 완료된 후, 출력 결과에 따라 클라이언트를 이용하실 수 있습니다.
* **적극 권장** 프로그램의 작업 흐름과 원칙에 대한 포괄적인 이해

## 서비스 관리

| 작동하다 | 주문하다 |
|------|------|
| Xray 시작 | `systemctl start xray` |
| Xray 중지 | `systemctl stop xray` |
| Nginx 시작 | `systemctl start nginx` |
| Nginx 중지 | `systemctl stop nginx` |

## 관련 카탈로그

| 콘텐츠 | 길 |
|------|------|
| 홈 디렉토리 | `/etc/idleleo` |
| Xray 구성 | `/etc/idleleo/conf/xray/config.json` |
| Nginx 구성 | `/etc/idleleo/conf/nginx/` |
| 설치정보 | `/etc/idleleo/conf/install_config.json` |
| 인증서 파일 | `/etc/idleleo/cert/xray.key`、`/etc/idleleo/cert/xray.crt` |
| 로그 디렉터리 | `/etc/idleleo/logs/`、`/var/log/xray/` |
| Nginx 설치 디렉터리 | `/usr/local/nginx` |
| 관리 명령 | `/usr/bin/idleleo` |
