# Xray 管理脚本

> 面向 Debian、Ubuntu 与 CentOS Stream 的 Xray 一键部署和管理工具，覆盖 Reality、TLS、ws/gRPC/xHTTP、中转节点与 Docker。

[![License: GPL-3.0](https://img.shields.io/badge/license-GPL--3.0-blue)](https://github.com/hello-yunshu/Xray_bash_onekey/blob/main/LICENSE) [![Platform: Linux](https://img.shields.io/badge/platform-Linux-lightgrey)](https://github.com/hello-yunshu/Xray_bash_onekey) [![Shell: Bash](https://img.shields.io/badge/shell-Bash-4EAA25)](https://github.com/hello-yunshu/Xray_bash_onekey)

简体中文 | [English](https://github.com/hello-yunshu/Xray_bash_onekey/blob/main/i18n/languages/en/README.md) | [Français](https://github.com/hello-yunshu/Xray_bash_onekey/blob/main/i18n/languages/fr/README.md) | [Русский](https://github.com/hello-yunshu/Xray_bash_onekey/blob/main/i18n/languages/ru/README.md) | [فارسی](https://github.com/hello-yunshu/Xray_bash_onekey/blob/main/i18n/languages/fa/README.md) | [한국어](https://github.com/hello-yunshu/Xray_bash_onekey/blob/main/i18n/languages/ko/README.md)

## 项目定位

这是一个用 Bash 编写的 Xray 部署与运维脚本。它把安装、证书、Nginx 前置、客户端配置、服务管理、备份恢复和日常排障集中到一个菜单里，适合希望快速搭建单机代理、又不想手工维护整套配置的用户。

脚本负责生成配置和编排服务，Xray 负责实际代理；Reality 与 TLS 模式建议搭配 Nginx 前置。所有关键写入都会先做语法检查或备份，失败时尽量回滚，避免把正在运行的服务留在半成品状态。

## 功能概览

| 能力 | 说明 |
|---|---|
| 安装模式 | Reality + Nginx、Nginx + TLS、ws/gRPC/xHTTP ONLY、中转节点、Docker |
| 传输协议 | WebSocket、gRPC、xHTTP，可单选或组合 `ws+gRPC+xHTTP` |
| 双栈网络 | 自动检测 IPv4/IPv6 出口能力，按域名 A/AAAA 记录分别校验并生成客户端入口 |
| 客户端输出 | 分享链接、二维码、Clash 配置；Clash 暂不支持 xHTTP |
| 安全管理 | fail2ban、流量阻断、SNI Guard、防火墙与证书管理 |
| 日常运维 | 服务管理、配置变更、日志清理、端口流量查看、备份恢复 |
| 流量统计 | 按 inbound 读取上行、下行与总量，支持 JSON、重置和实时刷新 |
| 智能助手 | RillML 本地 AI 运维助手，提供监控、诊断和处置建议 |
| 更新维护 | 脚本、Xray、Nginx 与证书更新，关键更新带备份和失败回滚 |

## 系统支持

| 系统 | 版本 | 说明 |
|---|---|---|
| Debian | 12、13 | 使用 `apt`，CI 覆盖 `debian:12-slim` 与 `debian:13-slim` |
| Ubuntu | 24.04、26.04 | 使用 `apt`，CI 覆盖 `ubuntu:24.04` 与 `ubuntu:26.04` |
| CentOS Stream | 10 | 使用 RPM 包管理器，CI 覆盖 `quay.io/centos/centos:stream10` |
| Rocky / AlmaLinux | 10+ | 按 RPM 系处理，主版本不低于 10 |

需要 root 权限、systemd、公网 IP 和可用的出站网络。安装过程会自动补齐 `curl`、`jq`、`openssl`、`qrencode`、`nmap` 等依赖；Reality/TLS 模式还需要准备域名，并按服务器网络配置 A 和/或 AAAA 记录。

> 不支持的系统会在安装前被拒绝。CentOS 模板差异较大，若遇到编译或依赖问题，建议改用 Debian 或 Ubuntu。

## 快速开始

准备一台受支持的 Linux 服务器，使用 root 执行：

```bash
bash <(curl -fsSL https://github.com/hello-yunshu/Xray_bash_onekey/releases/latest/download/install.sh)
```

安装完成后输入 `idleleo` 打开管理菜单；也可以直接执行 `idleleo --install-reality`、`idleleo --install-tls` 或 `idleleo --install-none` 进入对应模式。

首次使用建议先阅读菜单中的安装向导，不确定的项目直接回车使用默认值。安装完成后按脚本输出的分享链接或二维码配置客户端。

## 安装模式

| 模式 | 适用场景 | 关键说明 |
|---|---|---|
| Reality + Nginx | 推荐的单机入口 | 可按需附加 ws/gRPC/xHTTP 简单协议用于负载均衡 |
| Nginx + TLS | 需要标准 TLS 入口 | 自动申请并续期 Let's Encrypt 证书 |
| ws/gRPC/xHTTP ONLY | 后端或负载均衡节点 | 无 TLS，默认仅监听 `127.0.0.1` |
| 中转节点 | 独立 TCP 转发 | 仅使用 Nginx Stream 做单目标转发，不安装 Xray |
| Docker | 容器化部署 | 镜像内预装 Xray、Nginx 与主脚本 |

安装 ws/gRPC/xHTTP 相关模式时，可选择 `ws`、`gRPC`、`xHTTP` 或 `ws+gRPC+xHTTP`。脚本会分别为每个传输生成端口、路径、分享链接和二维码；Clash 配置会跳过 xHTTP，并在输出中提示。

## 管理菜单

输入 `idleleo` 进入主菜单：

| 选项 | 功能 |
|---|---|
| `1` | 安装向导 |
| `2` | 配置变更 |
| `3` | 查看信息 |
| `4` | Xray / TLS 服务与证书 |
| `5` | 更新向导 |
| `6` | 其他选项（TCP 加速、Fail2ban、流量统计、流量阻断、日志、网速） |
| `7` | 备份恢复与卸载 |
| `8` | 修改语言 |
| `9` | Rill Xray AI 运维助手 |
| `0` | 退出 |

菜单中的“其他选项 → Xray 流量统计”提供开启/关闭统计、查看、重置和实时监控四个入口。

## 常用命令

| 操作 | 命令 |
|---|---|
| 打开管理菜单 | `idleleo` |
| 查看帮助 | `idleleo --help` |
| 安装 Reality 模式 | `idleleo --install-reality` |
| 安装 TLS 模式 | `idleleo --install-tls` |
| 安装 ws/gRPC/xHTTP ONLY | `idleleo --install-none` |
| 安装中转节点 | `idleleo --install-relay` |
| 查看安装信息 | `idleleo --show` |
| 查看 Xray 访问信息 | `idleleo --xray-access` |
| 查看 Xray 错误信息 | `idleleo --xray-error` |
| 查看端口实时流量 | `idleleo --port-traffic` |
| 更新脚本 | `idleleo --update` |
| 更新 Xray | `idleleo --xray-update` |
| 更新 Nginx | `idleleo --nginx-update` |
| 设置 Fail2ban | `idleleo --set-fail2ban` |
| 设置流量阻断 | `idleleo --traffic-blocker` |
| 备份脚本管理文件 | `idleleo --backup` |
| 恢复脚本管理文件 | `idleleo --restore` |
| 卸载脚本与 Xray/Nginx | `idleleo --purge` |
| 查看流量统计 | `idleleo --stats` / `idleleo --stats --json` |
| 重置流量统计 | `idleleo --stats-reset`（确认后执行，`--yes` 跳过确认） |
| 实时监控流量统计 | `idleleo --stats-watch` [秒] |

## Xray 流量统计

统计开启后，统计 API 默认只监听 `127.0.0.1:10085`。读取工作由独立脚本 `/etc/idleleo/scripts/xray_stats.sh` 完成，权限为 `0600 root:root`；主脚本只负责入口、下载、SHA256 校验和委托，不复制查询逻辑。

```bash
idleleo --stats                  # 表格：每个 inbound 的上行、下行与总量
idleleo --stats --json           # 机器可读 JSON
idleleo --stats-reset            # 交互确认后清零计数
idleleo --stats-reset --yes      # 自动化确认
idleleo --stats-watch 5          # 每 5 秒刷新，Ctrl-C 退出
```

统计脚本缺失时，主脚本会从当前 Release 下载 `xray_stats.sh`，并用 `release-manifest.json` 的 `statsScriptSha256` 校验。校验失败只影响读取，不会影响统计开关。统计已开启但配置缺少 `api.listen` 时，首次执行 `--stats` 会明确询问是否补写并重启 Xray；拒绝不会修改配置。

### 退出码

| 退出码 | 含义 |
|---|---|
| `0` | 查询成功；计数为 0 也是成功 |
| `1` | 用户取消 reset |
| `2` | 前置缺失：未开启统计、无 `api.listen`、Xray 未运行、API 不可达、脚本缺失或校验失败 |
| `3` | API 调用或 JSON 解析失败 |
| `4` | 参数错误 |
| `5` | 非 root 或权限不足 |
| `130` | watch 被 Ctrl-C 中断 |

失败时不会打印伪造的 0：未开启统计或 API 不可达返回 `2`，坏 JSON 返回 `3`，非 root 返回 `5`。

### 安全边界

> 统计 API 只绑定回环地址，但没有鉴权。本机其他用户理论上可以访问该端口并读取或重置计数。建议在单用户 VPS 上使用，不要把 `10085` 暴露到公网；`--stats-reset` 必须显式确认。

Xray StatsService 只提供 inbound 上行/下行与 Uptime 等计数，**不提供活动连接数**。需要连接数时请使用系统级工具或独立观测方案，不要期待 `--stats` 给出连接数。

## 备份与恢复

`idleleo --backup` 只备份脚本管理的文件：`/etc/idleleo`、`/usr/local/nginx`、Xray 二进制、systemd unit、root crontab 和 ACME 状态。它不是主机全备份，也不会自动包含用户自己放在其他路径的数据。

`idleleo --restore` 选择文件名中时间戳最新的备份：带完整性清单的备份会校验归档内每个文件的 SHA256，并移除备份中不存在的脚本管理配置；无清单的旧备份只做结构校验，并跳过跨模式清理。恢复保留用户自定义文件，也不会自动启动服务。跨模式恢复后请检查残留配置，并按需重启服务。旧备份如果没有 `/usr/local/share/xray` 软链，恢复时会自动创建软链或把旧 GeoData 目录合并进 `/etc/idleleo/share/xray`，再用真实 `xray run -test` 校验；自愈失败会回滚，因此旧备份无需重装也能恢复到新主机。

备份包可能包含证书、私钥和客户端配置，请按敏感文件保管，不要上传到公开位置。

## 升级与更新

在管理菜单“更新向导 → 更新脚本”中更新，或执行：

```bash
idleleo --update                  # 交互确认
idleleo --update --yes            # 非交互，同一发布序列自动确认
idleleo --update --yes --allow-major  # 跨发布序列，需显式解除限制
```

`--yes` 只自动确认同一发布序列的更新；跨发布序列还需显式加 `--allow-major`。`--allow-major` 只解除序列限制，本身不替代确认，非交互场景仍需同时给 `--yes`。更新脚本会用新脚本整体替换 `/etc/idleleo/install.sh`，并按新脚本重新计算 Release 地址，同时同步辅助资产。

`--xray-update` 只更新 Xray 核心，`--nginx-update` 只更新 Nginx，都不会升级脚本本身。自动更新只在同一发布序列内自动升级脚本；Xray 和 Nginx 的自动更新仍按 API 元数据执行。升级前建议先执行 `idleleo --backup`。

旧版 XTLS 模式不再提供新建或重装入口；已有 XTLS 服务可以继续运行，但不能通过脚本重装或切换模式。需要继续管理时，请先备份并卸载，再重新部署 Reality、TLS 或中转模式。

## 重配置

已安装的环境再次运行安装时，脚本会自动备份当前运行配置，并提供三条路径：

| 路径 | 说明 | 限制 |
|---|---|---|
| 保留配置重新部署 | 保留自定义 routing、outbounds、DNS 和多用户配置，仅修改用户选择的字段 | 不支持传输结构变更，例如 ws 改为 gRPC |
| 标准模板重建 | 使用当前可复用参数生成标准模板配置 | 自定义 routing、outbounds、DNS 可能被移除 |
| 模式切换 | 切换到不同协议模式，例如 Reality 改为 TLS | 默认只复用主用户 UUID/email，其他用户不自动迁移 |

重配置过程中任何步骤失败（配置写入、服务启动、健康检查等）都会自动回滚到备份的原配置。备份目录使用唯一时间戳，支持连续多次重配置互不冲突。

## Go 管理器迁移（实验）

> 证据等级：容器级 `CONTAINER_VERIFIED`（固定 digest 的 Ubuntu 24.04 + 真实 systemd/Xray/nginx 容器），**不是“真实 VPS 已验证”**。真实 ACME 签发/续期不纳入本轮验收。

- **3.3.5 不启用 Go，也不会自动提示迁移**：新装、`-u`、`auto_update`、全量重装和菜单都不会探测、下载或提示 Go，普通用户看不到任何迁移入口。迁移代码仅为后续版本保留，维护者验证时才显式传入内部参数 `--internal-bridge-offer`。
- **迁移动作**：候选二进制 SHA256 + ELF 校验 → 只读审计与完整变更摘要 → 快照/journal → `xray -test` / `nginx -t` 预验收 → 原子切换 `/usr/bin/idleleo` → 精确移除 4 条项目 cron → 安装 `idleleo-schedule.timer`。
- **保留内容**：`/etc/idleleo` 配置、证书与私钥、用户、用户自定义 cron、nginx 自定义片段。
- **回滚**：任一步失败由 `/opt/idleleo/recovery/idleleo-recover` 恢复；已 `COMMITTED` 后不隐式逆向迁移。
- **定时任务**：`idleleo schedule status` 查看，`install` / `remove` / `run` 管理。GeoData 刷新与统计采集已原生实现（systemd timer 驱动）；自动更新改用 Go release 通道，**必须显式 `idleleo update configure --manifest-url URL`**，未配置时每轮记录 `degraded`（不猜测来源，也不静默失败）；证书续期仍无 ACME，只做外部续约后的指纹契约与到期告警。
- **Phase 04 新增命令**：`idleleo update status|check|apply|configure`、`idleleo stats [--json]`、`idleleo service status|start|stop|restart|reload|logs`、`idleleo rill status`。服务命令只允许自有 unit；`stats` 只读查询，不支持 watch/reset。
- **证书契约**：记录证书 DER 指纹基线；只有指纹变化才 `restart xray` / `reload nginx`，未变化不重启；world-readable 私钥拒绝 reload；到期或 <30 天未变化记录 `degraded`。**真实 ACME 签发/续期/清理未实现**。
- **自定义内容**：审计列出的未知 Xray 顶层键与自定义 nginx 片段必须先人工确认，否则 `prepare` 以 exit 6 拒绝，不做静默覆盖。

## 故障排查

| 现象 | 先检查 | 处理建议 |
|---|---|---|
| 安装被拒绝 | `/etc/os-release` 与系统支持矩阵 | 升级到受支持的系统版本，或改用 Debian/Ubuntu |
| Xray 未运行 | `systemctl status xray`、`idleleo --xray-error` | 查看 `journalctl -u xray`，检查配置和端口占用 |
| 配置语法错误 | `xray run -test -config /etc/idleleo/conf/xray/config.json` | 按输出修正配置，必要时用 `idleleo --restore` 回滚 |
| 端口被占用 | `ss -ltnp` | 释放端口，或在菜单中变更监听端口 |
| 证书异常 | `idleleo --cert-status` | 检查域名解析、80/443 端口和 ACME 状态，再执行 `idleleo --cert-update` |
| 与已有 Nginx 冲突 | `/usr/local/nginx/sbin/nginx -V`、`systemctl status nginx` | 不要在 LNMP 等脚本安装的 Nginx 上混装，先清理冲突 |
| 统计返回 `2` | 菜单中的统计开关、Xray 状态、`127.0.0.1:10085` | 开启统计、启动 Xray，或检查 `api.listen` |
| 统计返回 `3` | API 返回内容和 JSON 结构 | 检查 Xray 日志与配置，确认 StatsService 可用 |
| 统计返回 `5` | 当前用户 | 使用 root 执行，或检查文件权限 |
| Clash 缺少节点 | 协议类型 | Clash 不支持 xHTTP，改用支持 xHTTP 的客户端 |

日志与诊断入口：`/etc/idleleo/logs/`、`/var/log/xray/`、`idleleo --show`、`idleleo --xray-access`、`idleleo --xray-error`。

## 常见问题

**统计能看到活动连接数吗？** 不能。StatsService 只提供 inbound 上行/下行与 Uptime 等计数，不提供连接数。

**Cloudflare 用户什么时候开启 CDN？** 建议在安装完成、证书和直连验证通过后再开启 CDN，避免申请证书时被 CDN 代理干扰。

**IPv4 和 IPv6 可以同时使用吗？** 可以。脚本会检测公网出口能力，并按域名 A/AAAA 记录分别校验；双栈环境建议同时配置正确的 A 与 AAAA。

**如何修改端口、UUID 或传输方式？** 进入菜单“配置变更”，或重新运行安装向导选择重配置路径。涉及传输结构变更时使用标准模板重建。

**如何卸载？** 执行 `idleleo --purge`。卸载前建议先 `idleleo --backup`，并确认是否需要保留配置和证书。

**自定义字符串映射到 UUID 有什么要求？** 使用 UUIDv5 映射，需要客户端支持该特性；不支持时请使用标准 UUID。

**可以在生产环境直接使用吗？** 请先在测试环境验证连通性、证书续期、备份恢复和升级路径，再用于生产。

## 安全提示

- 统计 API 只绑定 `127.0.0.1`，但没有鉴权；不要把 `10085` 暴露到公网，也不要让不可信的本机用户访问。
- Reality + Nginx 模式默认启用 SNI Guard：未知 SNI、空 SNI 与异常 TLS 不会进入 Xray Reality 后端，默认使用 `ssl_reject_handshake` 隔离。
- Fail2ban、防火墙和流量阻断是可选加固项，启用前请确认不会误封自己的管理入口。
- 备份包、证书和客户端配置都包含敏感信息，请限制文件权限并避免公开分享。
- 脚本需要 root 权限；不要在未验证可用性前用于生产环境。

## 目录与服务

| 内容 | 路径 |
|---|---|
| 主目录 | `/etc/idleleo` |
| Xray 配置 | `/etc/idleleo/conf/xray/config.json` |
| Nginx 配置 | `/etc/idleleo/conf/nginx/` |
| 脚本状态配置 | `/etc/idleleo/conf/install_config.json` |
| 证书文件 | `/etc/idleleo/cert/xray.key`、`/etc/idleleo/cert/xray.crt` |
| 日志目录 | `/etc/idleleo/logs/`、`/var/log/xray/` |
| Nginx 安装目录 | `/usr/local/nginx` |
| 管理命令 | `/usr/bin/idleleo` |
| 安装信息文本 | `/etc/idleleo/info/xray_info.inf` |

| 操作 | 命令 |
|---|---|
| 启动 Xray | `systemctl start xray` |
| 停止 Xray | `systemctl stop xray` |
| 启动 Nginx | `systemctl start nginx` |
| 停止 Nginx | `systemctl stop nginx` |

## Docker 与 AI Skill

Docker 镜像预装 Xray、Nginx 与主脚本，容器内可以使用原脚本功能。详见 [Docker 部署指南](https://github.com/hello-yunshu/Xray_bash_onekey/blob/main/docker/DOCKER.md)。

```bash
git clone https://github.com/hello-yunshu/Xray_bash_onekey.git
cd Xray_bash_onekey
docker compose up -d
docker attach xray-onekey
```

AI Skill 适合让支持 Skill 的 AI 工具自动完成部署，无需逐项回答交互问题。详见 [Xray_bash_onekey_skill](https://github.com/hello-yunshu/Xray_bash_onekey_skill)。

脚本支持 Reality、TLS、ws/gRPC/xHTTP ONLY 和 Nginx Stream 中转节点。AI Skill 的自动部署模板当前只覆盖 Reality 与 TLS；ws/gRPC/xHTTP ONLY 与中转节点请在服务器上用 idleleo 完成。

## RillML Xray AI 运维助手

RillML（简称 Rill）为 Xray 提供本地自适应智能运维能力：实时监控 Xray/Nginx 健康状态，自动诊断故障并给出处理建议，无需外部 API。主菜单输入 `9` 或执行 `idleleo --rill-agent` 进入。

| 操作 | 命令 |
|---|---|
| 打开 AI 运维助手菜单 | `idleleo --rill-agent` |
| 安装或修复 AI 判断引擎 | `idleleo --rill-agent-install` |
| 查看 AI 判断状态 | `idleleo --rill-agent-status` |
| 运行 AI 故障诊断 | `idleleo --rill-agent-diagnose` |
| 校验 AI 判断引擎 | `idleleo --rill-agent-verify` |
| 安全停用 AI 判断 | `idleleo --rill-agent-safe-disable` |
| 卸载 Rill AI 引擎 | `idleleo --rill-agent-uninstall` |

Rill 默认以诊断建议为主，未开启自动修改前不会更改系统。

## 延伸阅读

- `idleleo` 命名背景：[迷雾后的真容](https://github.com/hello-yunshu/Xray_bash_onekey/wiki/%E8%BF%B7%E9%9B%9C%E5%90%8E%E7%9A%84%E7%9C%9F%E5%AE%B9)
- Reality 安装指南：[搭建 Xray Reality 服务器](https://hey.run/posts/da-jian-xray-reality-xie-yi-fu-wu-qi)
- Reality 协议风险：[Xray Reality 协议的风险](https://hey.run/posts/reality-xie-yi-de-feng-xian)
- Reality 加速服务器：[利用 Reality 协议“漏洞”加速服务器](https://hey.run/posts/use-reality)
- 交流群：[Telegram](https://t.me/+48VSqv7xIIFmZDZl)
- 官方文档：[Xray 文档](https://xtls.github.io)

## 许可证与致谢

本项目使用 [GPL-3.0](https://github.com/hello-yunshu/Xray_bash_onekey/blob/main/LICENSE) 许可证。感谢 JetBrains 提供非商业开源开发授权。

- 基于 [wulabing/V2Ray_ws-tls_bash_onekey](https://github.com/wulabing/V2Ray_ws-tls_bash_onekey) 开发。
- TCP 加速脚本引用自 [ylx2016/Linux-NetSpeed](https://github.com/ylx2016/Linux-NetSpeed)。
- 分享链接方案参考 [@DuckSoft](https://github.com/DuckSoft) 的[提案](https://github.com/XTLS/Xray-core/issues/91)，UUIDv5 与 REALITY 相关内容参考 [XTLS](https://github.com/XTLS/Xray-core/issues/158) 提案。
- 感谢 Xray-core、Nginx、Let's Encrypt 等上游项目。

作者：云舒。项目仅提供有限支持，请先阅读文档并保留备份后再操作生产环境。
