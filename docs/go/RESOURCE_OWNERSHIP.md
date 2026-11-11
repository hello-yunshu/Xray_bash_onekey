# Phase 00 — 系统资源所有权表

> 依据：`4752f77` 完整 Bash 源码（`install.sh`、`scripts/`、`docker/`、`config/`），
> 以及本轮真实文件读取。行号链接指向当前 `develop/go-native`（与基线行为一致）。
> 本表回答两个问题：Bash **现在实际写什么**；Go 迁移后**谁拥有、能否删除**。

## 1. 所有权模型

| 类型 | 含义 | Go 迁移规则 |
|---|---|---|
| `OWNED_PROJECT` | 脚本创建、脚本独占、可安全删除 | 可删除；删除前必须按指纹/标记校验 |
| `OWNED_PROJECT_SHARED` | 脚本创建但会被用户修改（如 xray config、install_config） | 可改写，但必须保留用户字段并走事务 |
| `USER_OWNED` | 用户/其他软件所有 | **只读**；迁移不得覆盖或删除 |
| `SYSTEM_SHARED` | systemd、crontab、iptables、limits、SELinux、fail2ban 全局配置 | 只能最小化、可审计地变更；默认不碰全局策略 |
| `EPHEMERAL` | 锁、临时目录、运行中标记 | 可清理，但必须带超时/所有权判断 |

## 2. 文件与目录

| 路径 | 类型 | 谁写 | 现状与备注 |
|---|---|---|---|
| `/etc/idleleo/` | OWNED_PROJECT | 安装器 | 根目录；备份/恢复的根 |
| `/etc/idleleo/conf/install_config.json` | OWNED_PROJECT_SHARED | `install_config_*` | **0600**；Bash 元数据层；字段见 `CONFIG_BRIDGE_CONTRACT.md` |
| `/etc/idleleo/conf/xray/config.json` | OWNED_PROJECT_SHARED | 安装器/更新 | 实际运行的 Xray 配置；用户可能手改 |
| `/etc/idleleo/conf/xray/status_config.json` | OWNED_PROJECT | `xray_status_add/del` | 统计/API 开关的叠加层 |
| `/etc/idleleo/conf/nginx/*.conf` | OWNED_PROJECT_SHARED | 安装器 | 项目 Nginx 片段；不得改写用户其它片段 |
| `/etc/idleleo/conf/rill-*`、`/etc/rill-xray-agent/` | OWNED_PROJECT | Rill 适配层 | 仅 Rill 功能使用 |
| `/etc/idleleo/scripts/` | OWNED_PROJECT | 安装器 | `auto_update.sh`、`geo_update.sh`、`ssl_update.sh` 等 |
| `/etc/idleleo/info/xray_info.inf` | OWNED_PROJECT | 安装器 | **0600**；`--show` 读取；Bash 解析时对不可信字段做校验 |
| `/etc/idleleo/info/xray_info_clash.yaml` | OWNED_PROJECT | 安装器 | 分享用 |
| `/etc/idleleo/logs/`、`/var/log/xray/` | OWNED_PROJECT / LOG | 安装器、Xray | 日志清理只处理项目文件 |
| `/etc/idleleo/cert/` | OWNED_PROJECT_SHARED | acme.sh + 安装器 | `xray.crt`、`xray.key`、`decoy.*`；权限 640、组 `idleleo-nginx` |
| `/etc/idleleo/tmp/` 与 `/etc/idleleo/*.tmp` | EPHEMERAL | 安装器 | 事务暂存；异常退出可能残留 |
| `/etc/idleleo/ssl_update_running` | EPHEMERAL | `ssl_update.sh` | 目录型锁，120 分钟过期 |
| `/usr/local/etc/xray/config.json` | SYSTEM_SHARED | 安装器 | 指向 `/etc/idleleo/conf/xray/config.json` 的软链 |
| `/usr/local/share/xray/` | SYSTEM_SHARED | 安装器/旧版本 | 旧版为真实目录；恢复旧备份时需自愈为软链 |
| `/usr/local/bin/xray` | SYSTEM_SHARED | 安装/更新 | 二进制；升级时原子替换 |
| `/usr/local/bin/idleleo` | OWNED_PROJECT | 安装器 | 指向本脚本的软链 |
| `/usr/local/nginx/` | USER_OWNED / SYSTEM_SHARED | 安装器 | 第三方 Nginx 构建；安装器只改项目配置与 sbin |
| `/root/.acme.sh/` | USER_OWNED | acme.sh | 证书账户与自有 cron；迁移只读/调用，不接管目录 |
| `/run/lock/idleleo-update.lock` | EPHEMERAL | 安装/更新/证书 | `flock` 跨脚本互斥 |

## 3. systemd 单元

| 单元 | 类型 | 当前行为 | Go 迁移规则 |
|---|---|---|---|
| `/etc/systemd/system/xray.service` | OWNED_PROJECT（落盘） | 安装器写入、启停 | 可重写，但需保留用户 `override.conf` |
| `/etc/systemd/system/nginx.service` | SYSTEM_SHARED | 项目定制 Nginx | 只改项目需要的部分；失败回滚 |

服务操作必须记录原状态（`is-active` / `is-enabled`），失败时恢复原状态（F11）。

## 4. crontab / 定时任务

| 条目 | 写入方式 | 风险 | Go 规则 |
|---|---|---|---|
| `0 1 * * * bash "/etc/idleleo/scripts/auto_update.sh"` | [`install.sh#L7296`](../../install.sh#L7296) | 无 PATH；整行按 `auto_update.sh` 字符串删除 | 用带所有权标记的独立行；只删自己的行 |
| `acme.sh --cron`（由 acme.sh 自管） | `/root/.acme.sh` | 不属于本项目，不能删除 | **不得接管**；只调用、只读 |
| GeoData 自动刷新 `0 3 * * 1` | 写入 Xray 原生 geodata 状态（[`install.sh#L5080`](../../install.sh#L5080)） | 与旧 `geo_update.sh` cron 可能重复 | fail-closed：启用原生前保留旧任务；迁移成功后再移除 |
| 卸载清理 | [`install.sh#L10948-L10951`](../../install.sh#L10948) | `sed -i "/auto_update.sh/d"`、`"/geo_update.sh/d"` 是**子串级**删除 | 必须改为指纹级删除 |

## 5. 网络与防火墙

| 资源 | 现状 | Go 规则 |
|---|---|---|
| `iptables` / `ip6tables` | 流量阻断/防火墙同步直接写链（[`scripts/file_manager.sh`](../../scripts/file_manager.sh#L160-L215)） | 先构建期望规则集，再单事务应用；失败回滚；不碰非项目链 |
| Xray 监听端口 | 端口安全校验 + `ss` 检查 | 只改项目配置；冲突时拒绝而不是抢占 |
| Nginx `stream` | 中转节点写 `relay-stream.conf` | 只写项目文件；不创建 Xray/UUID/证书 |
| DNS | 用户 DNS/DoH 存在 Xray 配置中 | 迁移只读解析，保留用户 `dns.servers` |

## 6. 全局安全策略（**必须默认不动**）

| 资源 | Bash 现状 | 迁移口径 |
|---|---|---|
| `/etc/security/limits.conf` | `basic_optimization` 追加内核/文件句柄参数，安装时调用 | **不默认改写**；仅进程级或明确授权（D2） |
| SELinux | `setenforce 0` + 改 `/etc/selinux/config` | **不默认禁用**；报告状态，用户显式选择（D2） |
| `/etc/fail2ban/jail.d/*.local` | 卸载执行 `rm -f /etc/fail2ban/jail.d/*.local`（[`scripts/fail2ban_manager.sh`](../../scripts/fail2ban_manager.sh#L1087-L1101)） | 只删带项目标记的文件，其余保留并报告（D1） |
| `/etc/fail2ban/jail.d/idleleo*.local` | 项目 jail | 项目独占，可删 |

## 7. Docker / Rill 交付物

| 资源 | 现状 | Go 规则 |
|---|---|---|
| `/usr/local/sbin/fake-systemctl`、`/etc/systemd/system/fake-systemctl.service` | Docker 中模拟 systemd | 迁移沿用假 systemd，**不假设宿主 DBus 可用**（R16） |
| `/var/lib/rill-xray-agent*` | Rill 状态 | 项目独占；卸载必须可审计 |
| `/etc/rill-xray-agent/` | Rill 配置 | 项目独占；不得覆盖系统其它 agent |

## 8. 删除语义与安全边界

1. 任何删除前先确认 `OWNED_PROJECT` 或带项目标记；`USER_OWNED`/`SYSTEM_SHARED` 默认拒绝删除。
2. 卸载不得使用目录通配删除（`jail.d/*.local`、`/etc/idleleo/*` 之外的 glob）。
3. 备份/恢复必须保留：自定义 DNS、routing、outbounds、证书、密钥、用户 Nginx 片段。
4. 旧目录迁移（`/usr/local/share/xray`）必须 **fail-closed**：发现非普通文件（目录/软链/设备）时保留原目录、保留备份、明确报错，不能「迁移成功」后丢数据。
5. 事务暂存与锁必须带所有权与超时；异常退出后可恢复，不能静默覆盖新改动。

## 9. Go 迁移实现状态（S0–S3 收尾）

前 8 节描述 Bash 基线的所有权与 Go 的迁移规则；本节记录 Go 侧**已经落地**的部分，
用于核对文档与现实是否一致。

| 资源 | 当前所有者 | 状态 |
|---|---|---|
| `/etc/idleleo/v1/metadata.json` | Go（安装器写一次） | 已实现；Bash 只读，缺字段直接报错，不回退默认值 |
| `/etc/idleleo/` 其余布局 | Bash | 不变；Go 不接管 `conf/`、`info/`、`logs/` |
| `/var/lib/idleleo/transactions/phase01.json` | Go | 已实现；有界事务记录（不含配置字节/密钥），供 `change recover` 重放 |
| `/var/lib/idleleo/deploy/` | Go | 已实现；部署状态与暂存，失败回滚 |
| `/run/lock/idleleo-update.lock` | Go / Bash 共用 | 沿用 Bash 锁名，切换窗口内不会出现两个写者 |
| systemd 单元（xray/nginx） | 系统 | Go 只通过 `systemctl` 操作，不直接写单元文件 |
| `/root/.acme.sh`、用户 `wwwroot` | USER_OWNED | 不变；Go 证书写入 `/etc/idleleo/cert`，不碰用户 acme 目录 |

`install.sh -u` 在 Go 元数据存在时直接拒绝（S1），因此 **Go 接管后的主机上 Bash 不会再
改写任何上面列出的资源**；Bash 仅在 Go 未安装的旧主机上保留原有所有权。
