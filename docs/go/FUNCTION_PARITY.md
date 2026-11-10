# Phase 00 — F01–F28 功能迁移矩阵与 CLI 对照

> 本文件是 Phase 00 的**事实基线**，不是迁移完成声明。
> 行为基线：`4752f77` 的完整 Bash 源码（`install.sh` + `scripts/` + `config/`），
> `install.sh` SHA-256 `0af8e8f222f26f02904f80bfd0e3cf5cd119b24bbde462019f0b582e1b79cfa6`。
> 当前 `main` 为 `04d76c2`（v3.3.6 之后追加了一次自动翻译提交；tag `v3.3.6`
> 指向 `0fa7052e`）。与 `4752f77` 相比，`install.sh` 只差“删除 `-u` 死标志”
> 一行与版本号，`scripts/`、`config/` 无差异。
> **2026-11-11 状态**：在 2026-11-08 固定 digest 容器复跑（Phase 01–04：
> **33/35、36/36、219/219、42/42**，见 [DOCKER_MIGRATION_ACCEPTANCE.md](DOCKER_MIGRATION_ACCEPTANCE.md)）
> 之上，修复分支补齐 `idleleo tcp`、Reality 主备容器 e2e 与原生 ACME（本地 CA）。
> F04 由「未实现」升为「部分实现（容器级）」，F12 由「未实现（有到期监控）」升为
> 「部分实现（本地 CA）」，F25 由「未实现」升为「部分实现（容器级）」；其余 25 项状态不变，
> 正式签收仍 **0/28**。Phase 01 的 C12.1/C12.2 仍为红：`2d44d98` 的 logrotate
> `ReadWritePaths` 修复在 v3.3.6 发布后修改了 `install.sh`（+26/−1），本轮不篡改 pin，差异如实保留。
> `4752f77` 仍是 F01–F28 的**行为基线**（3.3.6 仅删除了一行不可达的 `-u` 死标志，
> 行为未变）。本仓库中**存在 Phase 01 候选 Go 管理器**（`cmd/idleleo`，只在隔离
> 沙盒执行变更），它不是生产替代品；`tests/go-parity/prototype` 仍只是参考原型。

## 1. 状态定义

| 标签 | 含义 |
|---|---|
| **已验证** | 有可重复执行的证据，且在本轮真实运行过；**只描述 Bash 基线**，不等于 Go 已迁移 |
| **未实现** | 没有生产 Go 代码。Phase 00 的 28 项全部属于此类（Go 侧） |
| **未验证** | Go 代码存在但缺少证据（当前没有这种项） |
| **部分实现（容器级）** | Phase 01 有 Go 代码并已在固定 digest 容器内真实执行；只覆盖该功能的一个原语/子集，**不是完整 Bash 行为等价**，也不是真实 VPS 验证 |
| **已批准的安全差异** | 已记录、已批准「Go 不复制 Bash 危险行为」的口径，见第 5 节 |

**提示词包 C5 标签映射**（本文件沿用历史标签，逐项对外换算如下）：

| 本文件标签 | 提示词标签 | 说明 |
|---|---|---|
| 已验证（仅 Bash 基线） | 不换算 | 不得写成 Go `IMPLEMENTED`；Go 侧按实际标 `NOT_IMPLEMENTED` 或 `PARTIAL` |
| 部分实现（容器级） | `TESTED_CONTAINER` + `PARTIAL` | 容器内真实执行，但只覆盖子集；不是生产签收 |
| 未实现 | `NOT_IMPLEMENTED` | 无生产 Go 代码 |
| 未实现（有到期监控）F12 | `BLOCKED` | 容器无公网域名/CA，只验证外部续约契约 |
| 未实现（F20 已批准差异） | `APPROVED_SAFETY_DIFFERENCE` | 不复制 Bash 的 `jail.d` 删除行为 |

**结论：F01–F28 的 Go 迁移状态无一为「已验证」。** Phase 02 后在固定 digest 容器内把
F01/F02/F03/F05/F06/F07/F08/F11/F18/F19/F27/F28 推进到「部分实现（容器级）」；
Phase 03 把 F26、F14、F15、F16、F22 推进到「部分实现（容器级）」。
Phase 04 只加强 F11/F12/F14/F15/F22/F27/F28 的**容器级证据**，**没有改变任何状态标签**。
2026-11-08 的 A–D 轮次复跑 Phase 01–04（33/35、36/36、219/219、42/42），并新增
`idleleo tcp`：F25 由「未实现」升为「部分实现（容器级）」，其余标签不变。
其中 F01 的 fresh install、systemd、Reality 数据面，F05 的 Nginx stream 转发，
F06 的事务/回滚/故障注入，F19 的保留配置重装，F14/F16 的原生 systemd timer +
Xray GeoData 刷新，F15 的真实 Stats API 采集，F22 的 Rill 状态/交接，F25 的
TCP 事务/回退均有实测证据。
这些仍只是容器级子集，不是真实 VPS 验证，也没有任何一项升格为「已验证」。

**2026-11-11 preview 通道（不改变状态标签）**：新增
`tests/go-parity/parity/scripts/check_preview_gate.py` 与
`tests/go-parity/parity/cases/preview_contract.json`，为 **F01、F05、F11、F26、F27、F28**
建立可重复执行的真实夹具，并在固定 digest 容器内各跑两遍全绿。preview 通道显式打印
`PREVIEW — NOT FOR RELEASE`、`release_authority=false`，不写 tag/release；
`check_release_gate.py` 与 `feature_contracts.json` 字节未变，28 项仍为
`PENDING_GO_IMPLEMENTATION`。因此：**可执行夹具 6/28，仍缺 22 个；正式签收仍 0/28**；
`preview_contract.json` 自身保持 `PENDING_PREVIEW`，不因夹具通过而升格。F27 的
`backup/restore` 与 F28 与 Bash 的逐字段差分仍记为未验证。

> **判定口径（2026-11-06 用户明确授权）：** 真实公网 VPS 不再是本轮阻塞项，
> `CONTAINER_VERIFIED`（固定 digest 容器内真实执行并记录）即视为出口门槛满足；
> `REAL_VPS_VERIFIED` 保留为更高等级但不再强制。真实 ACME 因容器内无公网域名/CA 条件，
> **降级为“不纳入本轮验收”**。等级标签必须如实保留：容器结果不得写成“真实 VPS 已验证”。

## 2. Bash CLI 对照表（实测自 `show_help` 与入口分派）

只读命令在 root gate 之前执行；`-s/--show` 例外地要求 root（信息文件为 0600）。
分类来自 [`is_pure_readonly_command`](../../install.sh#L15903) 与
[`dispatch_offline_root_mutation_command`](../../install.sh#L15963)。

| 命令 | 分类 | 是否需要网络 | 是否写系统 | 备注 |
|---|---|---|---|---|
| `-h`, `--help` | 纯只读 | 否 | 否 | 在语言/完整性/依赖检查之前 |
| `-s`, `--show` | 纯只读（需 root） | 否 | 否 | 读 `/etc/idleleo/info/xray_info.inf`（0600） |
| `--access-log`, `--error-log`, `-xa`, `-xe` | 纯只读 | 否 | 否 | 读 `/var/log/xray/*.log` |
| `--stats`, `--stats-watch`, `--stats-reset` | 纯只读 / 变更 | `--stats` 需本机 API | reset 写统计状态 | `--stats-reset` 属于 root mutation |
| `--rill-agent-status/diagnose/timeline/auto-status` | 纯只读 | 否 | 否 | Rill 适配层 |
| `--rill-integration-self-check` | 纯只读 | 否 | 否 | 输出 JSON 契约 |
| `--service-start/stop/restart` | root mutation | 否 | 是 | systemd |
| `--backup`, `--restore` | root mutation | 否 | 是 | `/etc/idleleo` 备份 |
| `--purge`, `--uninstall` | root mutation | 否 | 是 | 两阶段卸载 |
| `--stats-reset` | root mutation | 否 | 是 | 重置计数器 |
| `--rill-agent`, `--rill-agent-safe-disable/verify/route-stage/...` | root mutation | 视动作 | 是 | 授权/熔断 |
| `--internal-geodata-migrate-legacy` | root mutation | 否 | 是 | 旧布局一次性迁移 |
| `-1`, `--install-tls` | 在线 root mutation | 是 | 是 | ws/gRPC/xHTTP |
| `-2`, `--install-reality` | 在线 root mutation | 是 | 是 | Reality ± Nginx |
| `-3`, `--install-none` | 在线 root mutation | 是 | 是 | ws ONLY，需二次确认 |
| `--install-relay` | 在线 root mutation | 是 | 是 | 仅 Nginx Stream |
| `-4`, `--install-xtls` | 拒绝 | 否 | 否 | 明确返回 1：旧模式已取消 |
| `-5`, `--add-upstream` | root mutation | 否 | 是 | 写 Nginx 上游片段 |
| `-6`, `--add-servernames` | root mutation | 否 | 是 | 写 `serverNames` |
| `-sg`, `--sni-guard` | root mutation | 否 | 是 | SNI guard 策略 |
| `-au`, `--auto-update` | root mutation | 是 | 是 | 安装/更新 cron |
| `-c`, `--clean-logs` | root mutation | 否 | 是 | 日志清理 |
| `-cs`, `--cert-status` | 只读为主 | 否 | 否 | 以文件 mtime 推算（R08） |
| `-cu`, `--cert-update` | 在线 root mutation | 是 | 是 | 手动续期 |
| `-cau`, `--cert-auto-update` | root mutation | 是 | 是 | acme cron |
| `-f`, `--set-fail2ban` | root mutation | 否 | 是 | 启用项目 jail |
| `--fail2ban-list/unban/trust-add/trust-del` | root mutation | 否 | 是 | CLI 子命令 |
| `-tb`, `--traffic-blocker` | root mutation | 否 | 是 | Xray 路由/iptables |
| `-l`, `--language` | root mutation | 否 | 是 | 交互设置 |
| `-n`, `--nginx-update` | 在线 root mutation | 是 | 是 | 支持 `auto_update` |
| `-p`, `--port-reset` | root mutation | 否 | 是 | 端口 |
| `-pt`, `--port-traffic` | 只读工具 | 否 | 否 | iftop |
| `-u`, `--update` | 在线 root mutation | 是 | 是 | 支持 `auto_update` / `--yes` / `--allow-major` |
| `-t`, `--target-reset` | root mutation | 否 | 是 | Reality target |
| `-tcp`, `--tcp` | 在线（浮动脚本） | **是** | 是 | 下载 `tcp.sh` 后执行（R09/F25） |
| `-tls`, `--tls` | root mutation | 否 | 是 | TLS 变更，`sed -i`（R07） |
| `-uu`, `--uuid-reset` | root mutation | 否 | 是 | UUID |
| `-x`, `--xray-update` | 在线 root mutation | 是 | 是 | 支持 `auto_update` |
| `1`–`35` / 无参数 | 交互菜单 | 启动阶段会联网 | 视选项 | R05：启动即 `check_online_version_connect`，网络失败 `exit 1` |
| `--rill-agent-install` | 在线 root mutation | 是（可回落） | 是 | 先本地载荷，失败再下载 |
| `--json` | `--stats` 子参数 | 同 `--stats` | 否 | 输出契约见 F15 |

## 3. F01–F28 矩阵

「Bash 证据」列引用现有 `.github/test/` 测试或本轮实际验证；「Go 状态」列是本阶段唯一权威状态。

| ID | Bash 功能 | Bash 证据 | Bash 状态 | Go 状态 | 迁移备注 |
|---|---|---|---|---|---|
| F01 | `--install-reality`，普通/加 Nginx | `test_install`、`test_true_fresh_install`、`test_reality_nginx_feedback`、CI job `Install (reality)` | 已验证 | 部分实现（容器级） | 容器内 fresh install 真实验证：systemd `active/enabled`、`User=xray`、`xray -test`、Reality 客户端隧道取回 HTTP；`reality-nginx` 仅配置生成 + `-test`，未做 Nginx 安装；preview 夹具 `F01_test.py` 全绿 |
| F02 | `--install-tls` ws/gRPC/xHTTP/组合 | `test_install`、`test_true_fresh_install`、CI job `Install (ws_grpc_xhttp)` | 已验证 | 部分实现（容器级） | 容器内生成 ws/gRPC/xHTTP 配置并通过真实 `xray -test`；TLS 安装需要真实域名/证书，未纳入本轮验收 |
| F03 | `--install-none`，ws ONLY | `test_ws_only_listen_address`、`test_install_menu_profiles` | 已验证 | 部分实现（容器级） | 容器内生成 none+ws 配置并通过 `xray -test`；保留「显式非回环确认」并实测 exit 2、零落盘 |
| F04 | Reality primary/secondary 负载均衡 | `test_install_menu_profiles`、`test_reality_nginx_feedback` | 部分验证 | 部分实现（容器级） | `--mode reality-balance --role primary/secondary` 生成真实 Nginx stream + 两个真实 Xray Reality 后端；容器 e2e（真实 nginx、真实客户端）验证轮询命中、secondary 宕机时 primary 全量承载、重启后重新加入、未知 SNI 拒绝（`tests/go-parity/evidence/balance-e2e-2026-11-08`）。**未在真实 VPS 双机验收**，生产签收仍需两台主机 |
| F05 | `--install-relay`，独立中转 | `test_relay_node`、`test_relay_container`、CI job `Install (relay)` / `True Fresh Mode (relay)` | 已验证 | 部分实现（容器级） | 生成 Nginx `stream` 片段；`nginx -t` 通过；真实容器网络内 PING 经 stream 转发回显；仍不能创建 Xray/UUID/证书；preview 夹具 `F05_test.py` 全绿 |
| F06 | 用户查看/添加/删除、UUIDv5 | `test_install`、`test_reinstall_preservation` | 部分验证 | 部分实现（容器级） | `user list/add/remove` 走事务并真实重启服务；主用户保护、重复拒绝、write-fail/service-fail 回滚已实测；UUID 为随机 v4，**未实现 UUIDv5**；Phase 03 迁移保留 4 用户逐字节不变 |
| F07 | shortId / spiderX / 用户映射 | `test_reality_min_client_ver`、`test_reinstall_preservation` | 部分验证 | 部分实现（容器级） | 新增用户可追加 Reality `shortId`；分享 URI 带 `sid/spx`；未实现完整用户映射管理 |
| F08 | 端口、target、serverNames、SNI Guard | `test_port_safety`、`test_port_validation`、`test_install_menu_profiles` | 已验证 | 部分实现（容器级） | `set-inbound-port` 原语、serverNames/target 校验与生成、非法 serverName fail-closed；SNI Guard 未实现 |
| F09 | `--add-upstream`，上游片段管理 | `test_nginx_security`、`test_reinstall_preservation` | 部分验证 | 未实现 | 只允许改写项目片段 |
| F10 | `--tls` 版本变更 | `test_nginx_security`、`test_nginx_update_rollback` | 部分验证 | 未实现 | R07：当前是 `sed -i` 后重启 |
| F11 | 服务状态/启停/日志 | `test_offline_commands`、`test_phase1_safety` | 已验证 | 部分实现（容器级） | Phase 04 新增 `service status/start/stop/restart/reload/logs`，仅限自有 unit；容器内实测 `xray=active`、restart 计数 3→4、stop/start、journal 日志、非法 unit exit 2、sandbox root 拒绝 exit 2；preview 夹具 `F11_test.py` 全绿 |
| F12 | 证书状态/签发/续期/清理 | `test_cert_update_recovery`、`test_ssl_update_recovery` | 部分验证 | 部分实现（本地 CA） | 原生 ACME v2 客户端（ES256/JWS/nonce/订单/HTTP-01）在 Pebble 本地 CA 上真实签发、窗口内跳过、强制续期；证书对原子替换（temp+fsync+rename），私钥 0600/证书 0644，`--reload-command` 失败回滚旧证书对且回滚后仍通过链/SAN/私钥匹配校验；负面覆盖 webroot 失效、reload 失败、只读目标、CA 拒绝域名（`tests/go-parity/evidence/acme-2026-11-08-fix`）。**公网 CA、DNS-01、EAB、真实域名与 Bash 的 `idleleo-nginx` 组/重启语义未验收**，不得据此升格 |
| F13 | `--update`、`--xray-update`、`--nginx-update` | `test_xray_update_transaction`、`test_nginx_update_rollback`、`test_candidate_real_upgrade` | 已验证 | 未实现 | 需哈希/降级/失败注入 |
| F14 | `--auto-update` 与 cron | `test_vps_auto_update_schedule`、`test_legacy_auto_update_path`、`test_auto_update_failure_records` | 已验证 | 部分实现（容器级） | Phase 03 新增原生 `idleleo schedule`：systemd timer 接管 GeoData/统计。Phase 04 接入 Go release 通道：配置后容器内真实定时升级 `0.3.0→0.4.0`。**P0-5 修正**：Go 无 Xray/Nginx 自动更新执行器，迁移保留旧 `auto_update.sh` cron（只移除 `geo_update.sh`/`xray_stats.sh`）；未配置 Go 通道只影响 Go 自身升级，`degraded` 不删除 cron；cert-renew 未接原生 ACME（签发/续期命令存在，仅本地 CA 验证，见 F12），`ssl_update.sh` 同样保留 |
| F15 | `--stats` / `--json` / watch / reset | `test_xray_stats_readout`（真实 Xray API）、`test_xray_stats` | 已验证 | 部分实现（容器级） | `stats-collect` 用真实 `xray api statsquery` 写 `stats.json`。Phase 04 新增只读 `idleleo stats`：真实调用 `xray api statsquery`、`--json` 原样输出、非 root exit 5、API down exit 8；**watch/reset 仍未实现**；首次查询瞬态失败见 `BASELINE_AND_CI.md` |
| F16 | GeoData 热更新/手动刷新/旧布局 | `test_geodata_native`（真实 Xray）、`test_geodata_update_path`、`test_restore_geodata_selfheal` | 已验证 | 部分实现（容器级） | `geodata-refresh` 下载双文件→内存校验→原子替换→重启 Xray；容器内用本地固定 origin 实测字节一致，截断下载不覆盖旧文件；旧布局迁移仍未实现 |
| F17 | IPv4/IPv6、DNS、端口、防火墙 | `test_dual_stack`、`test_dns_multi_record`、`test_firewall_ipv6`、`test_firewall_transaction_complete` | 已验证 | 未实现 | R12：iptables 直写未纳入统一事务 |
| F18 | 分享链接/二维码/Clash | `test_clash_yaml`、`test_color_output` | 部分验证 | 部分实现（容器级） | 容器内 `share` 从真实配置派生 URI，实测 `flow/sni/pbk/sid/spx`；Clash 生成存在，xHTTP 明确告警且不伪造；二维码未实现 |
| F19 | 备份/恢复/重配置保留/模式切换 | `test_backup_restore`、`test_backup_permissions`、`test_reinstall_preservation`、`test_restore_geodata_selfheal` | 已验证 | 部分实现（容器级） | 容器内实测卸载保留配置、`--keep-config` 重装后自定义 DNS 逐字节保留；Phase 03 增加 Bridge 快照与故障回滚（入口/unit/配置哈希、精确 cron、schedule units、权限 mode/group），backup/restore CLI 仍未实现 |
| F20 | Fail2ban（含 trusted/unban） | `test_fail2ban` | 已验证 | 未实现 | **已批准差异**：不得 `rm -f jail.d/*.local` |
| F21 | 流量阻断与自定义路由 | `test_firewall_reconcile`、`test_geodata_manual_confirm` | 部分验证 | 未实现 | 规则生成后必须 `xray -test` |
| F22 | Rill 观察/诊断/授权/卸载 | `test_rill_*`（7 个）、CI `rill-qualification` | 已验证 | 部分实现（容器级） | Phase 03 审计/快照/预验收/激活/回滚纳入 Rill 状态与哈希；观测漂移 → validate exit 6。Phase 04 新增只读 `rill status`（absent/active/stale），复用 legacybridge 投影、不写 Rill 状态；**安装/诊断/授权/两阶段卸载命令未迁移**；R03：`.py` 被 `bash` 启动并吞错 |
| F23 | 六语言 | `test_i18n_catalog`、`test_color_output`、CI `i18n.yml` | 已验证 | 部分实现（容器级） | zh/en 完整，fr/fa/ru/ko 回退英文；未与 Bash 文案逐条差分 |
| F24 | Docker 交付 | `test_relay_container`、`test_minimal_bootstrap`、`docker/fake-systemctl` | 部分验证 | 未实现 | R16：不能假设宿主 systemd DBus |
| F25 | TCP 优化/测速 | 无自动化（仅有菜单项） | 未验证 | 部分实现（容器级） | `idleleo tcp status/plan/apply/rollback` 只管理 `/etc/sysctl.d/90-idleleo-tcp.conf`（profile `bbr-fq`）：真实单测 20 项 + Docker sandbox 30 项断言，覆盖幂等、部分失败回滚、journal pending、文件/运行值漂移、符号链接、非 root、内核不支持；**仍不执行 `tcp.sh`、不下载远程脚本、不做测速与性能验收**；Bash 菜单未接线；详见 [TCP_NATIVE_DESIGN_AND_QA.md](TCP_NATIVE_DESIGN_AND_QA.md) |
| F26 | XTLS ONLY 旧模式 | `test_install_menu_profiles`、CI `Relay mixing and legacy-mode guards` | 已验证（只读识别/阻断） | 部分实现（容器级） | Phase 03 容器内实测：audit 识别 `legacy-xtls-removed` 并判定 `blocked`，prepare 拒绝（exit 3），入口/cron 不变、无 journal；按设计不执行迁移；preview 夹具 `F26_test.py` 复验：审计与 prepare 前后全树哈希不变，整棵根下不存在任何 journal 文件 |
| F27 | `--backup/--restore/--purge/--service-*` | `test_offline_commands`、`test_uninstall_clean`、`test_install_uninstall_transaction` | 已验证 | 部分实现（容器级） | 容器内实测 `uninstall` 保留配置、`uninstall --purge` 删除配置/log、systemd 停用；Phase 03 增加“迁移后服务仍 active/enabled + 故障恢复”。Phase 04 实现 `service status/start/stop/restart/reload/logs`；**`uninstall --purge` 已实现并由 preview 夹具 `F27_test.py` 实测（保留配置 / purge 删除配置与自有目录；二次 purge 幂等）；`backup/restore` CLI 仍未实现** |
| F28 | 运行态与分享信息展示 | `.github/test/test_offline_commands.sh` | 已验证 | 部分实现（容器级） | `status/show` 只读视图 + `xray share` 已在容器内真实读取安装结果；Phase 04 额外验证 `help`、`show`、`stats` 只读路径不写 `/etc/idleleo`；preview 夹具 `F28_test.py` 已逐字段断言 `show/status/share` 的 Go 输出契约并证明三个命令零写入，但仍**未与 Bash 逐字段差分** |

## 4. L0 纯函数差分（Phase 00 与 Phase 01 实际执行）

| 项目 | Phase 00（参考原型） | Phase 01（生产源码） |
|---|---|---|
| Oracle | `LIVE_PINNED_CLEAN`（独立 clone，`HEAD=4752f77`） | 同左（独立 clone，`HEAD=4752f77`） |
| Go 侧 | `BUNDLED_TOY_GO_DEMO`（非生产） | `SOURCE_BUILT_NATIVE_GO_L0`（`./cmd/parity-adapter` 导入 `internal/compat`） |
| 用例 | 83 | 83 |
| 通过 | **83 / 83** | **83 / 83** |
| `native_l0_only` | `false` | **`true`** |
| Release 认证 | 否 | 否（`release_certified=false`） |
| 证据 | `tests/go-parity/parity/evidence/functional_parity.json` | `tests/go-parity/parity/evidence/phase01-native-l0/functional_parity.json` |

Phase 00 的 L0 只能说明参考原型的 7 个纯函数行为一致；Phase 01 的 native L0 说明**生产
`internal/compat` 源码**在干净 checkout 中构建并与固定 Bash 基线逐例一致。两者都不覆盖业务功能。

补充：同一轮 `run_stage_gate.py` 的 Bridge 合成契约 39/39 通过（`bridge_cli_contract.json`），但它明确标注
`production_migration_certified=false`，同样不能作为迁移完成依据。

**环境要求（本轮实测）**：在 macOS 默认 `/bin/bash` 3.2 上运行 L0 得到 **0/83**，原因是
`install.sh` 顶层使用 `declare -A` 且无条件 `source /etc/os-release`。
L0 必须在 Linux + bash ≥ 4 下执行（本轮使用 `golang:1.24` 容器内的 bash 5）。这不是 Go 行为差异。

## 5. 已批准的安全差异（Phase 00 口径）

| 编号 | Bash 现状 | Go 必须采用的口径 | 关联 |
|---|---|---|---|
| D1 | `mf_uninstall_fail2ban` 执行 `rm -f /etc/fail2ban/jail.d/*.local`，会删除第三方 jail | 只删除带项目所有权标记的文件；其余保留并报告 | F20 / R02 |
| D2 | `basic_optimization` 默认改写 `/etc/security/limits.conf` 并禁用 SELinux | 默认不改全局内核/安全策略；只做进程级或明确用户授权的变更 | F17 / R04 |
| D3 | `-tcp`、测速菜单从变化的远程 URL 下载脚本并执行 | 不执行未固定哈希的远程脚本；如保留，必须固定 URL+SHA256 且显式确认 | F25 / R09 |
| D4 | 旧 XTLS ONLY 状态可能在机器上存在 | 只读识别并阻断激活，不能「先接管再报错」 | F26 / R18 |

D1–D4 在 `feature_contracts.json` 中仍保持 `PENDING`，因为 Go 实现尚不存在；
批准「差异口径」不等于功能已实现。

## 6. 不可宣称的事项

- 83/83 native L0 只表示 `internal/compat` 的 7 个纯函数与固定 Bash 基线一致；它不是 F01–F28 迁移完成。
- 39/39 Bridge 仍是合成契约，不得当作生产迁移认证。
- 不得用本文件的「已验证」描述 Go；该列只描述 Bash 基线。
- 不得因为 CI 绿灯或容器 35/35 宣布发布就绪；`check_release_gate.py` 在缺少生产 Go 与 22 个功能执行器（28 项中仅有 6 个 preview 夹具）时按设计返回红灯。
- Phase 04 的 42/42 容器 E2E 与双架构产物只加强 F11/F12/F14/F15/F22/F27/F28 的证据描述，
  **不改变任何状态标签**，也不构成发布授权。
- 容器证据一律是 `CONTAINER_VERIFIED`，不得升格为 `REAL_VPS_VERIFIED`。
- preview 通道 6/6 全绿只表示这 6 个夹具真实执行；不得据此修改 `feature_contracts.json`、
  不得写成 `PASS`/「已验证」，也不构成任何发布授权。
