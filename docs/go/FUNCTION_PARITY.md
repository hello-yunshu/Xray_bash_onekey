# Phase 00 — F01–F28 功能迁移矩阵与 CLI 对照

> 本文件是 Phase 00 的**事实基线**，不是迁移完成声明。
> 行为基线：`4752f77` 的完整 Bash 源码（`install.sh` + `scripts/` + `config/`），
> `install.sh` SHA-256 `0af8e8f222f26f02904f80bfd0e3cf5cd119b24bbde462019f0b582e1b79cfa6`。
> 当前 `main` 为 `59a87c6`；与基线相比只多出 CI 测试/工作流 4 个提交，`install.sh`、`scripts/`、`config/` 无差异（`git diff --stat 4752f77 59a87c6 -- install.sh scripts config` 为空）。
> 本仓库中**不存在生产 Go 管理器**；`tests/go-parity/prototype` 只是参考原型，不能被当作实现。

## 1. 状态定义

| 标签 | 含义 |
|---|---|
| **已验证** | 有可重复执行的证据，且在本轮真实运行过；**只描述 Bash 基线**，不等于 Go 已迁移 |
| **未实现** | 没有生产 Go 代码。Phase 00 的 28 项全部属于此类（Go 侧） |
| **未验证** | Go 代码存在但缺少证据（当前没有这种项） |
| **已批准的安全差异** | 已记录、已批准「Go 不复制 Bash 危险行为」的口径，见第 5 节 |

**结论：F01–F28 的 Go 迁移状态全部为「未实现」。** L0 的 83/83 只覆盖 7 个纯函数，不能用来宣布任何业务功能已迁移。

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
| F01 | `--install-reality`，普通/加 Nginx | `test_install`、`test_true_fresh_install`、`test_reality_nginx_feedback`、CI job `Install (reality)` | 已验证 | 未实现 | fixture `reality-direct` / `reality-nginx` 已通过 `xray -test` |
| F02 | `--install-tls` ws/gRPC/xHTTP/组合 | `test_install`、`test_true_fresh_install`、CI job `Install (ws_grpc_xhttp)` | 已验证 | 未实现 | fixture `tls-multi` 已通过 `xray -test` |
| F03 | `--install-none`，ws ONLY | `test_ws_only_listen_address`、`test_install_menu_profiles` | 已验证 | 未实现 | 必须保留「显式非回环确认」 |
| F04 | Reality primary/secondary 负载均衡 | `test_install_menu_profiles`、`test_reality_nginx_feedback` | 部分验证 | 未实现 | 负载均衡无真实双节点验收，Phase 02 补 |
| F05 | `--install-relay`，独立中转 | `test_relay_node`、`test_relay_container`、CI job `Install (relay)` / `True Fresh Mode (relay)` | 已验证 | 未实现 | fixture `relay`；⚠ 不能创建 Xray/UUID/证书 |
| F06 | 用户查看/添加/删除、UUIDv5 | `test_install`、`test_reinstall_preservation` | 部分验证 | 未实现 | R01 的 stop→改→start 不是事务 |
| F07 | shortId / spiderX / 用户映射 | `test_reality_min_client_ver`、`test_reinstall_preservation` | 部分验证 | 未实现 | 需与 F06 原子化 |
| F08 | 端口、target、serverNames、SNI Guard | `test_port_safety`、`test_port_validation`、`test_install_menu_profiles` | 已验证 | 未实现 | 与 F10 共用候选配置校验 |
| F09 | `--add-upstream`，上游片段管理 | `test_nginx_security`、`test_reinstall_preservation` | 部分验证 | 未实现 | 只允许改写项目片段 |
| F10 | `--tls` 版本变更 | `test_nginx_security`、`test_nginx_update_rollback` | 部分验证 | 未实现 | R07：当前是 `sed -i` 后重启 |
| F11 | 服务状态/启停/日志 | `test_offline_commands`、`test_phase1_safety` | 已验证 | 未实现 | 需保留 active/enabled 原状态 |
| F12 | 证书状态/签发/续期/清理 | `test_cert_update_recovery`、`test_ssl_update_recovery` | 部分验证 | 未实现 | 未做真实 ACME；R08/R13 |
| F13 | `--update`、`--xray-update`、`--nginx-update` | `test_xray_update_transaction`、`test_nginx_update_rollback`、`test_candidate_real_upgrade` | 已验证 | 未实现 | 需哈希/降级/失败注入 |
| F14 | `--auto-update` 与 cron | `test_vps_auto_update_schedule`、`test_legacy_auto_update_path`、`test_auto_update_failure_records` | 已验证 | 未实现 | R14：旧 cron 仍走 Bash `-u` |
| F15 | `--stats` / `--json` / watch / reset | `test_xray_stats_readout`（真实 Xray API）、`test_xray_stats` | 已验证 | 未实现 | 首次查询瞬态失败见 `BASELINE_AND_CI.md` |
| F16 | GeoData 热更新/手动刷新/旧布局 | `test_geodata_native`（真实 Xray）、`test_geodata_update_path`、`test_restore_geodata_selfheal` | 已验证 | 未实现 | 迁移必须 fail-closed，保留旧 cron |
| F17 | IPv4/IPv6、DNS、端口、防火墙 | `test_dual_stack`、`test_dns_multi_record`、`test_firewall_ipv6`、`test_firewall_transaction_complete` | 已验证 | 未实现 | R12：iptables 直写未纳入统一事务 |
| F18 | 分享链接/二维码/Clash | `test_clash_yaml`、`test_color_output` | 部分验证 | 未实现 | 需逐字段对照 URI/Clash |
| F19 | 备份/恢复/重配置保留/模式切换 | `test_backup_restore`、`test_backup_permissions`、`test_reinstall_preservation`、`test_restore_geodata_selfheal` | 已验证 | 未实现 | 必须保留自定义 DNS/routing |
| F20 | Fail2ban（含 trusted/unban） | `test_fail2ban` | 已验证 | 未实现 | **已批准差异**：不得 `rm -f jail.d/*.local` |
| F21 | 流量阻断与自定义路由 | `test_firewall_reconcile`、`test_geodata_manual_confirm` | 部分验证 | 未实现 | 规则生成后必须 `xray -test` |
| F22 | Rill 观察/诊断/授权/卸载 | `test_rill_*`（7 个）、CI `rill-qualification` | 已验证 | 未实现 | R03：`.py` 被 `bash` 启动并吞错 |
| F23 | 六语言 | `test_i18n_catalog`、`test_color_output`、CI `i18n.yml` | 已验证 | 未实现 | 缺省回退英文 |
| F24 | Docker 交付 | `test_relay_container`、`test_minimal_bootstrap`、`docker/fake-systemctl` | 部分验证 | 未实现 | R16：不能假设宿主 systemd DBus |
| F25 | TCP 优化/测速 | 无自动化（仅有菜单项） | 未验证 | 未实现 | **已批准差异**：不执行浮动远程脚本 |
| F26 | XTLS ONLY 旧模式 | `test_install_menu_profiles`、CI `Relay mixing and legacy-mode guards` | 已验证（只读识别/阻断） | 未实现 | fixture `xtls-only`；只读识别，禁止激活 |
| F27 | `--backup/--restore/--purge/--service-*` | `test_offline_commands`、`test_uninstall_clean`、`test_install_uninstall_transaction` | 已验证 | 未实现 | 退出码/JSON 兼容 |
| F28 | 运行态与分享信息展示 | `.github/test/test_offline_commands.sh` | 已验证 | 未实现 | 打开/`--show` 必须零网络零写入 |

## 4. L0 纯函数差分（Phase 00 实际执行）

| 项目 | 结果 |
|---|---|
| Oracle | `LIVE_PINNED_CLEAN`（独立 clone，`HEAD=4752f77`，`install.sh` 干净且哈希匹配） |
| Go 侧 | `BUNDLED_TOY_GO_DEMO`（参考原型，**非生产实现**） |
| 用例 | 83 |
| 通过 | **83 / 83** |
| 失败 | 0 |
| 覆盖 | `version_compare`(14)、`version_series_difference`(10)、`relay_is_valid_host`(24)、`format_uri_authority_host`(9)、`format_xhttp_path`(8)、`vless_urlquote`(11)、`yaml_quote_scalar`(7) |
| Release 认证 | **否**（`release_certified=false`，`native_l0_only=false`） |
| 证据 | `tests/go-parity/parity/evidence/functional_parity.json` / `.md` |

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

- 83/83 或 39/39 表示**参考原型的纯函数/合成桥接**通过，**不代表** F01–F28 已迁移。
- 不得用本文件的「已验证」描述 Go；该列只描述 Bash 基线。
- 不得因为 CI 绿灯宣布发布就绪；`check_release_gate.py` 在缺少生产 Go 与 28 个功能测试时按设计返回红灯。
