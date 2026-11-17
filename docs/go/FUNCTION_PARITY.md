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
| F02 | `--install-tls` ws/gRPC/xHTTP/组合 | `test_install`、`test_true_fresh_install`、CI job `Install (ws_grpc_xhttp)` | 已验证 | 部分实现（容器级） | `F02_test.py` 全绿（171 断言，两次）：generate 的 ws/gRPC/xHTTP/`ws+grpc+xhttp` 产物、share/Clash、Nginx 主配置与片段（证书路径、`*.{ws,grpc,xhttp}Servers`、80 端口 ACME/301）、端口钉选与冲突、`--public-port`/`--cert`/`--listen`、覆盖保护，全部配置与执行的 Bash 基线配置均通过真实 `xray -test`；修正 TLS 模式 `generated.port` 误报 0。已登记差异：VLESS 大小写、默认端口策略、默认路径、xHTTP 尾斜杠、`--listen 0.0.0.0` 无确认、`--port` 语义、ws+xhttp 组合未实现、组合只发主入口链接、generate 不校验证书对；真实证书 + 宿主 Nginx 的 `xray install --mode tls` 仍未执行（gap，不伪造） |
| F03 | `--install-none`，ws ONLY | `test_ws_only_listen_address`、`test_install_menu_profiles` | 已验证 | 部分实现（容器级） | `F03_test.py` 全绿（159 断言，两次）：none 默认 `security=none`/`listen=127.0.0.1`/端口 10086/无 Nginx 产物；`--allow-non-loopback` 守卫（`0.0.0.0`、`::1`、全局 IPv6）、ws/gRPC/xHTTP/`ws+grpc+xhttp` 产物、端口钉选与冲突、`--public-port`、覆盖保护；所有有效配置与真实执行的 Bash 基线配置均通过 `xray -test`。修正 none 多传输只让主入站跟随 `--listen` 的缺陷（Bash 会改写三个入站）。已登记差异：非回环守卫更严格、listen 格式未校验（gap，`xray -test` 会拒绝）、默认端口策略、VLESS 大小写、none 多传输 `--ws-port` 被忽略、`--public-port` 仅客户端视图、独立/多传输 xHTTP 默认路径、xHTTP Clash 未渲染、真实 none 安装未执行（gap，不伪造） |
| F04 | Reality primary/secondary 负载均衡 | `test_install_menu_profiles`、`test_reality_nginx_feedback` | 部分验证 | 部分实现（容器级） | `--mode reality-balance --role primary/secondary` 生成真实 Nginx stream + 两个真实 Xray Reality 后端；容器 e2e（真实 nginx、真实客户端）验证轮询命中、secondary 宕机时 primary 全量承载、重启后重新加入、未知 SNI 拒绝（`tests/go-parity/evidence/balance-e2e-2026-11-08`）。**未在真实 VPS 双机验收**，生产签收仍需两台主机。**2026-11-17 `F04_test.py` 214/214（连跑两次，CONTAINER_VERIFIED）**：primary 入站 9443/front 8443/`0.0.0.0`、secondary 入站=`--port` 且零 Nginx 产物；isolate→9403+`03-isolate.conf`、reject→9404 无站点、decoy/未知策略 rc=2；多后端逐 host 片段、同 host 不同端口/缺端口/非法 host 拒绝、相同 host:port 去重、IPv6 括号保留；角色/默认 443/保留端口/非 raw 传输/双 serverName 守卫；每份有效配置真实 `xray -test`，每个 primary 变体真实 `nginx -t`；真实执行的 Bash 基线（角色 profile、端口改写、本机 upstream、serverNames 自愈、isolate 站点与 http include、`nginx_reality_conf_add`）与 Go 配置逐字节一致。修复显式 `--public-port` 取 9403/9404/9443/9444 时 Nginx 前置与 Xray 后端端口冲突的缺陷（Bash 无此入口，front 端口必过保留检查）；已登记差异：decoy 未生成、generate 不自愈陈旧片段、双机数据面与真实服务启动未执行（gap，不伪造）。证据 `tests/go-parity/evidence/f04-2026-11-17` |
| F05 | `--install-relay`，独立中转 | `test_relay_node`、`test_relay_container`、CI job `Install (relay)` / `True Fresh Mode (relay)` | 已验证 | 部分实现（容器级） | 生成 Nginx `stream` 片段；`nginx -t` 通过；真实容器网络内 PING 经 stream 转发回显；仍不能创建 Xray/UUID/证书；preview 夹具 `F05_test.py` 全绿 |
| F06 | 用户查看/添加/删除、UUIDv5 | `test_install`、`test_reinstall_preservation` | 部分验证 | 部分实现（容器级） | `user list/add/remove` 走事务并真实重启服务；主用户保护、重复拒绝、write-fail/service-fail 回滚已实测；UUID 为随机 v4，**未实现 UUIDv5**；Phase 03 迁移保留 4 用户逐字节不变。**2026-11-16 `F06_test.py` 122/122（连跑两次，CONTAINER_VERIFIED）**：list 主用户标记；add 事务 COMMITTED、0640、无残留且非用户字段不变；随机 v4 与配置一致；重复 email/uuid/shortId、非法 uuid/shortId、缺 `--sandbox`、未标记根均 rc=2 零写盘；remove 精确删除二级用户、主用户/未知用户 rc=2；`user uuid` 一次改两个 inbound、`--inbound` 收窄、dry-run/无变化零写盘、目标重复 rc=2；validator 拒绝 rc=8、write-fail rc=13、service-fail rc=9 且配置逐字节还原；Bash `UUIDv5_tranc`/`--uuid-reset` 记为 `not-implemented` 写入 `baseline-compare.json`。证据 `tests/go-parity/evidence/f06-2026-11-16`。 |
| F07 | shortId / spiderX / 用户映射 | `test_reality_min_client_ver`、`test_reinstall_preservation` | 部分验证 | 部分实现（容器级） | 新增用户可追加 Reality `shortId`；分享 URI 带 `sid/spx`；未实现完整用户映射管理。**2026-11-17 `F07_test.py` 94/94（连跑两次，容器级 CONTAINER_VERIFIED）**：`generate --mode reality` 自动生成 8 hex sID 并同时写入运行配置与 URI（两次不同、无 spx、fp=chrome、pbk 43 字符、配置 0600）；显式 16 hex/4 hex 原样落盘，奇数/17 位/非 hex/空格 rc=2 且零落盘，空值回退自动；`user add --short-id` 事务 COMMITTED、sid 与 client 各追加一项、非用户字段与 0640 权限不变，重复/非法/非 Reality inbound rc=2 零写盘；`share` 的 sid 取首个 accepted sID、`shareLinkOnly` 的 fp/spx 只装饰链接（运行配置 SHA-256 不变）、未知用户 rc=1 无 URI、`--user` 选客户端后仍用首个 sID（无每用户绑定）；`short-id-list` 每 sID 一行且零写盘。固定 Bash 的 `generate_reality_short_id`/`generate_spiderx` 提取后真实执行（16 hex、`/assets\|static\|docs\|api` 模板）；自动 sID 8 vs 16、自定义约束 1–16 偶数 vs 必须 16、自动 spiderX、`reality_clients` 每用户映射、链接模板（无 target、多 encryption/type）、spx 未 URL 编码六类差异记入 `baseline-compare.json`。证据 `tests/go-parity/evidence/f07-2026-11-17`。 |
| F08 | 端口、target、serverNames、SNI Guard | `test_port_safety`、`test_port_validation`、`test_install_menu_profiles` | 已验证 | 部分实现（容器级） | `xray config edit --port/--listen/--server-names/--target` 真实写盘（模式/权限/备份/metadata sha 保持）、候选 `xray -test` 校验失败零写盘、直接 Reality 端口改写后链接与 `xray share` 同步、`--no-probe` 跳过源站握手；reality-nginx 生成 SNI Guard（isolate→9403+`03-isolate.conf`、reject→9404、decoy 拒绝）；运行期 `--sni-guard` 切换、decoy 产物与 9404 冲突检查仍缺；preview 夹具 `F08_test.py` 全绿 |
| F09 | `--add-upstream`，上游片段管理 | `test_nginx_security`、`test_reinstall_preservation` | 部分验证 | 已实现（容器级） | `xray balance list/add/remove --upstream reality\|ws\|grpc\|xhttp` 只改写项目片段。**2026-11-17 `F09_test.py` 65/65（连跑两次，CONTAINER_VERIFIED）**：真实 `generate --mode reality-balance --role primary` 产物 + 真实 nginx 1.24 `-t` 初始化；`add 10.0.0.2:8443 weight=60` 写出的 60 字节片段与 Bash `fm_create_server_file` 逐字节一致（sha256 `7326cff4…`）；list TSV/JSON 按 host/port 排序且零写盘；重复 host、保留 443、非法 host、端口 0/65536、权重 101/-1、未知 upstream 均按实测 rc 拒绝；删 loopback/错端口/缺文件 rc=1；破坏 nginx.conf 时 add rc=1 且删除新片段，恢复后同一 add 成功；TLS ws 安装只接受 ws/grpc/xhttp，reality rc=1；`--probe` 对真实 TLS 1.3+SNI 监听返回 `probed=true`；缺 metadata rc=3、缺锚点/缺 nginx rc=1。Bash 的列表/JSON、重复/保留端口、loopback 删除与 reload 行为记为 approved-difference。gap：未在真实 VPS/systemd/防火墙验收，真实根 `/` 的 `--container` 门禁与跨机 probe 未执行，TLS server 块用最小替身（真实块由 F02 覆盖）。证据 `tests/go-parity/evidence/f09-2026-11-17`，hygiene 0 findings。 |
| F10 | `--tls` 版本变更 | `test_nginx_security`、`test_nginx_update_rollback` | 部分验证 | 部分实现（容器级） | 新增 `idleleo xray tls --version 1.3\|1.2+`（[nginxtls.go](../../internal/deploy/nginxtls.go)）：按 `ssl_protocols` 或 `$ssl_preread_protocol` 定位托管文件，Reality 安装切换 `TLSv1.2 1;` map 条目，TLS 安装只允许 1.3（h3/quic 要求，1.2+ rc=1）；写入前校验 `nginx -t`，失败或 reload 失败还原原字节，重复调用零写盘。**2026-11-17 `F10_test.py` 38/38（连跑两次，CONTAINER_VERIFIED）**：真实 `generate --mode reality-balance --role primary` + 真实 nginx 1.24 `-t`；Reality 1.2+/1.3 与 TLS 1.3 三种产物均与 Bash `tls_type` 逐字节一致；缺 metadata rc=3、缺托管前端/ws-only rc=1、非法/缺失 `--version` rc=2。approved-difference：Bash 对 TLS 1.2 交互循环、`sed -i` 直写无回滚、重启 nginx+xray；Go 直接 rc=1、事务式回滚、沙箱根跳过 reload 并告警。gap：未在真实 systemd/VPS 验收，未做线上 TLS 握手。证据 `tests/go-parity/evidence/f10-2026-11-17`，hygiene 0 findings |
| F11 | 服务状态/启停/日志 | `test_offline_commands`、`test_phase1_safety` | 已验证 | 部分实现（容器级） | Phase 04 新增 `service status/start/stop/restart/reload/logs`，仅限自有 unit；容器内实测 `xray=active`、restart 计数 3→4、stop/start、journal 日志、非法 unit exit 2、sandbox root 拒绝 exit 2；preview 夹具 `F11_test.py` 全绿 |
| F12 | 证书状态/签发/续期/清理 | `test_cert_update_recovery`、`test_ssl_update_recovery` | 部分验证 | 部分实现（本地 CA） | 原生 ACME v2 客户端（ES256/JWS/nonce/订单/HTTP-01）在 Pebble 本地 CA 上真实签发、窗口内跳过、强制续期；证书对原子替换（temp+fsync+rename），私钥 0600/证书 0644，`--reload-command` 失败回滚旧证书对且回滚后仍通过链/SAN/私钥匹配校验；负面覆盖 webroot 失效、reload 失败、只读目标、CA 拒绝域名（`tests/go-parity/evidence/acme-2026-11-08-fix`）。**公网 CA、DNS-01、EAB、真实域名与 Bash 的 `idleleo-nginx` 组/重启语义未验收**，不得据此升格。2026-11-16 补齐 acme.sh 契约（D-024）：`--production` 默认 staging 预检（`--no-staging-check`/显式 `--directory` 跳过）、账本迁到 `/etc/idleleo/acme`（旧目录非 `account.key/json` 条目 fail-closed）、按 CA directory 分账、落盘后 `0750` 目录 + `0640 root:idleleo-nginx`（无组保持 `0644/0600`）、回滚恢复旧证书 uid/gid、`.user-managed`/`.managed-by-idleleo` 归属标记与 `--takeover`、`renew --dry-run` 只读预览；Bash `install.sh`/`ssl_update.sh` 与 schedule 同步拒绝覆盖用户自备证书。证据：`tests/go-parity/evidence/cert-contract-2026-11-16`（单元 + CLI 探测级，未重跑真实 CA 与真实 Nginx）。2026-11-16 新增契约执行器 `tests/go-parity/parity/features/F12_test.py`（预览容器 `idleleo-preview:latest`，夹具内本地 ACME v2 HTTPS CA + HTTP-01，非公网 CA）：72/72 断言全绿，覆盖 dry-run 四态只读、真实签发与链/SAN/私钥匹配、账户按 CA 分目录与旧账本迁移 fail-closed、`--takeover`、managed `0750`/`0640 root:idleleo-nginx` 与独立目录 `0644/0600`、reload 失败回滚旧证书对、`--production` 默认 staging 预检、schedule 跳过 user-managed 并在操作者替换后重启 xray/重载 nginx；证据 `tests/go-parity/evidence/f12-2026-11-16`（级别 CONTAINER_VERIFIED + ACME_LOCAL_CA，公网 CA/DNS-01/EAB/真实 Nginx worker 组仍未验收） |
| F13 | `--update`、`--xray-update`、`--nginx-update` | `test_xray_update_transaction`、`test_nginx_update_rollback`、`test_candidate_real_upgrade` | 部分验证 | 部分实现（容器级） | 2026-11-17 新增 `idleleo update xray\|nginx`：显式清单 `schemaVersion/component/version/sha256/sizeBytes/url`，component 必须匹配子命令，sha256 与 sizeBytes 下载后硬校验；拒绝降级 rc=4（Bash 警告后继续，记为 approved-difference）、同版本走 `reinstall`；备份到 `etc/idleleo/backup/<component>-<ver>-<unixnano>`（xray 复制 0755、nginx 整目录 rename），激活后校验版本并执行健康检查（xray `run -test -config`、nginx `-t`），失败自动回滚 rc=6、回滚失败 rc=10；仅真实 `/` + systemd 重启，沙箱 root 写 warning 且 `restarted=false`。清单强制 `schemaVersion=1`、`sizeBytes>0`，https 清单/资产拒绝重定向降级到 http；契约执行器 `tests/go-parity/parity/features/F13_test.py` 58/58（连跑两次，CONTAINER_VERIFIED）：环回 HTTP 清单下 xray 成功/同版本重装/降级/坏摘要/坏大小/`run -test` 失败回滚，nginx tar.gz 整树替换与坏包回滚（真实 nginx 1.24 `-t`），清单/旗标/真实根/无 marker 门禁（含非 1 schemaVersion 与非正 sizeBytes）与零写盘断言，Bash `version_compare` 9 组版本表与 Go 逐项一致；安全/实现差异记录在 `baseline-compare.json`。gap：未在真实 VPS 更新真实 Xray/Nginx、未触发 systemd 重启，未覆盖 Bash 交互确认/CDN 回退/Layer 2-3 测试回退，跨设备目录 rename 只报 rc=13。证据 `tests/go-parity/evidence/f13-2026-11-17`（hygiene 0 findings） |
| F14 | `--auto-update` 与 cron | `test_vps_auto_update_schedule`、`test_legacy_auto_update_path`、`test_auto_update_failure_records` | 已验证 | 部分实现（容器级） | Phase 03 新增原生 `idleleo schedule`：systemd timer 接管 GeoData/统计。Phase 04 接入 Go release 通道：配置后容器内真实定时升级 `0.3.0→0.4.0`。**P0-5 修正**：Go 无 Xray/Nginx 自动更新执行器，迁移保留旧 `auto_update.sh` cron（只移除 `geo_update.sh`/`xray_stats.sh`）；未配置 Go 通道只影响 Go 自身升级，`degraded` 不删除 cron；cert-renew 已接原生 ACME（与 CLI 同一 executor，本地 CA 证据见 F12），`ssl_update.sh` 同样保留。2026-11-16 新增契约执行器 `tests/go-parity/parity/features/F14_test.py`（一次性 sandbox root + 环回签名 manifest origin，级别 CONTAINER_VERIFIED + LOCAL_RELEASE_ORIGIN）：62/62 断言全绿，覆盖未签名/摘要不符/降级拒绝、真实 apply 与健康检查、健康失败回滚旧二进制、`schedule install` 的 3600s timer/四项职责/显式 auto-update degraded、无通道 degraded 与配置后定时真实升级；证据 `tests/go-parity/evidence/f14-2026-11-16`。Bash 基线为 install.sh 的 `0 1 * * * bash auto_update.sh`（scripts/auto_update.sh 覆盖 Xray/Nginx），真实 VPS cron 仍未验收 |
| F15 | `--stats` / `--json` / watch / reset | `test_xray_stats_readout`（真实 Xray API）、`test_xray_stats` | 已验证 | 部分实现（容器级） | `stats-collect` 用真实 `xray api statsquery` 写 `stats.json`。Phase 04 新增只读 `idleleo stats`：真实调用 `xray api statsquery`、`--json` 原样输出、非 root exit 5、API down exit 8；**watch/reset 仍未实现**（`--watch/--reset/--yes` 按未知参数显式 exit 2，不静默接受）；首次查询瞬态失败见 `BASELINE_AND_CI.md`。preview 夹具 `F15_test.py` 56/56（真实 Xray 26.11.9 StatsService + HTTP 代理入站产生 64 KiB 流量）：Go 透传与 Bash `xray_stats.sh --json` 归一化结果在同一计数器上逐值一致（tag 集合/上行/下行/合计/server）、`--pattern`、缺配置/坏 JSON/缺 `api.listen` exit 3、坏参数/路径穿越 exit 2、查询零写入；API down 的 Go 8 与 Bash 2 差异记录在证据；schedule `stats-collect` 写 `schedule/stats.json`（0640）且 API down 时 failed。证据 `tests/go-parity/evidence/f15-2026-11-16`（连跑两次均 56/56） |
| F16 | GeoData 热更新/手动刷新/旧布局 | `test_geodata_native`（真实 Xray）、`test_geodata_update_path`、`test_restore_geodata_selfheal` | 已验证 | 部分实现（容器级） | `geodata-refresh` 下载双文件→内存校验→原子替换→重启 Xray；容器内用本地固定 origin 实测字节一致，截断下载不覆盖旧文件；旧布局迁移仍未实现。2026-11-16 新增契约执行器 `tests/go-parity/parity/features/F16_test.py`（预览容器 + 夹具内环回 GeoData origin，级别 CONTAINER_VERIFIED + LOCAL_GEODATA_ORIGIN）：94/94 断言全绿，覆盖 `schedule install --geodata-url` 落盘 0640 配置、成功刷新逐字节一致且 0644/0755、detail 字节数与 `sandbox root, no service reload`、state/schedule.log 记录、二次运行幂等、外部旧布局树不变且不写 `geo_version.json`；badsha/truncated/empty/html/missing/mixed 六种失败 rc=1、旧资产逐字节保留、无 temp/stage 残留、state 记 failed，首次失败不创建目标目录；未标记 sandbox/非 root 真实 root/`geodataDir` 逃逸/未知 job 均显式失败。Bash `scripts/geo_update.sh` 固定 GitHub release，只能做静态契约比对（`baseline-compare.json`）：Go 缺 pinned tag + `geo_version.json`、Xray `run -test` 预校验、stage/restore 回滚与旧布局迁移，restart 仅真实 root。证据 `tests/go-parity/evidence/f16-2026-11-16`（连跑两次均 94/94）。真实 Xray 资产解析与真实 VPS reload 仍未验收 |
| F17 | IPv4/IPv6、DNS、端口、防火墙 | `test_dual_stack`、`test_dns_multi_record`、`test_firewall_ipv6`、`test_firewall_transaction_complete` | 部分验证 | 部分实现（容器级） | 2026-11-17 新增 `idleleo net dns`（`--domain/--policy/--resolver/--server-ipv4/--server-ipv6`）与 `net firewall status\|apply\|revert`（`--tcp/--udp/--family/--dry-run/--container`）：`internal/netcfg` 复刻 Bash 的 `classify_resolved_ips`（仅分类、不去重、保序）与 `validate_domain_network_records`（显式 ipv4 仍校验 AAAA，显式 ipv6 仍校验 A，坏记录 rc=2，无匹配 rc=1，NXDOMAIN 记 mode=none rc=1），family 由 `FamiliesForMode` 推导（dual 双栈、ipv6 仅 ip6tables、auto 依赖 ip6tables 存在），端口集持久化到 `etc/idleleo/managed_ports.json`、family 集写 `managed_families.json`，规则落 `etc/iptables/rules.v{4,6}`；apply 先 `-C` 再 `-I`、差分删除旧端口、family 收缩时清空整族，逐条登记逆操作，任一命令失败按逆序回滚，state 写失败同时回滚规则与 state；`--dry-run` 只列 `-C/-I` 且零执行零写盘；真实根需 `--container`，未标记沙箱 rc=2。契约执行器 `tests/go-parity/parity/features/F17_test.py` 113/113（连跑两次，CONTAINER_VERIFIED）：进程内权威 UDP DNS 下 dual/stale AAAA/显式 ipv4 拒 AAAA/仅 AAAA/无匹配/NXDOMAIN 判定，PATH 内 iptables/ip6tables shim 下首轮 4+4 规则、端口差分（逐条精确规则集）、dual→ipv4→dual 与 dual→ipv6→dual 切换、注入 `ip6tables -I` 失败回滚、逆操作失败 rc=10 且后续 apply 可收敛、dry-run 零写、门禁（bogus policy/port/family/flag、真实根、无 marker）零写、status 对缺失 OUTPUT 规则的如实报告且只检查 `managed_families.json` 记录的族（ipv4-only apply 不写 `rules.v6`、不把未受管族报成 drift）、revert 清空且幂等、隐藏 ip6tables 时 fail-closed；Bash `classify_resolved_ips` 6 组输入与 `managed_fw_families_for_mode` 10 组 mode×ip6tables 行与 Go 一致，且 family 集含缺失 ip6tables 时必须 rc=1。差异登记：Go 不做外部 echo 探测（地址来自旗标或本机接口，approved-difference）、新增显式 managed-state 文件、dual/ipv6 缺 ip6tables 直接拒绝（Bash auto 降级为 iptables）。gap：无真实 VPS、无真实 netfilter、未验证重启后规则持久化，仅建模 iptables/ip6tables，未覆盖 nft/ufw/firewalld 与 Bash 交互确认。证据 `tests/go-parity/evidence/f17-2026-11-17`（hygiene 0 findings） |
| F18 | 分享链接/二维码/Clash | `test_clash_yaml`、`test_color_output` | 部分验证 | 部分实现（容器级） | 容器内 `share` 从真实配置派生 URI，实测 `flow/sni/pbk/sid/spx`；Clash 生成存在，xHTTP 明确告警且不伪造。**2026-11-17 补齐终端二维码：`F18_test.py` 178/178（连跑两次，CONTAINER_VERIFIED）**：六份真实生成配置（reality raw、reality+ws 伴随入站、TLS ws/grpc/xhttp、none ws）经 `share` 派生，Reality URI 的 flow/sni/fp/pbk/sid 与 Clash `reality-opts` 一致且无 `target`；`--public-port` 只改客户端视图、配置 SHA-256 不变；回环 security=none 缺 `--public-security` 时以 ambiguous 拒绝，补 tls/none 分别出 TLS/明文链接（TLS 附 proxy 终止告警）；xHTTP 返回 `clash-xhttp-unsupported` 且不生成 Clash；`share --qr` 调用真实 `qrencode -o - -t utf8`（e2e 镜像内 4.1.1），矩阵与同一 URI 的直接调用逐字节一致（4994 B/31 行，sha256 相同，`qr-compare.json`）；`--qr` 为显式旗标，默认文本与 `--json` 输出不变，`--json --qr` rc=2，`PATH` 无 qrencode 时 rc=1 且 stdout 为空，未知旗标仍 rc=2。Bash 链接模板、Clash 键与 10 处 `qrencode` 为静态基线，target/fp/path 编码/mode=auto/none-sni/Clash 键/xHTTP Clash/二维码七类差异记入 `baseline-compare.json`（二维码一项为 approved-difference：Go 显式 `--qr`，Bash 每链自动打印）。gap：未做手机扫码解码、未适配终端宽度与不同 qrencode 版本、未在真实 VPS 验证。证据 `tests/go-parity/evidence/f18-qr-2026-11-17`，hygiene 0 findings。 |
| F19 | 备份/恢复/重配置保留/模式切换 | `test_backup_restore`、`test_backup_permissions`、`test_reinstall_preservation`、`test_restore_geodata_selfheal` | 已验证 | 部分实现（容器级） | 容器内实测卸载保留配置、`--keep-config` 重装后自定义 DNS 逐字节保留；Phase 03 增加 Bridge 快照与故障回滚（入口/unit/配置哈希、精确 cron、schedule units、权限 mode/group），backup/restore CLI 仍未实现。**2026-11-16 `F19_test.py` 136/136（连跑两次，容器级 CONTAINER_VERIFIED）**：node `metadata import` 不重写源配置/运行配置/证书/入口/cron，元数据 0640 且不含密钥，重复导入 rc=3 不覆盖，任意 `--from`/未标记根 rc=2 零写盘，缺配置/坏 JSON（rc=2）与缺运行配置（rc=3）零写盘，relay 角色映射正确；`metadata export` 默认只读、`--out` 0600、托管目录与覆盖元数据 rc=2；运行配置漂移报 `matchesMetadata=false`，`bridge deactivate` 对陈旧或漂移导出均 rc=6 且不动任何文件，恢复后交还归档元数据（0640 逐字节）并保持入口/cron/证书/运行配置不变。Bash `--backup`/`--restore` 归档与恢复仍缺，差异记入 `bash-baseline.json`。证据 `tests/go-parity/evidence/f19-2026-11-16`。 |
| F20 | Fail2ban（含 trusted/unban） | `test_fail2ban` | 已验证 | 部分实现（容器级） | `fail2ban install/status/banned/unban/trust/jail/uninstall` 全部走 manifest：只删自有文件，保留操作员 jail（ED-002）。**2026-11-17 `F20_test.py` 110/110（连跑两次，CONTAINER_VERIFIED）**：四个 Nginx jail（badbots/botsearch/no-host/tls-error）、incremental 策略、两个 filter、jail.local 逐字节等于 jail.conf、systemd 重启策略 drop-in，manifest `version=1` 九个文件；二次 install 整树 sha 不变；真实执行的 Bash 基线（`mf_configure_fail2ban`）与 Go 的九份生成物逐字节一致，两侧因无 SSH unit/journal 同样跳过 sshd；真实 `fail2ban-client` 守护进程下 status/banned/unban（二次 unban=alreadyAbsent）、trust IPv4/IPv6 add/del 与运行态 ignoreip、jail enable/disable 只翻 `enabled`、外来 jail 拒绝；uninstall 删除 10 个 manifest 文件并保留 `user-custom.local`，manifest 缺失时 rc=2+needForce 且零删除，`--force` 只清已知残留；S7 沙盒/`--container`/写令牌/缺 `fail2ban-client` 守卫全部零写盘。已登记差异：Go 不装包只给 apt/dnf/apk 提示（G13）、只删 manifest 文件（ED-002）、trust 写独立文件、jail 只切换自有文件；gap：无 systemd 重启、无 SSH journal、无日志驱动封禁与 iptables 数据面、仅 fail2ban 1.0.2、无真实 VPS。证据 `tests/go-parity/evidence/f20-2026-11-17`，hygiene 0 findings。 |
| F21 | 流量阻断与自定义路由 | `test_firewall_reconcile`、`test_geodata_manual_confirm` | 已验证 | 部分实现（容器级） | `xray block status/apply/off/ads/private-ip/bittorrent/country/custom` 在真实 systemd 容器内实测。**2026-11-17 `F21_test.py` 79/79（连跑两次，CONTAINER_VERIFIED）**：真实 `xray install --mode none --transport ws --port 443` 基线；首次 apply 写入 7 条 owned 规则（`geosite:cn`、`geoip:cn`、bittorrent、ads、`geoip:private`、custom domain、custom ip）并按序追加 `inboundTag -> direct`、`domainStrategy=IPIfNonMatch`、全部入站 `sniffing{routeOnly,destOverride}`、`/etc/idleleo/backup/block-*`（config/state/meta）、`50-xray-geodata.conf`（`XRAY_LOCATION_ASSET`），真实 `systemctl restart xray` + 本机 TCP 探针 + 真实 `xray -test` 输出 `Configuration OK`；二次 apply 零改写（`oldSha256==newSha256`、drop-in 复用）；`off` 精确恢复安装 sha、`AsIs`、sniffing null 且开关保留，二次 off `rc=1` `no traffic-block rules are installed`；三类失败（`zz` 被 `-test` 拒绝、用户末条吞流量、缺 geosite）均 `rc=1`、零写盘、服务仍 active；Bash `tb_build_block_rules` 真实执行产出 5 条规则与 Go 前 5 条语义一致，legacy adoption 不重复且保留用户规则。已登记差异：custom 列表与 IPIfNonMatch/sniffing 为 Go 扩展（approved-difference）、状态含 `owned_rules/previous_*`、JSON/dry-run、无规则时二次 off rc=1；gap：非 443 的 mode=none 探针固定拨 443、固定 geosite 仅 `cn` 可用、Bash 交互/下载流程未比、无客户端数据面、无真实 VPS。证据 `tests/go-parity/evidence/f21-2026-11-17`，hygiene 0 findings。 |
| F22 | Rill 观察/诊断/授权/卸载 | `test_rill_*`（7 个）、CI `rill-qualification` | 已验证 | 部分实现（容器级） | Phase 03 审计/快照/预验收/激活/回滚纳入 Rill 状态与哈希；观测漂移 → validate exit 6。Phase 04 新增只读 `rill status`（absent/active/stale），复用 legacybridge 投影、不写 Rill 状态；**安装/诊断/授权/两阶段卸载命令未迁移**；R03：`.py` 被 `bash` 启动并吞错。2026-11-16 修复投影未读真实观察字段 `capturedAtEpochSeconds`（此前只认 mtime 与 `observedAt` 等，导致真实快照的老化判定失真），并补 `internal/legacybridge/rill_test.go` 覆盖字段优先于 mtime（双向）与 absent/unobserved/坏 config。preview 夹具 `F22_test.py` 54/54：五态投影、哈希/路径、非 root 只读、未迁移子命令显式 exit 2；Bash 基线 `install.sh --rill-agent-status`（`RILL_XRAY_AGENT_MANAGER` 指向仓库内 manager，否则 install.sh 走 `installed=false` 桩）在 installed/mode 一致，空 root 上 Bash 新建默认 config 并报 installed=true、状态 JSON 无观察新鲜度，差异记录在 `baseline-compare.json`。证据 `tests/go-parity/evidence/f22-2026-11-16`（连跑两次均 54/54）。真实 Rill 运行时/两阶段卸载仍未验收 |
| F23 | 六语言 | `test_i18n_catalog`、`test_color_output`、CI `i18n.yml` | 已验证 | 部分实现（容器级） | zh/en 完整，fr/fa/ru/ko 回退英文；preview 夹具 `F23_test.py` 103/103（连跑两次）：六码均接受、fr/fa/ru/ko 的 `version`/`help` 与 en 逐字节一致且每次恰好一条英文回退提示、zh/en 无提示；`de/ZH/zh_CN` exit 2 英文 help；`LANG`/`LC_ALL` 与 `etc/idleleo/language.conf` 均被忽略、默认 zh；空根 `status`=3 与未知命令=2 跨语言一致且只读调用零写盘；无 TTY 输出本地化 `no_tty`，45 列 PTY 菜单仍为英文单行提示、无 ANSI，zh/en help 最长行 111/133 列（无窄屏适配）。Bash 六个 `.mo` 用 `gettext.GNUTranslations` 实测均有真实译文（`总览`/`信息`），差异（六语言完整度、逐条 vs 整语言回退、language.conf、本地化 45 列菜单盒、ANSI 抑制）记录在 `baseline-compare.json`。证据 `tests/go-parity/evidence/f23-2026-11-16`。**TTY 菜单本地化与窄屏适配未对齐** |
| F24 | Docker 交付 | `test_relay_container`、`test_minimal_bootstrap`、`docker/fake-systemctl` | 部分验证 | 部分实现（容器级） | 新增 Go 包 `internal/container` 与 `idleleo container status/up/down`：无 systemd 时直接启动 xray/nginx、写 pid 与 `var/log/idleleo/container.log`，有 systemd 时才委托 systemctl；`up/down` 幂等，`--dry-run` 零写盘，真实根仍需 `--container` 门禁。镜像改为多阶段构建，运行阶段带 `/opt/idleleo/bin/idleleo`；`docker-entrypoint.sh` 增加 `_go_container` 分叉，`_watchdog` 改用 `container status --json`，Bash 菜单与 `fake-systemctl` 保留。**2026-11-17 `F24_test.py` 58/58（连跑两次，CONTAINER_VERIFIED）**：空根 status 零写盘；真实 nginx 1.24 + 替身 xray 下 dry-run/up/down、pid/日志/幂等/second-down no-op；真实根、无 marker、未知旗标 rc=2；pid 归属按 `/proc/<pid>/cmdline` 中的受管二进制路径判定（非 Linux 退到 `ps`，无法核验的外来进程不会被 signal，单测覆盖外来进程不被误认）；Dockerfile/entrypoint/DOCKER.md 静态契约；提取 `_start_services`/`_stop_services` 真实执行，启停集合与 Go 一致。approved-difference：Bash 经 fake-systemctl 伪 unit，Go 直接 pid 管理且不读 DBus。gap：无真实 systemd 分支、xray 为替身、本轮不 `docker build`、未测 Docker Desktop/Podman。证据 `tests/go-parity/evidence/f24-2026-11-17`，hygiene 0 findings |
| F25 | TCP 优化/测速 | 无自动化（仅有菜单项） | 未验证 | 部分实现（容器级） | `idleleo tcp status/plan/apply/rollback` 只管理 `/etc/sysctl.d/90-idleleo-tcp.conf`（profile `bbr-fq`）：真实单测 20 项 + Docker sandbox 30 项断言，覆盖幂等、部分失败回滚、journal pending、文件/运行值漂移、符号链接、非 root、内核不支持；**仍不执行 `tcp.sh`、不下载远程脚本、不做测速与性能验收**；Bash 菜单未接线；详见 [TCP_NATIVE_DESIGN_AND_QA.md](TCP_NATIVE_DESIGN_AND_QA.md)。2026-11-16 preview 夹具 `F25_test.py` 78/78：以沙箱 `/proc/sys` 普通文件跑通 status/plan 只读、`--confirm` 事务、二次 apply no-op、正常回滚与二次 rollback no-op、漂移时 apply/rollback 均 exit 7 且删掉漂移后可恢复、pending journal 阻塞与 rollback 恢复、foreign/99- 冲突/symlink/未知 profile 的显式失败、无 bbr 内核 exit 12、非 root 真实 root apply exit 6、非 root 只读 status、真实内核不变；另用投毒的 `curl/wget/tcp.sh` PATH 证明 apply/rollback 从不调用它们。Bash 基线（install.sh 的 `-tcp` 项）只执行本地 `tcp.sh` 且已拒绝下载，无法作为 hermetic 等值基线，差异记录在 `baseline-absence.json`。证据 `tests/go-parity/evidence/f25-2026-11-16`（连跑两次均 78/78）。测速/真实内核性能仍未验收 |
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
