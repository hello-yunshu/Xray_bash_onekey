# F01–F28 功能完整性与迁移追踪矩阵

> 根据 v3.1 规划和实际源码核对整理；Bash 行为基线为 `4752f77`。**下表「负责阶段」表示计划，不表示已经实现。**
> 「当前状态」列为 **Go 侧实现状态（截至 2026-11-11）**，权威口径见
> [FUNCTION_PARITY.md](../../go/FUNCTION_PARITY.md) 第 3 节；状态文字与该文件不一致时以该文件为准。
> 按 2026-11-06 授权，`CONTAINER_VERIFIED` 视为阶段门禁满足，但**不等于** F01–F28 签收；
> 正式签收仍为 **0 / 28**，要求 `feature_contracts.json` 状态、真实 `Fxx_test.py` 执行器与受保护 CI 三条同时满足。
> 2026-11-11：preview 通道为 F01/F05/F11/F26/F27/F28 提供可执行夹具（6/28），
> 其余 22 项仍缺 `Fxx_test.py`；preview 无发布权限，签收结论不变。

| ID | Bash 已有功能 | 源码锚点 | Go 职责 | 开发阶段 | 最小验收证据 | 当前状态 |
|---|---|---|---|---|---|---|
| F01 | `--install-reality`、Reality 普通/加 Nginx | `install.sh:12127+` / `config/vless_reality.json` | `app` + `xray` + `nginx` | 02 | 真实 Xray -test + 进程健康 | 部分实现（容器级）：容器内 fresh install、systemd `active/enabled`、`User=xray`、`xray -test`、Reality 客户端隧道；`reality-nginx` 仅配置生成；preview 夹具 `F01_test.py` 全绿 |
| F02 | `--install-tls`，ws/gRPC/xHTTP 和组合模式 | `install.sh:12954+` / `config/vless_tls.json` | `xray` + `nginx` + `cert` | 02 | ws/gRPC/xHTTP 单独与组合配置验收 | 部分实现（容器级）：ws/gRPC/xHTTP 及组合配置生成 + 真实 `xray -test`；TLS 真实证书未纳入 |
| F03 | `--install-none`，受信后端 | `install.sh:9156+` / `install.sh:12954+` | `xray` + `host` | 02 | 无 TLS 回环监听 + 显式非回环确认 | 部分实现（容器级）：none+ws 生成 + `xray -test`；非回环确认实测 exit 2、零落盘 |
| F04 | Reality 负载均衡 primary/secondary | `install.sh:154xx` Reality primary/secondary wizard | `xray` + `nginx` | 02 | primary 与 secondary 分别启动 | 部分实现（容器级）：primary/secondary 配置 + 真实 Nginx stream + 双真实后端 e2e 5/5（轮询、宕机承载、重启恢复、未知 SNI 拒绝）；未做真实双 VPS |
| F05 | `--install-relay` / 独立中转菜单 | `install.sh:11143–11951` | `relay` + `nginx` | 02/03 | 无 Xray 的 Nginx Stream TCP 字节转发 | 部分实现（容器级）：stream 片段 + `nginx -t` + 真实容器网络 TCP 转发；不创建 Xray/UUID/证书；preview 夹具 `F05_test.py` 全绿 |
| F06 | 查看/添加/删除用户、UUIDv5 | `install.sh:10375–10574` | `xray` + `change` | 02 | 增删失败注入恢复原 active/配置 | 部分实现（容器级）：`user list/add/remove` 事务、主用户保护、重复拒绝、回滚；UUIDv5 未实现 |
| F07 | Reality shortId、spiderX 与用户映射 | `install.sh:10420–10457` | `xray` | 02 | UUID / shortId / spiderX / 主用户对应关系 | 部分实现（容器级）：追加 shortId、URI 带 `sid/spx`；完整用户映射管理未实现 |
| F08 | 修改端口、target、serverNames、SNI Guard | `install.sh:10041+` / Nginx config | `xray`/`nginx` + `change` | 02 | 冲突、无权限、reload 失败时差异/恢复 | 部分实现（容器级）：端口原语、serverNames/target 校验与生成、非法值 fail-closed；SNI Guard 未实现 |
| F09 | `--add-upstream`、Nginx 负载均衡文件管理 | `scripts/file_manager.sh:145–212` | `nginx` + `host` | 02 | 自有 Nginx 片段编辑与原规则保留 | 未实现 |
| F10 | `--tls` 版本变更 | `install.sh:9963–10012` | `nginx` + `change` | 02 | 目标 Nginx -t 失败原配置不变 | 未实现 |
| F11 | Xray/Nginx 服务状态、启停、日志 | `install.sh:8622–8663` | `host` + `app` | 02 | 服务原 active/enabled 与日志权限 | 部分实现（容器级）：`service status/start/stop/restart/reload/logs` 仅限自有 unit；非法 unit exit 2、sandbox root 拒绝；preview 夹具 `F11_test.py` 全绿 |
| F12 | `--cert-status`、签发、续期、清理 | `install.sh:7316+` / `scripts/ssl_update.sh` | `cert` | 02 | 证书 NotAfter、续期变化前后状态 | 部分实现（本地 CA）：原生 ACME v2 在 Pebble 上真实签发/续期/负面用例，证书对原子替换、失败回滚旧对；公网 CA、DNS-01、EAB 未验证 |
| F13 | `--update`、`--xray-update`、`--nginx-update` | `install.sh:12825+` / Nginx manifest | `app` + `host` | 02/03 | 哈希/降级/运行服务故障注入 | 未实现 |
| F14 | 原有 `--auto-update` 与 cron | `scripts/auto_update.sh:394–512` | `app` + 有界定时入口 | 02/03 | cron 不触发 Go 迁移的负向测试 | 部分实现（容器级）：`internal/schedule` timer 真实触发，Go 通道定时升级；无 Xray/Nginx 更新执行器，旧 cron 保留 |
| F15 | `--stats`、`--stats --json`、watch/reset | `install.sh:10751+` / `scripts/xray_stats.sh` | `xray` + `cli` | 02 | 真实 `--stats --json` 字段/退出码比对 | 部分实现（容器级）：`stats-collect` 与 `idleleo stats --json` 真实 Xray API；watch/reset 未实现 |
| F16 | GeoData 原生热更新/手动刷新/旧布局 | `install.sh:5516+` / `scripts/traffic_blocker.sh` | `xray` + `legacybridge` | 02 | 原生热更新与 legacy cron 精确清理 | 部分实现（容器级）：`geodata-refresh` 原子替换 + 截断不覆盖；旧布局迁移未实现 |
| F17 | IPv4/IPv6、DNS A/AAAA、端口、防火墙 | `install.sh:623+` / firewall test files | `xray` + `host` | 02 | IPv6 literal、DNS A/AAAA、防火墙回滚 | 未实现 |
| F18 | 分享链接、二维码、Clash 配置 | `install.sh:9190+` / README | `xray` + `cli` | 02 | 分享 URI 和 Clash YAML 可解析 | 部分实现（容器级）：`share` 从真实配置派生 URI、Clash 生成且不伪造 xHTTP；二维码未实现 |
| F19 | 备份/恢复/重配置保留/模式切换 | `install.sh:14250+` / `restore_directories()` | `change` + `store` + `legacybridge` | 02/03 | 自定义 routing/DNS + 增量修改无破坏 | 部分实现（容器级）：`--keep-config` 重装保留自定义 DNS、卸载保留配置；backup/restore CLI 未实现 |
| F20 | Fail2ban 管理（含 trusted/unban） | `scripts/fail2ban_manager.sh` | 可选 `app` + `host` 集成 | 02 | 非项目 jail 在卸载后保持原样 | 未实现；已批准差异 D1（不得 `rm -f jail.d/*.local`） |
| F21 | 流量阻断与自定义路由 | `scripts/traffic_blocker.sh` | `xray` + `change` | 02 | 规则生成后 xray -test 成功 | 未实现 |
| F22 | Rill 观察、诊断、授权、卸载两阶段 | `install.sh:1267–1298` / Rill payload | `rill` 受控适配 | 02/03 | Agent 缺失/存在、授权、正确解释器 | 部分实现（容器级）：迁移审计/快照/漂移拒绝 + 只读 `rill status`；安装/诊断/授权/卸载未迁移 |
| F23 | 中文/英文/法文/俄文/波斯文/韩文 | `i18n/languages/` / `install.sh` | `cli` | 02 | 六语言目录回退和窄屏可读 | 部分实现（容器级）：zh/en 完整，fr/fa/ru/ko 回退英文；未与 Bash 文案逐条差分 |
| F24 | Docker 原有交付 | `docker/docker-entrypoint.sh` / `docker/fake-systemctl` | `packaging` | 02/04 | fake-systemctl/entrypoint 与镜像试跑 | 未实现（Docker 仅作测试环境） |
| F25 | TCP 优化与测速快捷工具 | `install.sh:10823+` / `install.sh:15218+` | 可选独立命令 | 02（可延期） | 不执行浮动脚本；如延期写 release notes | 部分实现（容器级）：`tcp status/plan/apply/rollback` 只管理自有 sysctl 文件；不执行 `tcp.sh`、不做测速 |
| F26 | `XTLS ONLY` 旧模式 | `install.sh:12988+` | `legacybridge` 只读识别 | 00/03 | 旧 XTLS 只读识别并阻断激活 | 部分实现（容器级）：audit 识别 `legacy-xtls-removed`，prepare 拒绝 exit 3，入口/cron 不变；preview 夹具 `F26_test.py` 复验无 journal、全树哈希不变 |
| F27 | `--backup`、`--restore`、`--purge`、`--service-*` 等历史参数 | `install.sh:12954–13162` / `15903–15998` | `cli` 兼容别名 | 00/01/02 | 旧 flag 参数/JSON/退出码对照 | 部分实现（容器级）：`service *` 与 uninstall/purge 已实测；preview 夹具 `F27_test.py` 覆盖退出码、保留配置、purge 删除与二次 purge 幂等；backup/restore CLI 未实现（`not_verified`） |
| F28 | 运行态及分享信息展示 | `install.sh:15944+` / README | `cli` + `store` | 01/02 | 打开/--show 无网络无写入 | 部分实现（容器级）：`status/show/share/help/stats` 只读且 `/etc/idleleo` 零写入；preview 夹具 `F28_test.py` 逐字段断言 `show/status/share`；未与 Bash 逐字段差分 |

## 可执行夹具（2026-11-11 preview 通道）

preview 通道只执行已有夹具，不改变本表状态与签收计数。当前 6/28 有真实执行器：

| ID | 夹具 | 结果 |
|---|---|---|
| F01 | `features/F01_test.py` | PASS（两遍） |
| F05 | `features/F05_test.py` | PASS（两遍） |
| F11 | `features/F11_test.py` | PASS（两遍） |
| F26 | `features/F26_test.py` | PASS（两遍） |
| F27 | `features/F27_test.py` | PASS（两遍） |
| F28 | `features/F28_test.py` | PASS（两遍） |

其余 22 项仍缺 `Fxx_test.py`。preview 输出明确标注
`PREVIEW — NOT FOR RELEASE`、`release authority: NONE`；
`feature_contracts.json` 的 28 项保持 `PENDING_GO_IMPLEMENTATION`。

## 使用规则

- Phase 00 补齐具体命令分发表：旧 flags、菜单入口、新 Go 命令、命令副作用级别、非 TTY 行为与兼容决策（硬兼容/安全拒绝/明确废弃）。
- Phase 01 落实 F27/F28 的基础 CLI，不能因为 `--help` 可运行便判定全功能完成。
- Phase 02 每完成一个业务包，填写真实测试产物与复现命令，更新 `功能: Go 实现路径 / 用例编号 / 结果 / 责任提交`。
- Phase 03 对迁移成功/失败的旧环境再次回测 F06/F07/F15/F19/F26/F27（这是最可能丢失用户数据或自动化契约的区域）。
- Phase 04 以此表作为禁止静默功能倒退的发布门槛，少量复杂模式可以有显式不支持的界限，但不能不经批准就删除旧功能。
- 状态列的「部分实现」一律是容器级或本地 CA 证据，**不是签收**；升格必须走 `feature_contracts.json` + 执行器 + 受保护 CI。
- `XTLS ONLY` 与 `xtls-rprx-vision` **不是同一个概念**：只阻断已废弃的旧安装模式，不能禁用 Reality/Vision。
