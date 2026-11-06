# CHANGELOG

## 3.3.5 — 2026-11-07

> 状态：**待发布**。版本号、CHANGELOG 与测试断言已就绪；实际发布需与生产
> `bridge/asset.json`（P0-2）同批合并 `main`，本轮未合并、未打 tag、未发 Release。
> 影响面见 `docs/release/BASH_VERSION_3_3_5_ASSESSMENT.md`。

### 新增

- **Go 迁移入口（Bridge-aware Bash）**：手动 TTY `-u` 在版本检查后提示是否迁移；
  `auto_update`、`--yes`、非 TTY 一律不触发。入口只读
  `/etc/idleleo/bridge/asset.json`，缺文件/字段不完整时干净跳过（不下载、不改动）。
- **真机写入门禁**：容器内仍要求 `IDLELEO_ALLOW_SYSTEM_WRITES=I_ACCEPT_CONTAINER_ONLY`；
  真实 root 主机放行切换，但先在 `/var/log/idleleo/system-writes.log`（0600）写入
  可审计记录，写失败则拒绝。

### 修复

- **xHTTP 上行超过 1MB 返回 413（历史模板缺陷，非本版引入）**：`335f4d8c`
  起生成的 `/etc/idleleo/conf/nginx/00-xray.conf` 把 xhttp location 的
  `client_max_body_size 0;` 注释掉，Nginx 回落默认 `1m`，`stream-one`
  的大请求体（如 `git push`）失败；ws location 一直正常。模板已改为生效行，
  并去掉对 `grpc_pass` 无效的 `proxy_buffering` 假配置。已部署节点需要
  **重装**或手工放开该行；`-u` 不重建 Nginx 配置，更新成功后会打印提示。
- **保留的 auto_update cron 不会静默回退迁移**：Bash 自更新路径原先无条件把
  `/usr/bin/idleleo` 重新指向 `/etc/idleleo/install.sh`；现在检测到 Go 入口或
  journal `COMMITTED` 时只刷新 Bash 脚本，不改变入口。
- **`-u --yes` 不再在“实际更新成功”后触发迁移入口**：此前该分支会重新执行
  刚下载脚本的 offer，`--yes` 在子进程里丢失；现在 `--yes`、`auto_update`
  与非 TTY 一样直接返回，Phase 03 回归覆盖了“真实升级成功 + TTY + `--yes`”。
- **迁移保留证书续期与自动更新 cron**：Go 尚无等价执行器的 `ssl_update.sh`、
  `auto_update.sh` 在切换后保留原 cron，只有已有 Go 执行器的 `geo_update.sh`、
  `xray_stats.sh` 被移除；`schedule status` 仍如实标记 `degraded`。
- **真实 root 迁移不再被容器标记硬阻断**：容器标记只用于区分执行环境，
  不再作为真机拒绝条件。

### 迁移说明

- 已发布 v3.3.4 资产保持不变（`install.sh` SHA-256 `0af8e8f2…`）；本条目对应新资产，
  由 `publish-shell-version.yml` 在合并 `main` 后自动发布。

## 未发布 — Go 管理器迁移（Phase 04 候选）

Phase 04 完成容器级验收与发布候选，但**发布门禁仍为红灯**；证据等级
`CONTAINER_VERIFIED`，不是“真实 VPS 已验证”，真实 ACME 不纳入本轮。

### 新增

- **Go 自更新通道**：`idleleo update status|check|apply|configure`。manifest
  `channel=go`、per-asset SHA256/size、ELF 校验、原子替换、健康检查、失败回滚；
  错误 SHA、截断下载、非 ELF、降级、磁盘满均保留旧二进制；恢复失败 exit 10。
- **证书外部续约契约**：DER 指纹基线，变化才 `restart xray` / `reload nginx`；
  未变不重启；world-readable 私钥拒绝 reload；到期/<30 天显式降级。
- **服务类 CLI**：`idleleo service status|start|stop|restart|reload|logs`，
  仅允许 `xray`、`nginx`、`idleleo-schedule.timer`。
- **只读查询**：`idleleo stats [--json]`（真实 `xray api statsquery`）、
  `idleleo rill status`（absent/active/stale，不写 Rill 状态）。
- **发布候选**：`packaging/build-go-release.sh` 生成 linux-amd64/arm64 +
  `SHA256SUMS` + `manifest.json`；`assets/go/` 记录候选身份。

### 验证

- 固定 digest Ubuntu 24.04 特权 systemd 容器：`42/42 PASS`，含真实 Xray 统计、
  systemd 重启计数、证书变化/未变化、更新失败注入。
- 双架构产物各自在对应平台容器执行 exit 0；manifest 真实 HTTP 下载校验
  `verified=true`。
- `go test ./...` / `go vet ./...` exit 0。

### 已知限制

- `check_release_gate.py` 实测 exit 2（28 pending + 28 个功能测试缺失）；未改 JSON
  状态、未伪造执行器。因此未合并 `main`、未打 tag、未发 Release。
- 自动更新需显式配置 manifest URL，否则用户失去自动更新（每轮记录 `degraded`）。
- ACME 签发/续期/清理、Rill 安装/授权/卸载、`backup/restore/purge`、
  Xray/Nginx 更新、Fail2ban、防火墙、多发行版/SELinux、真实 VPS 均未实现或未验证。
- 详见 `docs/release/KNOWN_LIMITATIONS.md` 与 `docs/go/PHASE_04_REPORT.md`。

## 未发布 — Go 管理器迁移（Phase 03 收尾）

实验性 Bash → Go 迁移路径补齐 Phase 03 缺口；证据等级为容器级
`CONTAINER_VERIFIED`，**不是“真实 VPS 已验证”**，真实 ACME 不纳入本轮。

### 新增

- **原生 Go 定时入口**：`idleleo schedule install|remove|run|status`，
  由 `idleleo-schedule.timer` 接管旧 cron 的 `auto_update.sh`、`ssl_update.sh`、
  `geo_update.sh`、`xray_stats.sh`。GeoData 刷新与统计采集为完整实现
  （原子替换、真实 Xray Stats API）；自动更新与证书续期为**显式降级**
  （无 Go release 通道 / 无 ACME），每轮写入 `schedule.log`，不再静默暂停。
- **Rill 契约**：审计、快照、候选预验收、激活与回滚均纳入 Rill 状态与文件哈希；
  观测漂移时 validate 以 exit 6 拒绝。
- **迁移审计增强**：`bridge audit --summary` 展示完整变更摘要；未知 Xray 顶层键与
  自定义 nginx 片段进入 `customItems`，未确认时 `prepare` 以 exit 6 拒绝
  （`--acknowledge-custom`）。
- **权限/软链修复**：runtime config world-writable → 0644；私钥 → 0640 且归属 xray 组；
  runtime 配置符号链接与越界 entry 软链 → `blocked`；修复随回滚恢复原 mode/group。
- **03-D 预验收**：validate 运行转换后 metadata 的候选 `status --json`，校验
  `installed` 与 `config.matchesMetadata`；relay 允许无 runtime 配置。
- **故障注入**：`prepare --fault disk-full`（ENOSPC → exit 13，零 journal/plan）、
  Bash 下载截断、Go GeoData 下载截断；`activate --fault after-schedule` 可在
  timer 安装与权限修复后中断并回滚。

### 修复

- `packaging/install.sh` manifest 解析括号错误（对 dict 调用 `.get` 后再 `json.load`）。
- relay 无 runtime 配置时 `status` 报错，导致 03-D 预验收无法通过。

### 迁移说明

- 迁移仅在 `idleleo --update` 的真实 TTY 手动路径提示；`--yes` 与自动更新不触发。
- 保留配置、证书/私钥、用户、用户自定义 cron 与 nginx 自定义片段。
- 回滚使用 `/opt/idleleo/recovery/idleleo-recover`；已 `COMMITTED` 后不隐式逆向迁移。
- 本轮未合并 `main`、未打 tag、未发 Release。

## 3.3.4 — 2026-11-05

菜单 i18n 的 locale 依赖修复，以及 GeoData 手动刷新前置确认。

### 修复

- **菜单不再依赖系统 locale**：主脚本直接读取 `.mo` 生成离线查表函数，
  所选语言 → 英文 → msgid 逐级回退；最小 Ubuntu/CentOS 只生成
  `C/C.utf8` 时，选英文也能得到英文菜单，不再退回中文。
- **语言前缀同步刷新**：切换语言后 `[信息]/[错误]/[警告]` 一起更新，
  不再出现英文菜单配中文前缀。
- **菜单语言显示修复**：中文默认不再显示空的“当前语言”，最小镜像也不会
  再因未生成的 locale 打印 `setlocale` 警告。
- **GeoData 手动刷新加确认**：默认 N，直接回车取消；文案说明会下载
  `geoip.dat` 与 `geosite.dat`、写入目录、Xray 运行中会重启以及大致耗时。
  取消返回 1，与 `--stats-reset` 一致；自动化可用
  `GEO_REFRESH_ASSUME_YES=1` 跳过确认。
- **真实终端宽度自适应**：统计表和主菜单改用 `/dev/tty` 的 `stty size`，
  不再在命令替换里依赖永远为假的 `[[ -t 1 ]]`；45/80/100/120 列真实 tmux
  下框线不再折断。
- **实时监控修复**：删除顶层误用的 `local`，`--watch` 的 stderr 为空；
  首次查询成功前不打印标题，API 不可达时 stdout 仍为 0 字节。
- **GeoData 迁移 fail-closed**：旧目录出现子目录/符号链接时不再“成功”迁移后
  删除；保留原目录、旧 cron 与失败标记。复制失败会清理本次写入的 `.dat`，
  同名不同内容的旧文件保留为备份。隐藏普通文件（`.foo`）与两个 `.dat` 一样
  纳入复制和备份比较，不再被备份清理静默删除。managed 状态不再重复打印
  “已切换”日志。
- **安装/更新路径统一迁移**：`set_xray_config_path` 不再自行 `mv` 覆盖，而是
  复用上面的同一个事务式迁移；单个 `.dat`、同名不同内容、隐藏文件和非普通
  条目都按同一策略处理。迁移失败时 `xray_install`/`xray_update` 中止，不再
  继续启动服务。
- **主菜单行宽与清屏**：内容行与节标题/分隔线都按显示宽度截断，Rill 检测
  长句按词换行；45/80/100/120 列真实终端下每一行（含 fr/ru 等长翻译的
  `├─` 标题行）都闭合在框线内，不再折行或越界。`NO_COLOR=1` 时
  `menu_clear`/`rxa_clear_screen` 不再调用 `clear`，菜单在真实 PTY 上 0 ESC。
- **`--stats` 只读契约**：旧 `status_config.json` 的清理移到 root 检查之后；
  非 root 运行 `--stats` 不再删除任何文件。
- **菜单与统计一致性**：缺语言目录时与统计 helper 一样回退英文；菜单预初始化的
  “未安装/信息/警告/错误”会随语言刷新；无 `api.listen` 时统计菜单明确提示。
- **systemd 沙箱边界**：`ProtectSystem=strict` 下支持多条 `ReadWritePaths`
  累加；真实 systemd + `User=nobody` 容器验证：没有资产写路径时 fail-closed，
  有 `/etc/idleleo/share/xray` 与日志写路径时迁移成功且服务保持 active。
- **其它修复**：`--reset` 提示补回 `Y`；`countdown` 在 `NO_COLOR`/`TERM=dumb`
  下 0 ESC；旧 `status_config.json` 在启动与 `--stats` 时清理；“只刷新单个
  `.dat`”的不可实现选项已移除；“其他选项”新增 GeoData 直达入口；修正英文
  翻译（`geo_update.sh`、`Active jail list` 等）；流量阻断表格按 UTF-8 单元
  宽度对齐。
- **恢复/卸载/清空证书加菜单确认**：这三项在备份恢复菜单里默认 N，
  确认前不会覆盖配置、卸载服务或删除证书。

## 3.3.3 — 2026-11-05

GeoData 自动迁移与统计界面改版。

### 改进

- **GeoData 全自动迁移**：启动钩子仍是唯一路径，不再让用户在菜单里选择
  “立即迁移 / 移除旧任务”。仅当检测到旧 `geo_update.sh` cron 或真实
  `/usr/local/share/xray` 目录时才执行。注意：**只有 3.3.3 及以后版本的自更新
  能在同一进程内完成迁移；真实 3.3.2 进程没有这段代码，升级后会在下一次启动
  或进入菜单时迁移。**
- **状态单一来源**：custom 配置不再被摘要误报为“原生自动刷新”，迁移失败态
  不再同时显示“已开启”。菜单只展示事实状态与手动补刷入口。
- **统计界面**：总览与入站明细分区、框线、右对齐数值、B/KB/MB/GB 自动换算；
  3.3.3 的自适应只在显式 `XRAY_STATS_WIDTH` 时有效，真实终端自动检测在 3.3.4
  修复。
- **实时监控**：固定标题、刷新间隔与退出提示，TTY 下清屏且退出恢复光标。
  3.3.3 顶层误用 `local`，非 TTY 的 stderr 也会被污染，3.3.4 修复。
- **统计多语言**：表格、空态、错误与确认接入现有 gettext 体系，六种语言同步；
  缺译时非中文环境回退英文。
- **语言选择修复（3.3.3 未生效）**：3.3.3 使用 `LANGUAGE` + `C.UTF-8`，
  在 Ubuntu 24.04 / CentOS Stream 10 的 glibc 下不会选择目录，实际仍退中文；
  3.3.4 改为直接读取 `.mo`。
- **统计菜单**：顶部显示当前开启状态与 `api.listen`，开/关确认明确会重启 Xray。

### 约束

- `--stats --json` 的 `schemaVersion: 1` 结构与退出码
  `0/1/2/3/4/5/130` 保持不变；失败态 stdout 仍为空。
- GeoData 迁移继续 fail-closed：配置测试失败、重启失败、布局失败均回滚并保留
  旧 cron；手写 cron、未运行服务不重启。

## 3.3.2 — 2026-11-04

流量统计读取与发布资产版本。

### 新增

- **统计读取**：新增 `--stats`、`--stats --json`、`--stats-reset`、
  `--stats-watch [秒]` 和“其他选项 → Xray 流量统计”子菜单；读取委托
  `/etc/idleleo/scripts/xray_stats.sh`（0600 root），主脚本不复制查询逻辑。
- **回环统计 API**：统计片段新增 `api.listen=127.0.0.1:10085`，不引入
  `HandlerService`/dokodemo-door；旧 v3.3.x 统计配置首次读取时确认补写，
  失败自动还原原配置。
- **第五 Release 资产**：发布 `xray_stats.sh`、`SHA256SUMS` 与
  `release-manifest.json` 的 `statsScriptSha256`；脚本缺失时按 SHA 校验下载，
  校验失败只影响读取，不影响统计开关。

### 验证与门禁

- 新增 `test_xray_stats_readout.sh`，覆盖查询、reset、watch、JSON、
  未开启/无监听/API 不可达/坏 JSON/非 root/校验失败等失败态，且断言
  所有失败态 stdout 为空、无假 0。
- 现有 16 项统计幂等测试保留；Debian 12、Ubuntu 24.04、CentOS Stream 10
  真实 Xray CI 矩阵均通过（16/16 + 25/25）。

## 3.3.1 — 2026-11-02

审计复核后的修复版本。

### 修复

- **非交互 `-u` 假成功**：`read` 失败、非 TTY、EOF 返回非零并明确提示“未升级”；
  `--yes` 只自动确认同一 minor，跨 minor 必须显式 `--allow-major`
  （非交互场景仍需同时给 `--yes`）。`-u auto_update` 的跨 minor 保护不变。
- **离线 `--purge` 残留**：不再依赖 `xray_installer_ref`/metadata，也不依赖二进制
  是否存在，直接 stop/disable（unit 存在时）、删除 Xray 二进制、`/usr/local/etc/xray`、
  配置目录和 systemd unit 并 `daemon-reload`；保留配置的选择不变。
- **中转卸载中断**：Nginx 目录/unit 已不存在时不再让 `uninstall_nginx --force`
  返回失败，relay purge 能继续删除 `/etc/idleleo`；清理后不再向已删除的日志
  文件写入（消除 `tee: No such file or directory` 假错误）。
- **备份权限与失败处理**：备份使用 0600，旧备份迁移；tar 非零时删除半成品并返回失败，
  不再报告“备份成功”。
- **日志泄密**：日志目录 0700、`install.log`/归档 0600；`basic_information`
  的 UUIDv5 映射字符串与 `mode_switch_reuse` 的完整 UUID 仅输出到终端/信息文件，
  不写 `install.log`；旧日志做权限迁移。CI 脱敏与诊断扫描同步覆盖
  `UUIDv5`/`映射字符串`/`idc`。
- **缺 Xray 修复**：二进制不存在时按安装/修复路径继续 `-x`，不再因无法备份而拒绝。
- **失败记录与 installer 身份**：记录增加 `schema:2`、`installer_ref`/`installer_sha`；
  同一 Xray 版本换 installer 会重试；无 schema 的旧格式 Xray/Nginx 记录各允许
  一次重试；schema:2 的空身份记录不会每天重复重试。
- **Shell 版本防护**：`auto_update.sh` 读取实际安装的 `shell_version` 数值比较；
  在线版本低于已安装版本时拒绝降级且不写 `install_config`；启动时修正
  config 与实际脚本版本不一致。
- **Purge 混合态与损坏元数据**：relay purge 一并清理残留的 `/usr/local/etc/xray`、
  `/usr/local/share/xray`、`/usr/local/bin/xray` 和 Xray unit；`install_config.json`
  损坏时只输出诊断警告，不再把已完成的文件清理报告为失败。
- **Release 重发与 API 基线**：Release 工作流在幂等重跑时也刷新 jsDelivr，
  并同步写入 `compatibility-baselines.json`；3.3.1 基线覆盖
  `direct`/`shell-first`/`reinstall`/`failure-recovery`/`restart-recovery`/`fallback`。
- **非 root `idleleo -s`**：在纯只读分发前明确提示需要 root（信息文件保持 0600），
  不再以原始 Permission denied 失败。

### 同版本重发说明

3.3.1 为同版本重发，安装器字节已更新但 `shell_version` 仍为 3.3.1。已安装旧 3.3.1 的
节点不会通过 `-u` 自动获得新安装器（同版本跳过）；`-x` 只更新 Xray 核心，不更新
Shell。请用重新安装/手动覆盖 `/etc/idleleo/install.sh` 的方式取得新包。

### 验证与门禁

- 新增定向测试：非交互确认与同/跨 minor 三档、离线卸载、备份权限/tar 半成品/
  低权限读取、`basic_information` 日志隐私、缺 Xray 修复（走生产备份函数）、
  失败记录 schema/空身份二次抑制、Shell 元数据回退、旧 `auto_update.sh` 路径。
- `relay-guards` 纳入 `release-gate` / `release-candidate-gate`；真实 purge
  （含二进制/unit 缺失的中断场景）、五模式全新安装矩阵、旧自动更新路径全部进入门禁。
- 文档补充两步升级、`--yes`、`--install-relay`、`--purge`、XTLS 迁移和
  自动更新不跨 minor 的说明；恢复被替换成中文的英文 README。

## 3.3.0 — 2026-11-02

首个把第四阶段优化完整交付的 Shell 版本。

### 新增

- **中转节点**：独立的 Nginx Stream 单目标 TCP 转发角色，不安装 Xray、不终止 TLS、
  不收集落地私钥；支持改目标、改监听端口、Nginx 更新与卸载。
- **GeoData 原生热更新**：普通节点由 Xray 进程按 `0 3 * * 1` 自行下载并热重载
  Loyalsoldier `geoip.dat` / `geosite.dat`，不再依赖外部 cron，也不重启 Xray。
- **自动更新可靠性**：失败记录改为 `{组件, 目标版本, 时间}`；同一坏目标不反复重试，
  元数据出现新目标会自动重试；旧 `.xray` / `.nginx` 永久标记不再阻断未来版本。
- **元数据源回退**：jsDelivr 失败或返回非法/缺字段 JSON 时回退 GitHub Raw，
  两个源都必须通过字段与版本格式校验；既有 Release/SHA/manifest 校验不变。
- **版本降级保护**：按数字段比较版本；元数据回退到更旧版本时拒绝自动降级，
  `install.sh` 与 `auto_update.sh` 同步生效。
- **REALITY 客户端下限**：模板显式写入 `minClientVer: 1.0.0`，存量配置在更新前补齐，
  不覆盖用户设置，配置测试失败时逐字节回滚。
- **证书故障恢复**：证书续签失败不再把原本运行的 Nginx 留在停止状态；
  Xray 日志目录与文件的权限收紧为 `750` / `640`。
- **无 TLS 后端默认回环**：新建 ws/gRPC/xHTTP ONLY 安装默认监听 `127.0.0.1`，
  需要公网可达时必须显式指定地址。

### 变更（不兼容）

- **移除 XTLS ONLY 模式**。旧安装不会被自动删除或迁移；重装/切换会被明确拒绝，
  需要用户主动重新部署。`xtls-rprx-vision`（Vision 流控）与 Reality 均保留。
- 纯中转节点为独立服务器角色，不支持与普通节点同机混装，也不支持多落地、UDP/QUIC、
  PROXY Protocol 或智能分流。

### 兼容性

- 支持从 **3.3.0 及更高版本** 直接升级到后续 3.3.x。
- **3.2.9 / 3.2.10 / 3.2.11** 不支持直接升级到 3.3.0：请先升级 Shell（`-u`）再更新 Xray，
  或使用重装路径（保留或重建配置）。资格门禁按此策略验证真实支持路径，不使用
  expected-incompatible 豁免把失败刷成通过。

### 验证

- 本地定向回归：自动更新失败记录 46 断言、REALITY 下限 12、降级守卫 29、
  Xray 更新事务 53；安装菜单 221、重装调用链 160、GeoData 93、中转 112。
- 容器整机：Reality 32/32、Reality+Nginx 51/51、ws/gRPC/xHTTP 33/33、TLS 31/31、
  中转 30/30；Linux（Debian 12）`test_xray_version_pipefail` 通过。
- 真实 VPS 上的证书续签恢复、中转→真实落地端到端、Reality/TLS 外网完整数据面、
  低内存峰值与 `ProtectSystem` 组合仍需实机验证。
- 发布：tag `v3.3.0`，`Release Xray` run `41409994118` 成功；正式 API 资格验证
  run `41414537541` 30/30 通过（矩阵包含 `relay`）。3.2.12 从未发布，
  因此「3.2.12 → 3.3.0 直更」无法构造，标记为 NOT_RUN。
