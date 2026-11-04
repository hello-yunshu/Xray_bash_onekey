# CHANGELOG

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
