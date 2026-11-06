# F01–F28 功能完整性与迁移追踪矩阵

> 根据 v3.1 规划和本次实际源码核对整理；基线主仓库为 `4752f77`。**下表「负责阶段」表示计划，不表示已经实现。正式开发时每行必须补充 PR、测试日志与通过/拒绝的结果。**

| ID | Bash 已有功能 | 源码锚点 | Go 职责 | 开发阶段 | 最小验收证据 | 当前状态 |
|---|---|---|---|---|---|---|
| F01 | `--install-reality`、Reality 普通/加 Nginx | `install.sh:12127+` / `config/vless_reality.json` | `app` + `xray` + `nginx` | 02 | 真实 Xray -test + 进程健康 | 待开发/待验证 |
| F02 | `--install-tls`，ws/gRPC/xHTTP 和组合模式 | `install.sh:12954+` / `config/vless_tls.json` | `xray` + `nginx` + `cert` | 02 | ws/gRPC/xHTTP 单独与组合配置验收 | 待开发/待验证 |
| F03 | `--install-none`，受信后端 | `install.sh:9156+` / `install.sh:12954+` | `xray` + `host` | 02 | 无 TLS 回环监听 + 显式非回环确认 | 待开发/待验证 |
| F04 | Reality 负载均衡 primary/secondary | `install.sh:154xx` Reality primary/secondary wizard | `xray` + `nginx` | 02 | primary 与 secondary 分别启动 | 待开发/待验证 |
| F05 | `--install-relay` / 独立中转菜单 | `install.sh:11143–11951` | `relay` + `nginx` | 02/03 | 无 Xray 的 Nginx Stream TCP 字节转发 | 待开发/待验证 |
| F06 | 查看/添加/删除用户、UUIDv5 | `install.sh:10375–10574` | `xray` + `change` | 02 | 增删失败注入恢复原 active/配置 | 待开发/待验证 |
| F07 | Reality shortId、spiderX 与用户映射 | `install.sh:10420–10457` | `xray` | 02 | UUID / shortId / spiderX / 主用户对应关系 | 待开发/待验证 |
| F08 | 修改端口、target、serverNames、SNI Guard | `install.sh:10041+` / Nginx config | `xray`/`nginx` + `change` | 02 | 冲突、无权限、reload 失败时差异/恢复 | 待开发/待验证 |
| F09 | `--add-upstream`、Nginx 负载均衡文件管理 | `scripts/file_manager.sh:145–212` | `nginx` + `host` | 02 | 自有 Nginx 片段编辑与原规则保留 | 待开发/待验证 |
| F10 | `--tls` 版本变更 | `install.sh:9963–10012` | `nginx` + `change` | 02 | 目标 Nginx -t 失败原配置不变 | 待开发/待验证 |
| F11 | Xray/Nginx 服务状态、启停、日志 | `install.sh:8622–8663` | `host` + `app` | 02 | 服务原 active/enabled 与日志权限 | 待开发/待验证 |
| F12 | `--cert-status`、签发、续期、清理 | `install.sh:7316+` / `scripts/ssl_update.sh` | `cert` | 02 | 证书 NotAfter、续期变化前后状态 | 待开发/待验证 |
| F13 | `--update`、`--xray-update`、`--nginx-update` | `install.sh:12825+` / Nginx manifest | `app` + `host` | 02/03 | 哈希/降级/运行服务故障注入 | 待开发/待验证 |
| F14 | 原有 `--auto-update` 与 cron | `scripts/auto_update.sh:394–512` | `app` + 有界定时入口 | 02/03 | cron 不触发 Go 迁移的负向测试 | 部分实现（容器级）：`internal/schedule` timer 真实触发；auto-update 显式降级 |
| F15 | `--stats`、`--stats --json`、watch/reset | `install.sh:10751+` / `scripts/xray_stats.sh` | `xray` + `cli` | 02 | 真实 `--stats --json` 字段/退出码比对 | 部分实现（容器级）：`stats-collect` 真实 Xray API；交互 CLI 未实现 |
| F16 | GeoData 原生热更新/手动刷新/旧布局 | `install.sh:5516+` / `scripts/traffic_blocker.sh` | `xray` + `legacybridge` | 02 | 原生热更新与 legacy cron 精确清理 | 部分实现（容器级）：`geodata-refresh` 原子替换 + 截断不覆盖 |
| F17 | IPv4/IPv6、DNS A/AAAA、端口、防火墙 | `install.sh:623+` / firewall test files | `xray` + `host` | 02 | IPv6 literal、DNS A/AAAA、防火墙回滚 | 待开发/待验证 |
| F18 | 分享链接、二维码、Clash 配置 | `install.sh:9190+` / README | `xray` + `cli` | 02 | 分享 URI 和 Clash YAML 可解析 | 待开发/待验证 |
| F19 | 备份/恢复/重配置保留/模式切换 | `install.sh:14250+` / `restore_directories()` | `change` + `store` + `legacybridge` | 02/03 | 自定义 routing/DNS + 增量修改无破坏 | 待开发/待验证 |
| F20 | Fail2ban 管理（含 trusted/unban） | `scripts/fail2ban_manager.sh` | 可选 `app` + `host` 集成 | 02 | 非项目 jail 在卸载后保持原样 | 待开发/待验证 |
| F21 | 流量阻断与自定义路由 | `scripts/traffic_blocker.sh` | `xray` + `change` | 02 | 规则生成后 xray -test 成功 | 待开发/待验证 |
| F22 | Rill 观察、诊断、授权、卸载两阶段 | `install.sh:1267–1298` / Rill payload | `rill` 受控适配 | 02/03 | Agent 缺失/存在、授权、正确解释器 | 部分实现（容器级）：状态/交接/漂移拒绝已纳入 Bridge；管理命令未迁移 |
| F23 | 中文/英文/法文/俄文/波斯文/韩文 | `i18n/languages/` / `install.sh` | `cli` | 02 | 六语言目录回退和窄屏可读 | 待开发/待验证 |
| F24 | Docker 原有交付 | `docker/docker-entrypoint.sh` / `docker/fake-systemctl` | `packaging` | 02/04 | fake-systemctl/entrypoint 与镜像试跑 | 待开发/待验证 |
| F25 | TCP 优化与测速快捷工具 | `install.sh:10823+` / `install.sh:15218+` | 可选独立命令 | 02（可延期） | 不执行浮动脚本；如延期写 release notes | 待开发/待验证 |
| F26 | `XTLS ONLY` 旧模式 | `install.sh:12988+` | `legacybridge` 只读识别 | 00/03 | 旧 XTLS 只读识别并阻断激活 | 待开发/待验证 |
| F27 | `--backup`、`--restore`、`--purge`、`--service-*` 等历史参数 | `install.sh:12954–13162` / `15903–15998` | `cli` 兼容别名 | 00/01/02 | 旧 flag 参数/JSON/退出码对照 | 待开发/待验证 |
| F28 | 运行态及分享信息展示 | `install.sh:15944+` / README | `cli` + `store` | 01/02 | 打开/--show 无网络无写入 | 待开发/待验证 |

## 使用规则

- Phase 00 补齐具体命令分发表：旧 flags、菜单入口、新 Go 命令、命令副作用级别、非 TTY 行为与兼容决策（硬兼容/安全拒绝/明确废弃）。
- Phase 01 落实 F27/F28 的基础 CLI，不能因为 `--help` 可运行便判定全功能完成。
- Phase 02 每完成一个业务包，填写真实测试产物与复现命令，更新 `功能: Go 实现路径 / 用例编号 / 结果 / 责任提交`。
- Phase 03 对迁移成功/失败的旧环境再次回测 F06/F07/F15/F19/F26/F27（这是最可能丢失用户数据或自动化契约的区域）。
- Phase 04 以此表作为禁止静默功能倒退的发布门槛，少量复杂模式可以有显式不支持的界限，但不能不经批准就删除旧功能。
- `XTLS ONLY` 与 `xtls-rprx-vision` **不是同一个概念**：只阻断已废弃的旧安装模式，不能禁用 Reality/Vision。
