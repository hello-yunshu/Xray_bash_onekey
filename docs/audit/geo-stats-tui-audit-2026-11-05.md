# GeoData 与流量统计 TUI 交互审计（2026-11-05）

## 结论

**新用户可以在有人口头指路的前提下完成“刷新 GeoData”和“查看统计”，但无法只靠界面稳定独立完成。** 主要卡点不是功能缺失，而是：

1. 手动刷新是**无确认的危险动作**：选中即下载，并可能重启 Xray。
2. GeoData 和流量统计都埋在“其他选项”里，入口名称对非技术用户不直观（“流量阻断”不是“GeoData”）。
3. 状态有两个来源且会互相矛盾：custom 配置同时显示“不会自动接管”和“由 Xray 原生 geodata 自动刷新”；失败标记和“自动刷新已开启”同时出现。
4. 统计菜单不显示当前是否已开启；开启/关闭提示没有说会重启 Xray。
5. 统计结果使用英文表头和原始字节数，Xray 未运行时只给英文技术错误，没有下一步动作。

如果只修一处：**先给手动刷新加确认**。如果修三处：见文末。

---

## 环境与方法

- 干净 `debian:12-slim` 容器（arm64），执行完整安装链：
  `bash .github/test/test_install.sh reality`，结果 **32 passed / 0 failed**。
- 真实 Xray **26.10.31**，真实 Reality 入站，真实 `api.listen=127.0.0.1:10085`。
- 容器没有 systemd；用 `/usr/local/bin/systemctl` shim 管理**真实 Xray 进程**（start/restart/stop/is-active 会实际启停 `/usr/local/bin/xray`），因此状态文案对应的服务状态是真实的。
- 安装后把 `/etc/idleleo/{install.sh,scripts/*.sh}` 刷新为当前 main 版本；v3.3.2 Release 里的脚本仍是被审计前的旧文案，直接装 tag 资产会看到旧界面。
- TUI 在 `tmux` 中按 100×30 和 80×24 真实按键操作；截图来自 `tmux capture-pane -p -e`，用 pyte 解析 ANSI 后渲染 PNG，保留配色。
- 真实流量：容器内启动一个 Xray Reality 客户端，经本地 10808 socks 访问 `https://www.example.com`，服务端 `VLESS-Reality-in` 统计出现非零 UPLINK/DOWNLINK。

### 会话轨迹（真实按键）

| 路径 | 输入序列 | 结果 |
| --- | --- | --- |
| 主菜单 | 启动后等待 6s | 主菜单，`Xray: 运行中..` |
| GeoData | `6` → `4` → `3` | 进入“刷新 GeoData” |
| Geo 手动刷新 | `1` | 无确认，直接 `正在手动刷新全部 GeoData...` |
| Geo 子菜单 | `4` → `2` | 无确认，直接 `正在运行 geo_update.sh...` |
| 统计菜单 | `6` → `3` | 进入“Xray 流量统计” |
| 统计开启确认 | `1` → `y` | 停 Xray、写 stats/api/policy、启动 Xray |
| 统计读取 | `2` | 表格；非零流量后显示 3839/5717/9556 |
| api.listen 补写 | `2` → `n` / `y` | N 保持配置不变；Y 补写并重启 |
| 实时监控 | `4` | 只反复打印表格，无标题/退出提示；Ctrl-C 返回菜单 |
| 统计关闭 | `1` → `y` | 停 Xray、删除 stats/api/policy、启动 Xray |
| CLI 表格 | `idleleo --stats` | rc=0 |
| CLI JSON | `idleleo --stats --json` | rc=0，`jq -e .` 通过 |
| CLI 监控 | `timeout 3 idleleo --stats-watch 1` | rc=124（被 timeout 终止） |
| 非 root | `runuser -u nobody -- idleleo --stats` | rc=5，`统计查询需要 root 权限` |

---

## 问题清单

### P0 — 阻断或容易误操作

| ID | 问题 | 证据 | 最小改法 |
| --- | --- | --- | --- |
| P0-1 | 手动刷新没有任何前置确认。选中 `1` 立即下载并替换 GeoData；Xray 正在运行时脚本会重启 Xray。用户可能在业务高峰误按数字键，连接被短暂中断。 | `geo-manual-refresh-running.png` 中 `请选择一个选项:1` 后直接出现 `正在手动刷新全部 GeoData...`，没有 Y/N；`geo-manual-refresh-done.png` 才出现 `脚本已重启 Xray`。 | 执行前一行确认：`将下载 GeoData 并重启 Xray（约中断数秒），是否继续？[y/N]`，默认 N；`--yes` 等非交互语义另行定义。 |

### P1 — 明显影响理解或完成

| ID | 问题 | 证据 | 最小改法 |
| --- | --- | --- | --- |
| P1-1 | 入口深且命名不直观：主菜单没有 GeoData 或流量统计；GeoData 在 `6 其他选项 → 4 Xray 流量阻断 → 3 刷新 GeoData`，统计在 `6 其他选项 → 3 Xray 流量统计`。外行不知道“流量阻断”里藏着 GeoData。 | `main-menu.png`；会话轨迹。 | 主菜单直接增加两项，或把“其他选项”改成“工具与状态”并在主菜单状态栏显示 GeoData/统计当前状态。 |
| P1-2 | 统计菜单不显示“当前已开启/未开启”，用户点“开启/关闭统计”前无法知道会开还是关。 | `stats-menu.png` 只有四个动作，没有状态行。 | 菜单顶部加一行：`当前状态：已开启（api 127.0.0.1:10085）/ 未开启`。 |
| P1-3 | 统计开启/关闭提示没有说会**重启 Xray**，也没说会写入 `stats/api/policy`；只写“需要使用 api / 可能影响性能”。实际输出紧接着 `Xray 停止/启动`。 | `stats-enable-confirm.png`；`stats-enable-progress.png`；关闭流程 `stats-disable-done.png`。 | 提示改为：`将写入 stats/api/policy 并重启 Xray（短暂中断），是否继续？[y/N]`；关闭同理。 |
| P1-4 | 统计表格是英文表头 + 原始字节数，没有 KB/MB、占比或“暂无流量”解释；与中文菜单混排。 | `stats-table.png`：`Uptime / INBOUND / UPLINK_BYTES / DOWNLINK_BYTES / TOTAL_BYTES`，数值 3839/5717/9556。 | 表头中文化；字节做人类可读格式化；零流量时显示“暂无流量”。 |
| P1-5 | 实时监控没有标题、刷新间隔、时间戳或退出提示，只剩一张反复刷新的表；用户只能猜 Ctrl-C。 | `stats-watch.png`；Ctrl-C 后实测直接返回统计菜单，无“已退出监控”提示。 | 顶部固定一行：`实时监控（每 N 秒刷新，Ctrl-C 退出）` + 最后刷新时间。 |
| P1-6 | Xray 未运行时，统计只给英文技术错误 `Xray is not running or the stats API is unreachable at 127.0.0.1:10085`，没有“先启动 Xray / 检查 api.listen”的下一步。 | `stats-xray-down.png`。 | 中文错误 + 下一步：`Xray 未运行，请先到 Xray/TLS 菜单启动，或检查 api.listen`。 |
| P1-7 | custom geodata 状态自相矛盾：状态头说 `[自定义 geodata] 已跳过本项目托管，不会自动接管`，下一段摘要却说 `由 Xray 原生 geodata 自动刷新`，并展示 custom 的 `0 5 * * *`。 | `geo-menu-custom.png`。 | 摘要也基于 `geodata_state` 分支；custom 时显示“自定义配置，本项目不接管”，不再显示“原生自动刷新”；手动刷新项应隐藏或明确警告会写托管目录。 |
| P1-8 | 失败态重复且矛盾：状态头先显示 `[自动刷新已开启]`，紧接着 `[自动刷新开启失败]`；摘要再次打印 `上次切换自动刷新失败`。 | `geo-menu-failure.png` 两个黄色警告内容相同。 | 失败标记存在时只显示一次“上次开启失败，当前状态需重试确认”，不要同时宣称“已开启”；删除摘要里的重复失败行。 |
| P1-9 | “自动刷新未开启”不能持久：删除 `.geodata` 后重新启动 TUI，启动钩子会自动补回；菜单没有“关闭自动刷新”入口。真实输出：删除后 `has("geodata")=false`，启动一次 TUI 后变为 `true`，并打印 `已从脚本模式切换为自动刷新`。 | 实测命令输出；`geo-menu-auto-off.png` 只能在 TUI 运行中改配置后看到。 | 启动钩子只在“存在本项目旧 cron”时迁移；增加“关闭自动刷新（删除 .geodata）”菜单项并确认。 |
| P1-10 | 80 列下“流量阻断”规则表分隔线折行、列错位：分隔线被拆成 `--------` 单独一行，中文列与“已禁用”不对齐。 | `width-80-geo-rules.png`。 | 表格宽度按终端列数动态收缩，或 80 列时切换为紧凑列表。 |
| P1-11 | 用户无法判断“上次自动刷新是否成功”：摘要明确说“不代表某次自动刷新已成功”，只给文件 mtime，没有日志入口。 | `geo-menu-auto-on.png` 中 `说明: ... 不代表某次自动刷新已成功`。 | 增加“查看最近一次 GeoData 刷新日志”菜单项（`journalctl -u xray` 过滤 `app/geodata`），并把 mtime 标签写成“最后刷新时间（不代表成功）”。 |

### P2 — 文案与打磨

| ID | 问题 | 证据 | 最小改法 |
| --- | --- | --- | --- |
| P2-1 | 配置不可解析时只说“请先修复 config.json 后重试”，没有备份/恢复入口或示例。 | `geo-menu-invalid.png`。 | 追加一行：`可先修复 JSON；最近备份在 /etc/idleleo/xray_bash_*.tar.gz`。 |
| P2-2 | 手动刷新失败提示给了日志路径，但没有可直接复制的一条命令。 | `geo-manual-refresh-failed.png`；`geo-manual-refresh-xray-down.png` 是正常未运行路径，不是失败。 | 追加：`排查：tail -n 50 /etc/idleleo/logs/geo_update.log`。 |
| P2-3 | 取消统计开启/关闭/api 补写后还要按一次 Enter（`回到菜单 [Enter]`），取消路径多一步。 | `stats-enable-cancel.png`；`stats-api-listen-cancel.png`。 | 取消后直接回菜单，不再 pause；只有执行动作才 pause。 |
| P2-4 | 确认与警告配色不统一：统计提示是绿色背景黑字，GeoData 失败是黄色背景/文字；同样是“是否继续”，视觉含义不一致。 | `stats-enable-confirm.png`、`geo-menu-failure.png`。 | 统一：危险确认用黄色/红色，普通状态用绿色。 |
| P2-5 | 主菜单头 `当前语言:` 为空，`Xray: 运行中..` 有两个点；对首次用户像渲染故障。 | `main-menu.png`。 | 语言为空时显示 `自动`；状态文案去掉重复标点。 |
| P2-6 | 术语没有解释：`GeoData`、`api`、`api.listen`、`geoip.dat/geosite.dat` 直接暴露给普通用户。 | GeoData 菜单、统计确认、api 确认截图。 | 首次出现时加一句白话解释，例如“GeoData 是 IP/域名路由数据”。 |
| P2-7 | 统计表全 0 时不区分“统计正常但暂无流量”和“统计没工作”。 | `stats-table.png`。 | 全 0 时显示“暂无流量；若刚开启统计，请产生一次访问后刷新”。 |
| P2-8 | “手动刷新 geoip.dat / geosite.dat”看起来只更新一个文件，但底层 updater 从同一个不可变 release 同时替换两个文件。 | 代码行为与 `geo_update.log` 的 “All GeoData files are current and match release ...” 一致；菜单没有说明。 | 文案改为“刷新全部（同时更新 geoip/geosite）”，或真正支持单文件。 |
| P2-9 | 长失败文案在 100 列下折行后第二行没有缩进，`可在此重试` 顶格，和上一条警告粘连。 | `geo-menu-failure.png`。 | 失败信息拆成两行并缩进续行。 |

### 这里没问题

- 自动刷新已开启时，状态头清楚给出 `0 3 * * 1` 和“每周一 03:00”，并明确“无需手动操作”；配色可辨。`geo-menu-auto-on.png`。
- 统计开启/关闭/api 补写的 Y/N 语义有效：N 不改配置，Y 执行并重启；实测配置与进程状态一致。`stats-enable-cancel.png`、`stats-api-listen-cancel.png`。
- api.listen 补写确认明确写了“补写并重启 Xray”，是三条确认里最清楚的。
- CLI `--stats --json` 输出是合法 JSON，字段可被脚本消费：`schemaVersion/version/server/uptimeSeconds/inbounds`。
- 统计表格在 80 列下仍能对齐，问题主要出在 100 列宽度的规则表。
- 手动刷新失败时会明确说 config.json 未改、未创建定时任务，并给日志路径；比只报 rc 好。
- Xray 未运行、手动刷新完成时，提示 `Xray 未运行, 未执行重启`，没有误启动服务（在修正 shim 的 `is-active --quiet` 解析后实测）。

### 关键命令输出

```text
# 启动钩子会把“未开启”重新变成“已开启”
before=false
rc=0
after=true
已从脚本模式切换为自动刷新

# CLI 退出码
stats_rc=0
json_rc=0
json_valid=0
watch_rc=124          # timeout 3 idleleo --stats-watch 1
非 root：统计查询需要 root 权限（rc=5）

# Xray 未运行时的统计菜单
xray_stats: Xray is not running or the stats API is unreachable at 127.0.0.1:10085
```

---

## 截图索引

目录：`docs/audit/screenshots/geo-stats-2026-11-05/`

| 文件 | 内容 |
| --- | --- |
| [main-menu.png](screenshots/geo-stats-2026-11-05/main-menu.png) | 主菜单；GeoData/统计入口在 `6 其他选项` |
| [geo-menu-auto-on.png](screenshots/geo-stats-2026-11-05/geo-menu-auto-on.png) | GeoData 菜单，自动刷新已开启，含 cron 含义 |
| [geo-menu-auto-off.png](screenshots/geo-stats-2026-11-05/geo-menu-auto-off.png) | GeoData 菜单，自动刷新未开启（TUI 运行中修改配置后捕获） |
| [geo-menu-custom.png](screenshots/geo-stats-2026-11-05/geo-menu-custom.png) | custom geodata 的矛盾状态 |
| [geo-menu-invalid.png](screenshots/geo-stats-2026-11-05/geo-menu-invalid.png) | 配置不可解析 |
| [geo-menu-failure.png](screenshots/geo-stats-2026-11-05/geo-menu-failure.png) | 失败标记 + “已开启”矛盾/重复 |
| [geo-manual-refresh-running.png](screenshots/geo-stats-2026-11-05/geo-manual-refresh-running.png) | 从子菜单执行手动刷新，无确认，执行中 |
| [geo-manual-refresh-done.png](screenshots/geo-stats-2026-11-05/geo-manual-refresh-done.png) | 手动刷新完成 + 写入位置 + 重启结论 |
| [geo-manual-refresh-xray-down.png](screenshots/geo-stats-2026-11-05/geo-manual-refresh-xray-down.png) | Xray 未运行时手动刷新，不重启 |
| [geo-manual-refresh-failed.png](screenshots/geo-stats-2026-11-05/geo-manual-refresh-failed.png) | 模拟下载失败，错误 + 日志路径 |
| [stats-menu.png](screenshots/geo-stats-2026-11-05/stats-menu.png) | 统计菜单，无当前状态 |
| [stats-enable-confirm.png](screenshots/geo-stats-2026-11-05/stats-enable-confirm.png) | 开启统计确认，只说 api/性能 |
| [stats-enable-progress.png](screenshots/geo-stats-2026-11-05/stats-enable-progress.png) | 确认后实际 Xray 停止/启动 |
| [stats-enable-cancel.png](screenshots/geo-stats-2026-11-05/stats-enable-cancel.png) | N 取消 + 额外 Enter |
| [stats-api-listen-confirm.png](screenshots/geo-stats-2026-11-05/stats-api-listen-confirm.png) | 缺少 api.listen 的补写确认 |
| [stats-api-listen-cancel.png](screenshots/geo-stats-2026-11-05/stats-api-listen-cancel.png) | N 取消，配置未改 |
| [stats-table.png](screenshots/geo-stats-2026-11-05/stats-table.png) | 菜单表格视图（真实非零流量） |
| [stats-cli-table.png](screenshots/geo-stats-2026-11-05/stats-cli-table.png) | `idleleo --stats` 表格 |
| [stats-cli-json.png](screenshots/geo-stats-2026-11-05/stats-cli-json.png) | `idleleo --stats --json` |
| [stats-watch.png](screenshots/geo-stats-2026-11-05/stats-watch.png) | 实时监控，无标题/退出提示 |
| [stats-disable-confirm.png](screenshots/geo-stats-2026-11-05/stats-disable-confirm.png) | 关闭统计确认 |
| [stats-disable-done.png](screenshots/geo-stats-2026-11-05/stats-disable-done.png) | 关闭后 Xray 停止/启动 |
| [stats-xray-down.png](screenshots/geo-stats-2026-11-05/stats-xray-down.png) | Xray 未运行时的英文技术错误 |
| [width-80-geo-rules.png](screenshots/geo-stats-2026-11-05/width-80-geo-rules.png) | 80 列下规则表错位 |

---

## 如果只能改三处

1. **给手动刷新加确认（P0-1）**：默认 N，明确“会下载并可能重启 Xray”。这是唯一可能让用户在无预期的情况下中断生产流量的动作。
2. **统计菜单加当前状态 + 把重启/写配置写进确认（P1-2、P1-3）**：用户不需要猜现在是开还是关，也不会在不知情时重启 Xray。
3. **把 GeoData 提升为一级入口并统一状态来源（P1-1、P1-7、P1-8）**：主菜单可直接进入；状态头成为唯一状态来源，custom 不再显示“原生自动刷新”，失败态不再同时说“已开启”。

其余 P1（统计英文字段、watch 提示、Xray 未运行下一步、80 列表格、无关闭自动刷新入口）可以随后按表格逐条做，都是小改文案/分支，不需要重构菜单。
