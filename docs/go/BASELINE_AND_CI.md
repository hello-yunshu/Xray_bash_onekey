# Phase 00 — 基线与 CI 状态

> 执行日期：2026-11-06（Asia/Shanghai）
> 仓库：`hello-yunshu/Xray_bash_onekey`（真实工作目录，非沙箱镜像）

## 1. 基线核验

| 项 | 值 |
|---|---|
| 初始工作树 | 分支 `feat/geodata-auto-stats-ui`，未跟踪 `.workbuddy/`、`docs/plans/` 被**原样保留** |
| 远端 `main`（执行时） | `59a87c6`（`Merge pull request #176`） |
| 行为基线 pin | `4752f77c58028ac169c429fe7674c20060b30c9e`（`install.sh` SHA-256 `0af8e8f2…cfa6`） |
| 版本 | `shell_version=3.3.4`；线上 API `shell_online_version=3.3.4` 且哈希一致 |
| 开发分支 | `develop/go-native`，基于 `origin/main@59a87c6`，**未合并 main** |
| 独立验证 checkout | `/tmp/xray-bash-clone`（干净 clone，`HEAD=4752f77`，`install.sh` 无改动） |

### 1.1 基线漂移

执行期间 `main` 从 `4752f77` 前进到 `59a87c6`（4 个提交）：

```
47d405d chore(actions): harden workflows for Xray_bash_onekey
c75d11f test(stats): wait for Xray API readiness instead of fixed sleep
95c4cff test(stats): print stderr when a stats query fails
160f01c test(stats): wait for statssys Uptime before querying
59a87c6 Merge pull request #176
```

差异审计结论：

```bash
git diff --stat 4752f77 59a87c6 -- install.sh scripts config
# （空）
git diff --name-only 4752f77 59a87c6
# .github/test/test_xray_stats_readout.sh
# .github/workflows/test-install.yml
# .github/workflows/cleanup-workflow-runs.yml（新增）
```

因此**行为基线仍是 4752f77**，但开发分支已包含上游 CI 修复；这正好修复了 1.3 的红灯。

## 2. 资产与 CI 清单

| 项 | 数量/内容 |
|---|---|
| `install.sh` | 单文件管理器（菜单 + CLI + 安装/更新/备份/Rill/统计/Geo） |
| `scripts/` | 20 个文件（13 个 Shell 脚本 + 7 个 Python 辅助），含 `auto_update.sh`、`geo_update.sh`、`ssl_update.sh`、`xray_stats.sh`、`fail2ban_manager.sh`、`file_manager.sh` |
| `.github/test/` | 82 个测试脚本（`.sh`/`.py`，含 `redact.sh` 辅助） |
| `.github/workflows/` | 基线 7 个；Phase 00 新增 2 个 Go 门禁 |
| `Test Install` | 10 个 job：`security-regression`、`rill-qualification`、`test-install`、`relay-guards`、`minimal-bootstrap`、`stats-readout-matrix`、`true-fresh-install`、`true-fresh-modes`、`release-gate`、`release-candidate-gate` |

**真实二进制测试**（非 mock）：`test_xray_stats_readout.sh`、`test_geodata_native.sh`
（真实 Xray 23/24/26 版本）；其余多为沙箱/合成资产。

## 3. 主线红灯：Stats Readout (ubuntu:24.04)

### 3.1 具体失败

- Run：`42048259341`，`headSha=4752f77`，事件 `push`，结论 `failure`。
- **唯一失败 job**：`Stats Readout (ubuntu:24.04)`；同一运行其余 21 个 job 全绿，`release-gate` 绿，
  `release-candidate-gate` 因无 candidate 输入而 skipped。
- 失败步骤：`test_xray_stats_readout.sh` 的 `enable and query`，4 项：

```
FAIL: query rc!=0
FAIL: table missing fields
FAIL: zero-traffic empty-state missing
FAIL: repeat query differs
```

- 时间线：`== enable and query ==` 14:47:17；`PASS: 10085 listener present` 14:47:19.475；
  首个查询失败 14:47:19.516；随后 `PASS: --json contract valid` 14:47:31，
  `PASS: query after migration` 14:47:55。

### 3.2 根因（已证实）

首次查询发生在 Xray 启动后约 1 秒的固定 `sleep` 窗口内，StatsService 尚未就绪；
后续查询全部成功。上游 PR #176 的修复提交标题直接给出了结论：

- `c75d11f test(stats): wait for Xray API readiness instead of fixed sleep`
- `160f01c test(stats): wait for statssys Uptime before querying`
- `95c4cff test(stats): print stderr when a stats query fails`

同一套测试在 #176 重跑后转绿并已合并到 `59a87c6`。

### 3.3 本地复现记录

| 实验 | 环境 | 结果 |
|---|---|---|
| 直接跑 `test_xray_stats_readout.sh` ×5 | `ubuntu:24.04` + Xray `26.10.31` | **5/5 PASS**（47/47） |
| 按 CI 顺序先跑 `test_xray_stats.sh` 再跑 readout ×3 | 同上 | **3/3 PASS** |
| 32 个 CPU 忙循环 + 无等待首查 ×3 | 同上 | **3/3 PASS**（首查约 1.2 s 后成功） |
| 对“拒绝连接”/“假监听”测 `xray api` 失败延迟 | 同上 | 约 3.1 s 后失败（与固定 1 s 等待矛盾） |

结论：**它是测试就绪等待不足导致的瞬态失败，不是产品稳定缺陷**；
在 `4752f77` 上按验收要求记为“已修复（上游 #176）”，不记为“未知即通过”。

### 3.4 其他红项

- `4752f77` 上 `Test Install` 仅上述 1 个 job 红；无其他红项。
- 新增 `go-release-qualification.yml` **按设计为红**（缺少生产 Go 与 28 个功能测试），
  它只在 `workflow_call` / `workflow_dispatch` 触发，不会污染 Bash 绿灯。
- 新增 `go-parity-stage.yml` 只在 PR / 手动触发；本阶段 push 分支不会自动运行它。

## 4. L0 执行环境（重要）

| 环境 | 结果 | 原因 |
|---|---|---|
| macOS 默认 `/bin/bash` 3.2 | **0/83** | `install.sh` 顶层 `declare -A` 失败；且无 `/etc/os-release` |
| Linux（`golang:1.24` 容器，bash 5） | **83/83** | Oracle 为 `LIVE_PINNED_CLEAN` 独立 clone |

因此 Phase 00 的差分门禁必须在 Linux + bash ≥ 4 下运行。
macOS 只能用于读取/编写，不能作为 Bash oracle 宿主。

## 5. R01–R24 复核

图例：**仍成立** / **部分过时** / **已修复**。行号指向基线（与当前行为一致）。

| 编号 | 复核结论 | 证据 |
|---|---|---|
| R01 | 仍成立 | [`install.sh#L15105-L15125`](../../install.sh#L15105-L15125)：更新用户时 stop → 写 → start，无候选配置校验 |
| R02 | 仍成立 | [`scripts/fail2ban_manager.sh#L1087-L1101`](../../scripts/fail2ban_manager.sh#L1087-L1101)：`rm -f jail.d/*.local` |
| R03 | 仍成立 | [`install.sh#L1276-L1296`](../../install.sh#L1276-L1296)：`.py` 被 `bash` 启动且 `|| true` |
| R04 | 仍成立 | [`install.sh#L2464-L2491`](../../install.sh#L2464-L2491)：默认追加 limits、关闭 SELinux |
| R05 | 仍成立 | 启动即 `check_online_version_connect`，失败 `exit 1`（`install.sh#L16085` 附近） |
| R06 | **部分过时** | `--stats` 的 legacy cleanup 已移到 root gate 之后；`-s/--show` 仍要求 root |
| R07 | 仍成立 | [`install.sh#L9958-L10012`](../../install.sh#L9958-L10012)：`sed -i` 改 TLS 后重启 |
| R08 | 仍成立 | [`install.sh#L8688-L8716`](../../install.sh#L8688-L8716)：证书状态用 mtime |
| R09 | 仍成立 | [`install.sh#L10815-L10845`](../../install.sh#L10815-L10845) 与 `#L15210-L15235`：下载远程脚本后执行，无固定哈希 |
| R10 | 仍成立 | `test_backup_restore` 有 SHA 校验，但无恶意压缩包/路径穿越负例 |
| R11 | 仍成立 | [`install.sh#L10948-L10951`](../../install.sh#L10948-L10951)：按子串 `sed -i "/auto_update.sh/d"` |
| R12 | 仍成立 | [`scripts/file_manager.sh#L160-L215`](../../scripts/file_manager.sh#L160-L215)：直接写 iptables 链 |
| R13 | 仍成立 | [`scripts/ssl_update.sh#L92-L141`](../../scripts/ssl_update.sh#L92-L141)：续期前先停 Nginx，未先判断证书是否变化 |
| R14 | 仍成立 | `-u` 只换 `install.sh`；`auto_update.sh` cron 仍走 Bash |
| R15 | 仍成立 | API 只有 `shell_*` 字段（见第 1 节） |
| R16 | 仍成立 | `docker/fake-systemctl`；不能假设宿主 DBus |
| R17 | 仍成立 | `install_config.json` 与 Xray config 两层，存在漂移 |
| R18 | 仍成立 | 旧 `tls=XTLS` 只被读/拒绝；fixture `xtls-only` |
| R19 | **已修复** | 上游 #176（`59a87c6`）修复统计首查等待 |
| R20 | 仍成立 | 失败运行中 `release-gate` 仍 success（单 job 绿不等于整体绿） |
| R21 | 仍成立 | Relay 与 Reality primary/secondary 共用入口，无独立所有权 |
| R22 | 仍成立 | 入口替换无 journal；失败依赖备份 |
| R23 | 仍成立 | 服务用户/证书组权限（`idleleo-nginx`、640）由脚本直接改 |
| R24 | 仍成立 | 主仓 / API 仓 / Nginx 仓 / Xray 仓多链发布 |

## 6. Phase 00 的 CI 约束

- 本轮**没有**修改任何 Bash 产品代码；R01–R18 的 Bash 修复留待用户决定（不在 Phase 00 授权范围）。
- 新增的两个 Go 工作流不改变现有 Bash 门禁语义。
- `check_release_gate.py` 在本阶段必须保持红灯；不把原型结果写成迁移完成。
- 不删除、不跳过任何既有测试来换绿灯。
