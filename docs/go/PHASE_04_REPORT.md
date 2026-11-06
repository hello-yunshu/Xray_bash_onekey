# Phase 04 报告 — 容器级验收、发布候选与回退

> 分支：`develop/go-native`　基线：Phase 03 收尾 `9e35b52`
> 实现提交：`5ad2732`（工作包 A/B）、`a1e0085`（只读路径、构建与 E2E 扩展）
> 证据等级：`CONTAINER_VERIFIED`　**不是** `REAL_VPS_VERIFIED`
> 日期：2026-11-07

## 0. 结论

Phase 04 的计划工作包已**按顺序执行到能执行的部分**：

- 完成了 Go 自更新通道、证书外部续约契约、服务类 CLI、只读 Rill 状态、统计查询、
  双架构候选产物与 42/42 容器 E2E；
- **未能**完成真实 VPS/多发行版矩阵、28 个发布执行器、候选 CI 绿灯；
- 发布门禁实测仍为**红灯**（exit 2）。

因此：**Phase 04 容器级工作完成，但发布资格未获得；不能合并 `main`、不能打 tag、
不能发 Release，也不能宣称可以进入下一阶段。**

## 1. 工作包逐条结果

| # | 工作包 | 结果 | 真实证据 | 未完成部分 |
|---|---|---|---|---|
| 1 | 建立完整发布证据清单 | **部分完成** | `go test ./...` exit 0；`go vet ./...` exit 0；42/42 E2E；manifest 真实下载校验 | 备份、Docker 产品交付、Fail2ban、防火墙、多发行版无证据 |
| 2 | 小而有效的实机矩阵 | **部分完成** | Ubuntu 24.04 固定 digest 容器：arm64 全量 E2E；amd64 只跑 Stats 复现 47/47 | Debian 12/13、CentOS Stream 10、Rocky/Alma、SELinux、真实 arm64/amd64 硬件、真实 VPS 全部未跑 |
| 3 | 当前 CI 红灯硬门槛 | **部分完成** | 失败 run `42048259341` / head `4752f77` 定位；ancestry 实测 3 个修复提交均不在失败 run；当前代码 amd64 复现 `PASS=47 FAIL=0` | 候选分支没有绿色 Actions run；工作流路径与模块布局不一致 |
| 4A | 代理运行安全故障验证 | **部分完成** | 错误 SHA、截断下载、非 ELF、降级、磁盘满均保留旧二进制；证书未变不重启、变化重启一次、world-readable 私钥拒绝 | 真实客户端握手、TLS/Reality 多协议、IPv6/自定义 routing 的完整矩阵 |
| 4B | 管理与恢复 | **部分完成** | 只读命令 `/etc/idleleo` 零写入；API down exit 8；非 root exit 5；降级拒绝 exit 4；`RECOVERY_REQUIRED` exit 10 | 恶意备份归档、Fail2ban 第三方 jail、防火墙同端口用户规则、syscall 级零写入证明 |
| 4C | 跨版本迁移与恢复 | **部分完成** | Phase 03 201/201：拒绝路径、6 个中断点、`COMMITTED` 后不逆向；Phase 04 在已迁移安装上 42/42 | 真实 Bash 3.3.4/更早版本、真实断电重启、真实 SIGKILL 随机点 |
| 5 | 发布物与工作流 | **部分完成** | 双架构产物真实构建/执行；`SHA256SUMS` + `manifest.json`；真实 `update check` | 未发布；`go-release-qualification.yml` 未修；无独立 VM/systemd 强制 job |
| 6 | 交付清单 | **完成** | 本提交的 `docs/release/*`、`assets/go/manifest.json`、`SHA256SUMS` | 无 |
| 7 | 最终发布门槛 | **未通过** | `check_release_gate.py` exit 2，28 pending + 28 missing tests | 全部 10 项门槛中多项不满足，见第 6 节 |

## 2. 实际改动

相对 `9e35b52`（18 个文件，+2212 / -103）：

| 文件 | 作用 |
|---|---|
| [`internal/release/release.go`](../../internal/release/release.go) | Go 发布通道：manifest 解析、下载、SHA/Size/ELF 校验、原子替换、健康检查、回滚、降级拒绝、共享锁 |
| [`internal/host/gate.go`](../../internal/host/gate.go) | 真实 root / sandbox 统一写入门禁 |
| [`internal/cli/update.go`](../../internal/cli/update.go) | `update status/check/apply/configure` 与稳定退出码 |
| [`internal/cli/stats.go`](../../internal/cli/stats.go) | `stats` 真实 `xray api statsquery` 查询；`--json`、exit 5/8 |
| [`internal/service/service.go`](../../internal/service/service.go) + [`internal/cli/service.go`](../../internal/cli/service.go) | 仅自有 unit 的 status/start/stop/restart/reload/logs |
| [`internal/legacybridge/rill.go`](../../internal/legacybridge/rill.go) + [`internal/cli/rill.go`](../../internal/cli/rill.go) | 只读 Rill 状态投影 |
| [`internal/schedule/schedule.go`](../../internal/schedule/schedule.go) | auto-update 接入 release 通道；证书指纹契约；`releaseChannel` 状态 |
| [`internal/cli/cli.go`](../../internal/cli/cli.go)、[`internal/i18n/i18n.go`](../../internal/i18n/i18n.go) | 新命令分派与帮助 |
| [`packaging/build-go-release.sh`](../../packaging/build-go-release.sh) | 双架构构建 + SHA256SUMS + manifest |
| [`tests/go-parity/phase04/`](../../tests/go-parity/phase04/) | 固定 digest 容器、origin、42 项 E2E |

## 3. 真实运行证据

### 3.1 容器 E2E

```text
image-id: sha256:8737d13b89f8bf8d8b5e0136ef9f9c020876a4ac9edf146511659535894b6924
systemd: running
phase04-start 2026-11-06T17:34:47Z arch=arm64
...
phase04-end 2026-11-06T17:34:52Z pass=42 fail=0
phase04-exit=0
```

关键断言原文：

```text
PASS update apply action=applied health=idleleo 0.3.0-phase04 (go) version=idleleo 0.3.0-phase04 (go)
PASS downgrade refused exit=4
PASS disk full rejected rc=1
PASS scheduled auto-update applied 0.4.0 at=2026-11-06T17:34:48Z
PASS changed certificate restarted xray once and reloaded nginx
PASS world-readable private key blocked the reload
PASS service restart restarted xray (starts 3->4)
PASS rill status active mode=observe-only
PASS stats --json returned a real inbound counter
PASS read-only commands wrote nothing under /etc/idleleo
```

### 3.2 双架构产物

```text
== amd64 == idleleo 0.2.0-phase04 (go)   exit=0
== arm64 == idleleo 0.2.0-phase04 (go)   exit=0
9f7a5ab3…  idleleo-linux-amd64
0177eed4…  idleleo-linux-arm64
```

### 3.3 manifest 真实下载

```text
state=available platform=linux-arm64 current= latest=0.2.0-phase04 verified=true
asset=idleleo-linux-arm64 size=6488248 sha256=0177eed4…
check-exit=0
```

### 3.4 发布门禁

```text
gate-exit=2
RELEASE BLOCKED: pending 28; missing executable feature tests 28
```

## 4. F01–F28 变化

- 状态标签变化：**0**。
- 证据加强、标签不变：F11、F12、F14、F15、F22、F27、F28。
- 其余 21 项无变化。
- `feature_contracts.json` 保持 28 × `PENDING_GO_IMPLEMENTATION`。

逐项见 [FEATURE_PARITY_RESULTS.md](../release/FEATURE_PARITY_RESULTS.md)。

## 5. Phase 03 三个前置的收口

| 前置 | 结果 |
|---|---|
| 自动更新通道 | **已实现（容器验证）**：显式 `update configure` 后定时升级 0.3.0→0.4.0；未配置时 `degraded`，用户失去自动更新 |
| ACME / 外部续约契约 | **外部契约已实现，ACME 未纳入**：指纹基线、变化才重启、未变不重启、短证书降级；用户仍需外部工具续期 |
| Rill 管理命令 / 服务类 CLI | **部分完成**：`rill status` 只读 + `service` 自有 unit 管理；Rill 安装/授权/卸载未迁移 |

## 6. 最终发布门槛核对

| 门槛 | 结果 |
|---|---|
| Phase 00 契约未被偷偷放宽 | 是（未改契约） |
| Phase 01/02 事务/锁与 F01–F28 完成或批准延期 | 否（28 pending） |
| 无 Bash 单体核心/DB/daemon/Web | 是 |
| Reality/TLS/ONLY/主次/relay 均有证据 | 否（主次负载均衡未实现） |
| R01–R04 故障注入无越界 | 部分（已有注入项通过，未覆盖项见限制文档） |
| Ubuntu Stats CI 根因定位解决或正式阻断 | 根因已定位、本地复现通过；**无候选 CI 绿灯**，按阻断处理 |
| 迁移路径容器级 E2E | 是（Phase 03 + Phase 04） |
| Bash/Go 更新字段隔离 | 是（代码与文档证据） |
| AMD64/ARM64 覆盖与 Release Note 一致 | 是（明确写为容器级） |
| Go Release 可追溯、门禁通过才切换 | 否（门禁红灯） |

**结论：最终发布门槛未通过。**

## 7. 未验证项（摘要）

真实 VPS；真实 ACME；真实断电/重启；更早 Bash 版本；Debian/RPM/SELinux；
真实 amd64 硬件；恶意备份；Fail2ban/防火墙第三方共存；Xray/Nginx 更新（F13）；
backup/restore/purge CLI；Rill 安装/授权/卸载；stats watch/reset；Docker 产品交付；
六语言完整文案；Reality 主次负载均衡。详见
[KNOWN_LIMITATIONS.md](../release/KNOWN_LIMITATIONS.md)。

## 8. 能否进入 Phase 05

- 仓库的 `docs/go-migration/phases/` **只有 00–04，没有 Phase 05 计划**。
- 即使按“是否可继续下一阶段”理解，答案也是**否**：Phase 04 的发布门槛未通过，
  `check_release_gate.py` 红灯，候选分支无绿色 CI run；继续推进只会扩大未授权范围。
- 建议的下一动作：补齐 28 个真实 feature test 与受保护 CI、修复
  `go-release-qualification.yml` 路径、取得绿色 run，再重跑本阶段门槛。

## 9. Git 事实

- 分支：`develop/go-native`
- 已推送实现提交：`5ad2732`（工作包 A/B）、`a1e0085`（只读/构建/E2E）
- 本文档提交 SHA 见 `git log`（提交后补记）
- 未合并 `main`、未打 tag、未发 Release
- `.workbuddy/`、`docs/plans/` 未跟踪
