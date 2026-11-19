# 审计整改问题追踪（2026-11-19）

> 代码基线：`4527b721fda1dee39545f63ae35f27f9f5078e4f`（父提交 `b8b31f7e`，对比基线
> `origin/develop/go-native` = `9b965843`）。分支 `work/go-hardening-parity-20261119`。
> 本文只记录**当前 HEAD 可复核的事实**；未执行的项标 `NOT_RUN`/`BLOCKED`，不当作通过。
> 未读取任务书中的 ChatGPT 链接，不作任何“已读”声明。

## 1. 方法

1. 逐条把审计材料（`AUDIT_V4.md`、`AUDIT_REPORT.md`、`TRACEABILITY_MATRIX.md`、
   `RELEASE_MIGRATION_CONTRACT.md`）映射到当前源码路径与函数。
2. 对每个 P0/P1 先写最小复现或对照脚本，在 Docker 内用真实 Nginx/Xray/容器网络执行。
3. 只有“代码 + 真实执行 + 可复核证据”同时成立才标 `FIXED_VERIFIED` /
   `ALREADY_FIXED_VERIFIED`；仅代码存在而缺执行证据的保持 `OPEN`。
4. 测试结论词汇：`MATCH / GAP / GO_FAILED / BASH_FAILED / REFUSED / NOT_RUN`。

## 2. P0 问题

| ID | 优先级 | 原审计依据 | 当前 HEAD 复现 | 影响范围 | 修复策略 | 自动化用例 | 结果 | 证据路径 | commit |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| P0-A | P0 | `AUDIT_V4.md` P0-A；`RELEASE_MIGRATION_CONTRACT.md` 中转边界 | 否：4 个地址实测，`listen`/`proxy_timeout 720m`/`keepalive` 均在 | relay 公网暴露/绕行 | 保留显式 `listen`；非法地址 fail-closed 且不改 fragment | `artifacts/audit-remediation/p0a_relay_exposure.sh` + `nginx -t` | `ALREADY_FIXED_VERIFIED` | `artifacts/audit-remediation/p0a/summary.json` | `b8b31f7e` |
| P0-B | P0 | `AUDIT_V4.md` P0-B；`TRACEABILITY_MATRIX.md` 分享链路 | 是（修复前）：`xray share` 不读元数据，TLS 回环节点分享为 `security=none` | 分享链接泄露真实拓扑/协议 | 元数据回填 `TLS/host/port`；显式标志优先；未知/缺失保持 fail-closed | `internal/cli/share_metadata_test.go` 6 例 + 红测 | `FIXED_VERIFIED` | `internal/cli/share_metadata_test.go`；`TEST_EVIDENCE.md` §3 | `4527b721` |
| P0-C | P0 | `AUDIT_V4.md` P0-C；`TRACEABILITY_MATRIX.md` 迁移/恢复 | 否：锁、journal、原子写、入口漂移保护均在 | 迁移覆盖入口/配置/证书/cron | `audit` 只读；`prepare` 不碰运行时；`activate` 仅切入口/cron；`recover` 回滚 | `p0c_migration_restore.sh`；`legacybridge/backup/repair` 测试 | `ALREADY_FIXED_VERIFIED` | `artifacts/audit-remediation/p0c/summary.json`；`logs/p1e-fault-injection.log` | `8ac1385f`、`43ceb680` |

### P0-B 变更细节

- 仅当 `--public-security/--host/--public-port` **未显式给出**时，从
  `metadata.json` 的 `TLS`、`Install.ServerNames[0]`、`Install.Port` 回填。
- 映射：`TLS→tls`、`Reality→reality`、`None→none`；未知值不回填，保持 fail-closed。
- 显式标志优先；无元数据时行为与旧版完全一致（回环 `security=none` + 未声明公网
  security 仍拒绝）。
- 同一份元数据继续提供 `ShareLinkOnly` 的 `fp/spx`，不新增敏感字段。

## 3. P1 问题

| ID | 优先级 | 原审计依据 | 当前 HEAD 复现 | 影响范围 | 修复策略 | 自动化用例 | 结果 | 证据路径 | commit |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| P1-A | P1 | `AUDIT_V4.md` P1-A；`TRACEABILITY_MATRIX.md` 传输/元数据 | 部分：旧矩阵有 20 个前置端口 GAP 与 OPS 覆盖缺口 | 传输、元数据、管理路径 | P2 双端矩阵 + 98 项矩阵 + OPS Go sweep + 5 个 OPS 双端复跑；修正固化旧缺陷的端口断言 | `run_p2_matrix.sh`、`run_matrix_container.sh`、`run_ops_sweep.sh` | `FIXED_VERIFIED` | `tests/e2e-diff/evidence/audit-final-20261119/p2/`；`tests/go-parity/evidence/matrix-20261120-final/summary.json`；`tests/e2e-diff/evidence/audit-ops-20261120/`；`tests/e2e-diff/evidence/audit-ops-dual-20261120/` | `4527b721`、`288c9e91`、`1cd8b98c` |
| P1-B | P1 | `AUDIT_V4.md` P1-B；`RELEASE_MIGRATION_CONTRACT.md` 原子性 | 否：journal、回滚、服务状态恢复均实测 | 多文件半更新/服务状态错乱 | 首字节前 fsync journal；失败 `restoreTransaction`；Nginx 残留显式报告 | `go test ./internal/deploy`（5 个回滚用例） | `ALREADY_FIXED_VERIFIED` | `artifacts/audit-remediation/logs/p1b-deploy-rollback.log` | `c3313638` |
| P1-C | P1 | `AUDIT_V4.md` P1-C | 否：离线全量通过 | DNS/DoH 依赖导致结果漂移 | 容器内 origin；`--network none` 全量回归 | `go test -count=1 ./...`（离线） | `ALREADY_FIXED_VERIFIED` | `logs/go-test-offline.log`；P2 L4 | `96bc4edd` |
| P1-D | P1 | `AUDIT_V4.md` P1-D | 否：race/所有权测试全绿 | 长期运行、日志/服务账户所有权 | `-race`；fail2ban 只改自有文件；日志只截断普通文件 | `logs/p1d-race.log`、`logs/p1d-ownership.log` | `ALREADY_FIXED_VERIFIED` | `logs/p1d-race.log`、`logs/p1d-ownership.log` | `2d9a27af`、`2a930874` |

## 4. 仍未闭环（不得当作已修复）

| 项 | 状态 | 原因 / 下一步 |
| --- | --- | --- |
| 独立 VPS（systemd 真机、重启、cron 真实交接） | `BLOCKED` | 任务书禁止操作生产 VPS；本仓库无独立测试机 |
| 公网 CA / DNS-01 / EAB 的纯 Bash ACME | `BLOCKED` | 需要公网域名与 CA；只能在受控域名下执行 |
| 外部 IPv6 数据面 | `NOT_RUN` | Docker 默认 bridge 无 IPv6；已证明 `::` 监听与 `::1` 数据面，外网 IPv6 需双栈宿主 |
| 多版本 Xray/Bash 配置矩阵 | `NOT_RUN` | 需要固定历史发行物；当前只使用仓库 fixture 与固定 Xray `26.10.31` |
| OPS 运营场景双端复跑 | `NOT_RUN` | OPS-09/19/21/31/32 已在 `1cd8b98c` 双端复跑并 PASS；其余 18 个 ID 在当前 HEAD 仍只有 Go 单侧 sweep，不宣称双端 MATCH |
| OPS 尚未迁移到 Go 菜单/CLI 的行 | `GAP` | 真正缺等价命令的是 OPS-08（在线修改 SNI Guard）与 OPS-27（清空证书）；OPS-30 语言切换为 `allowed-diff`；OPS-05/06/07/10/17b/24 已有 `xray edit`、`xray tls`、`update nginx`、`schedule run` 等价路径 |
| 98 项矩阵的前置端口断言 | `FIXED_VERIFIED` | 旧断言把 Xray 回环后端端口当公网端口，等于固化旧缺陷；已改为校验 Nginx `listen <port>`，不跳用例 |
| 正式发布与 `main` 合并 | `INTENTIONAL_DELTA_APPROVED` | 任务书明确禁止；仅提交工作分支 |
