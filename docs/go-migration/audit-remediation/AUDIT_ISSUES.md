# 审计整改问题追踪（2026-11-19）

> 代码基线：`4527b721fda1dee39545f63ae35f27f9f5078e4f`（父提交 `b8b31f7e`，对比基线
> `origin/develop/go-native` = `9b965843`）。分支 `work/go-hardening-parity-20261119`。
> 本文只记录**当前 HEAD 可复核的事实**；未执行的项标 `NOT_RUN`/`BLOCKED`，不当作通过。
> 未读取任务书中的 ChatGPT 链接，不作任何“已读”声明。
>
> 2026-11-20 复审：任务书基线 `a1056a14`，复审起点 `d13fca44`（已在基线上追加
> OPS-08/27 与证据），修复提交 `9f66b22a`（分享归属/SNI/隐私）与 `f217a2fa`
> （E2E 显式 Host）。§5 记录本轮新增问题与结论。

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
| P0-B | P0 | `AUDIT_V4.md` P0-B；`TRACEABILITY_MATRIX.md` 分享链路 | 是（修复前）：`xray share` 不读元数据，TLS 回环节点分享为 `security=none`；2026-11-20 又发现跨 root 元数据污染与 SNI 当 Host | 分享链接泄露真实拓扑/协议或指向错误入口 | 元数据仅在路径+SHA 归属成立时回填 TLS/port；Reality 强制显式 `--host`；显式标志优先；未知/缺失保持 fail-closed | `internal/cli/share_metadata_test.go` 10 例 + F28/F08/F18 回归 | `FIXED_VERIFIED` | `internal/cli/share_metadata_test.go`；`TEST_EVIDENCE.md` §3、§11 | `4527b721`、`9f66b22a` |
| P0-C | P0 | `AUDIT_V4.md` P0-C；`TRACEABILITY_MATRIX.md` 迁移/恢复 | 否：锁、journal、原子写、入口漂移保护均在 | 迁移覆盖入口/配置/证书/cron | `audit` 只读；`prepare` 不碰运行时；`activate` 仅切入口/cron；`recover` 回滚 | `p0c_migration_restore.sh`；`legacybridge/backup/repair` 测试 | `ALREADY_FIXED_VERIFIED` | `artifacts/audit-remediation/p0c/summary.json`；`logs/p1e-fault-injection.log` | `8ac1385f`、`43ceb680` |

### P0-B 变更细节

> 2026-11-20 复审修正：初版实现把 `Install.ServerNames[0]` 当作公网连接地址，
> 且未校验元数据与所选配置的归属关系。Reality 的 `serverNames` 是 SNI/伪装身份，
> 不是客户端拨号地址；该行为已在 `9f66b22a` 修正，见 §5。

- 仅当所选 `--path` 与 `meta.runtimeConfigPath` **规范化后同路径**，且
  `meta.runtimeSha256`（非空时）与文件字节一致，才从 `metadata.json` 回填
  `--public-security` 与 `--public-port`；跨 root、跨配置、过期哈希一律不采用。
- 同一路径但哈希不一致说明配置被直接编辑过：元数据不再参与渲染，`xray share`
  仍按运行时配置生成链接，并在 `warnings` 中明确报告 `stale`。若唯一能消歧的信息
  恰好来自该陈旧元数据（loopback + `security=none`），则返回可操作的
  `--public-security` 错误，绝不猜一个可能错误的公网链接。
- 映射：`TLS→tls`、`Reality→reality`、`None→none`；未知值不回填，保持 fail-closed。
- 显式标志优先；Reality 链接必须显式 `--host`，不再把 SNI 当连接地址。
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
| OPS-08 / OPS-27 Go 命令 | `FIXED_VERIFIED` | 已在 `241cc99f` 新增 `xray guard show/set`（isolate/reject/decoy，含 deny 端口、include、nginx -t 回滚、元数据）与 `xray cert clear`（符号链接拒删、`--dry-run`、真实 root 才清 acme.sh）。验证为 Go 单测 + 沙箱 CLI smoke + `nginx:1.27-alpine` 真实 `nginx -t`（isolate/reject/decoy 三种策略均通过）；与 Bash 的双端交互仍 `NOT_RUN` |
| OPS-30 语言切换 | `INTENTIONAL_DELTA_APPROVED` | `allowed-diff`，不要求与 Bash 逐字节一致 |
| OPS-05/06/07/10/17b/24 | 已有等价路径 | `xray edit`、`xray tls`、`update nginx`、`schedule run` 已覆盖，无同名 OPS 行 |
| 98 项矩阵的前置端口断言 | `FIXED_VERIFIED` | 旧断言把 Xray 回环后端端口当公网端口，等于固化旧缺陷；已改为校验 Nginx `listen <port>`，不跳用例 |
| 正式发布与 `main` 合并 | `INTENTIONAL_DELTA_APPROVED` | 任务书明确禁止；仅提交工作分支 |

## 5. 2026-11-20 复审新增问题

| ID | 级别 | 复现 | 修复 | commit | 状态 |
| --- | --- | --- | --- | --- | --- |
| FUP-01 | P0 | F28 在 CI 中 35 passed / 2 failed：`--public-security none conflicts with runtime stream security=reality`。`xray share` 读取默认 `/etc/idleleo` 元数据并套到另一个 `--root` 的 Reality 配置 | 元数据仅在 `--path` 与 `runtimeConfigPath` 规范化同路径、且 `runtimeSha256` 匹配时生效；跨 root/跨配置忽略；同路径哈希不符时忽略默认值并输出 `stale` 警告，运行时配置仍可分享 | `9f66b22a` + 复审修订 | `FIXED_VERIFIED`（本地 pre-fix 红测 35/2 → 57/0） |
| FUP-02 | P0 | Reality 分享把 `Install.ServerNames[0]`（SNI/伪装域名）当客户端拨号 Host | 删除该回填；Reality 无显式 `--host` 直接拒绝；TLS/Nginx 仍用运行时 `tlsSettings.serverName` | `9f66b22a` | `FIXED_VERIFIED` |
| FUP-03 | P0 | `tests/go-parity/evidence/matrix-20261120-final/environment.txt` 第 7 行含 macOS 本机绝对路径，Stage Gate / Privacy Guard 红 | 生成器只写 SHA256 值与仓库相对路径；历史 evidence 同步脱敏；新增 `test_environment_contract.py` 阻止复发 | `9f66b22a` | `FIXED_VERIFIED` |
| FUP-04 | P1 | F28 `commands.log`、PASS/FAIL detail 与 `xray x25519 -i` argv 含临时私钥 | `f.run(redact=True)` 脱敏命令与输出；只保留布尔断言；fixture root 移出 evidence 目录 | `9f66b22a` | `FIXED_VERIFIED` |
| FUP-05 | P1 | F28 的 `share` 未带 `--root`，测试自身不自洽 | 加 `--root`；其余 Reality 探针显式 `--host 127.0.0.1` | `9f66b22a`、`f217a2fa` | `FIXED_VERIFIED` |
| FUP-06 | P2 | 矩阵 `repo_dirty` 把自身输出目录算进去 | 在创建 evidence 目录前快照 `git status` | `b212f1cf` | `FIXED_VERIFIED` |
| FUP-07 | P1 | 直接编辑 `config.json` 后 `xray share` 因哈希不符完全不可用（OPS-21 `shareUri=false`） | 陈旧哈希降级为警告，仍按运行时配置渲染；loopback 歧义保持可操作错误 | `102f52e1` | `FIXED_VERIFIED` |
| FUP-08 | P1 | `xray config edit` 的 `OldShareURI`/`NewShareURI`/`ShortIDLinks` 把 Reality SNI 当拨号地址，报告与备份可能给出不可连接的链接 | `EditRequest.Host` 成为唯一拨号地址来源；URL 形式拒绝；Reality 缺 `--host` 时输出降级警告；E7/E8 与驱动两侧显式 `--host 127.0.0.1` | `1cd248e6` | `FIXED_VERIFIED` |
| FUP-09 | P1 | OPS-32 要求 A 链一直延续到恢复窗口末尾；nginx 以衰减权重重新放行后端，A 本就稀疏，同一行为在 bash 过、go 判 `BLOCKER` | 判定改为窗口尾部 `2*fail_timeout` 内 A ≥ `stable_min` 且相邻间隔 ≤ `fail_timeout`；规则文案同步 | `1cd248e6` | `FIXED_VERIFIED` |

FUP-08/09 的验证见 [REVIEW_20261120_FOLLOWUP.md](REVIEW_20261120_FOLLOWUP.md)
§3、§5；FUP-08 只影响链接渲染，不写配置字段，`--host` 单独使用时提示
“nothing to edit”（它不产生运行时变更）。

## 6. 第三轮 Docker 实机验收（2026-11-20，候选 `df3f3838`）

完整报告：[DOCKER_ACCEPTANCE_20261120.md](DOCKER_ACCEPTANCE_20261120.md)。
覆盖账本：`artifacts/audit-remediation/docker-final-round3-20261120-df3f3838/case-matrix.csv`。

| ID | 第三轮结论 | 证据 | 说明 |
| --- | --- | --- | --- |
| A1 证书清理所有权/在用引用/第三方/事务 | `FIXED_VERIFIED` | `a1-red-baseline.log`、`a1-acme-realroot-final.log`、`certclear_test.go` | 真实 root；dry-run 零写；staging+journal；第三方与 ACME 账户保留；Bash 旧风险为 `INTENTIONAL_SAFETY_DELTA` |
| A2 分享 Host/SNI 与元数据归属 | `PASS_IMPACT_SCOPED` | `internal/cli/share_metadata_test.go`；F28 57/0、F08 129/0、F18 178/0 | 候选未重跑 F28；`df3f3838` 只改 XHTTP 路径，未触及 share |
| A3 Guard show 默认 enabled/isolate；set 锁/journal/回滚 | `FIXED_VERIFIED` | `a3-guard-redgreen.log`、`smoke-guard-cert-final.log`、`guard_test.go` | pre-fix `sniGuard=true/isolate` → candidate `not-applicable`；真实 nginx 三策略 PASS；Bash 交互 `NOT_RUN` |
| A4 XHTTP `/xhttp` vs `/xhttp/` | `NO_DEFECT_SEMANTIC_DIFF` | `a4-prefix-probe.log`、`a4-xhttp-path.log` | 父提交负例测试通过；真实 Xray 四交叉 200/301；`normalizeXHTTPPath` 为防御性统一 |
| A5 已修复项/缓存/OPS-32/Test Install | `PARTIAL` | `OPS-32`、`gate-final.log` | OPS-32 ws+reality PASS；Test Install 静默退出仍 `CI_PENDING` |

### 6.1 §4 未闭环项的更新

| 项 | 第三轮状态 |
| --- | --- |
| 独立 VPS / 公网 CA / 外部 IPv6 / 多版本 | 仍 `BLOCKED` / `VPS_DEFERRED` / `NOT_RUN` |
| OPS 双端 | 5 个双端 PASS；17 个仅 Go sweep；2 个仅 Go 命令；10 个 `NOT_RUN`。**不满足任务书 B4** |
| 9 个 subscripts | `NOT_RUN` |
| 30 分钟 soak | `NOT_RUN` |
| Test Install 静默退出 | `CI_PENDING` |

### 6.2 结论

- Docker 开发候选：`NO_GO_FOR_DOCKER_QUALIFIED_CANDIDATE`（B4/C3/C4 未完成）。
- 正式发布：`NO_GO_NOT_AUTHORIZED`；PR 保持 draft，不合并、不发版。
