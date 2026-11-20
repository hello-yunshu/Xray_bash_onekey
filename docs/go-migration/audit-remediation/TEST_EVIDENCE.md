# 测试证据（2026-11-19）

> 所有结果来自当前分支 `work/go-hardening-parity-20261119`。代码提交
> `4527b721fda1dee39545f63ae35f27f9f5078e4f`；P2 矩阵运行的代码 SHA 见各
> `run.json` 的 `commit` 字段；98 项矩阵与 OPS sweep 在 `86d810e5` 上运行。
> `NOT_RUN` 不计通过。

## 1. 环境

| 项 | 值 |
| --- | --- |
| 日期 | 2026-11-19（Asia/Shanghai） |
| Go | `golang:1.27.4`，digest `sha256:5e8afd493a7124a8586e134d9b532731161d4b9becf9dee5a5956b107426f93d` |
| E2E 镜像 | `idleleo-e2e:24.04`，digest `sha256:2e722b98cfb43dfcc6fd285bc3d8771ad9a44a40a3c4663027500686db343cde` |
| Origin | `nginx:1.27-alpine` |
| Bash 基线 | `install.sh` v3.3.6，pin `0fa7052e` |
| Go 基线 | `origin/develop/go-native` = `9b965843` |
| 二进制 SHA256 | `df100b2c97050f30796d96bc3c1c9318abf45021981801b3873826680aefd088`（`go build -trimpath -buildvcs=false ./cmd/idleleo`） |
| 构建方式 | vendored、`GOPROXY=off`、`GOTOOLCHAIN=local`、`CGO_ENABLED=0` |
| 主机 | macOS；Bash 3.2；Docker Desktop |

### 1.1 测试入口、工作流与既有材料

| 类别 | 位置 |
| --- | --- |
| 单元/全量 | `go test -count=1 ./...`（离线 `--network none`） |
| P2 双端矩阵 | `tests/e2e-diff/run_p2_matrix.sh`（`matrix.json`，M1–M10） |
| 历史 98 项矩阵 | `tests/go-parity/matrix/run_matrix_container.sh` + `run_matrix.py` |
| OPS 运营 sweep | `tests/e2e-diff/run_ops_sweep.sh` |
| P0 证据脚本 | `artifacts/audit-remediation/p0a_relay_exposure.sh`、`p0c_migration_restore.sh` |
| CI 工作流 | `.github/workflows/go-parity-stage.yml`、`go-realroot-container.yml`、`go-preview-qualification.yml`、`go-release-qualification.yml`、`test-install.yml` |
| 既有审计报告 | `docs/go-migration/reference/{AUDIT_V4,AUDIT_REPORT,TRACEABILITY_MATRIX,RELEASE_MIGRATION_CONTRACT}.md`、`docs/go/BASH_GO_REAL_RUNTIME_PARITY_REPORT.md` |
| 证据目录 | `tests/e2e-diff/evidence/`、`tests/go-parity/evidence/`、`artifacts/audit-remediation/` |

## 2. P0-A：中转监听与公网暴露

命令：

```bash
bash artifacts/audit-remediation/p0a_relay_exposure.sh
```

结果文件：`artifacts/audit-remediation/p0a/summary.json`（`allPass: true`），
二进制 SHA256 前缀 `8221745cb4c6`。

| 地址 | install | `nginx -t` | 容器内本机 | 同桥对端 | 结论 |
| --- | --- | --- | --- | --- | --- |
| `127.0.0.1:18443` | 0 | 0 | 0 | 1（拒绝） | PASS |
| `0.0.0.0:18444` | 0 | 0 | 0 | 0 | PASS |
| `[::1]:18445` | 0 | 0 | 0 | 1（拒绝） | PASS |
| `[::]:18446` | 0 | 0 | 0 | 1（IPv4 拒绝，`ipv6only`） | PASS；外部 IPv6 `NOT_RUN` |
| `node.example` / `127.0.0.1]` / `0.0.0.0:443` | 1 | — | — | — | PASS（拒绝且 fragment 哈希不变） |

说明：Docker 默认 bridge 无 IPv6，`::` 只证明监听器与本地数据面；外部 IPv6 数据面
标 `NOT_RUN`。managed Nginx 真实执行 `nginx -t`，日志见 `p0a/nginx-*.log`。

## 3. P0-B：TLS 分享拓扑

命令：

```bash
docker run --rm -v "$PWD:/src:ro" -w /src \
  -e CGO_ENABLED=0 -e GOFLAGS=-mod=vendor -e GOPROXY=off -e GOTOOLCHAIN=local -e GOCACHE=/tmp/gocache \
  golang:1.27.4 bash -c 'export PATH=$PATH:/usr/local/go/bin; go test -count=1 -run TestXrayShare -v ./internal/cli'
```

结果：6/6 PASS。

| 用例 | 断言 | 结果 |
| --- | --- | --- |
| `TestXrayShareUsesMetadataForPublicTLS` | 回环 `security=none` + `TLS` 元数据 → `security=tls`、`sni`、`:443` | PASS |
| `TestXrayShareUsesMetadataForReality` | `Reality` 元数据 → `security=reality`、含 `pbk` | PASS |
| `TestXrayShareUsesMetadataToResolveLoopbackNone` | `None` 元数据消解歧义 | PASS |
| `TestXrayShareExplicitFlagWinsOverMetadata` | 显式 `none`/host/port 覆盖元数据 | PASS |
| `TestXrayShareWithoutMetadataStillRefusesAmbiguousLoopback` | 无元数据仍拒绝，错误含 `public security is ambiguous` | PASS |
| `TestXrayShareMetadataKeepsSelectedUser` | `--user` 与元数据并存仍选对 UUID/email | PASS |

红测：注释 `applyShareMetadataDefaults` 调用后重跑，TLS 用例 FAIL（输出
`security=none`、`sni=127.0.0.1`），证明用例确实覆盖缺陷；恢复调用后全绿。

## 4. P0-C：迁移/恢复不破坏资源

命令：

```bash
bash artifacts/audit-remediation/p0c_migration_restore.sh
```

结果：`p0c/summary.json`（`allPass: true`）。

| 检查 | 样本 | 结果 |
| --- | --- | --- |
| `bridge audit` 只读 | reality-direct / reality-nginx / tls-multi / custom-dns-routing / relay / xtls-only | 6/6 全树 SHA256 前后一致；xtls 正确判 `blocked` |
| `prepare` 不碰运行时 | tls-multi / reality-direct | 5 个运行时资源哈希不变；状态 `PREPARED` |
| `recover` 丢弃 PREPARED | tls-multi / reality-direct | 状态 `ROLLED_BACK`；运行时哈希不变 |
| 安全回归 | `./internal/legacybridge ./internal/backup ./internal/repair` | 0 FAIL；日志 `p0c/go-safety-tests.log` |
| 接管/改后校验/回滚 | `TestActivateSwitchesEntryAndCronOnly`、`TestValidateRejectsDrift`、`TestRecoverActivatingRestoresEntryAndCron`、`TestRecoverAfterMetadataCrashLeavesNoHalfMigration` | PASS（`logs/p1e-fault-injection.log`） |

故障注入覆盖（既有权威测试，本轮重跑）：入口漂移拒绝、第三方入口保持、
6 个持久点 SIGKILL 收敛、ENOSPC/EROFS/EACCES、坏 journal、并发锁。

## 5. P1-B：事务性部署

命令与日志：`artifacts/audit-remediation/logs/p1b-deploy-rollback.log`。

结果：5 PASS / 0 FAIL，覆盖：
`TestReinstallRollbackRestoresFilesAndService`、`TestFreshInstallRollbackRemovesNewFiles`、
`TestFinalizeFailureMentionsManagedNginx`、`TestManagedNginxFailureReportsResidualInstall`、
`TestRollbackFailureIsReportedNotHidden`。失败发生在配置/服务阶段后，均恢复到旧文件与
旧 `enable/active`；Nginx 残留被显式报告，不假装原子。

## 6. P1-C：离线可复现

命令：

```bash
docker run --rm --network none -v "$PWD:/src:ro" -w /src \
  -e CGO_ENABLED=0 -e GOFLAGS=-mod=vendor -e GOPROXY=off -e GOTOOLCHAIN=local -e GOCACHE=/tmp/gocache \
  golang:1.27.4 bash -c 'export PATH=$PATH:/usr/local/go/bin; go test -count=1 ./...'
```

结果：退出码 0，全部包 `ok`；日志 `logs/go-test-offline.log`。仓库内无
`1.1.1.1 / 8.8.8.8 / DoH` 硬编码；e2e 数据面使用容器内 origin。

## 7. P1-D：长期运行与所有权

- `go test -race`：`internal/backup`、`repair`、`legacybridge`、`schedule`、`store`、
  `change` 全绿（`logs/p1d-race.log`）。
- 所有权/日志：`logs/p1d-ownership.log` 25 PASS，包含
  `TestFail2banInstallKeepsForeignFiles`、`TestFail2banJailToggleEditsOnlyManagedFile`、
  `TestCleanLogsTruncatesOnlyRegularLogFiles`、`TestCleanLogsRefusesRealRootWithoutAck`。

### 7.1 故障注入覆盖（任务书 §4 第 5 层）

命令：`go test -count=1 -v` 定向运行 12 个包，退出码 0；**31 PASS / 0 FAIL /
0 SKIP**（含迁移接管/回滚 9 项），日志
`artifacts/audit-remediation/logs/p1e-fault-injection.log`。

| 条件 | 测试 | 结果 |
| --- | --- | --- |
| 无 root / 写保护 | `TestRequireSystemWriteSandboxNeedsMarker`、`TestCleanLogsRefusesRealRootWithoutAck` | PASS |
| 只读目录 | `TestApplyReadOnlyFileLeavesKernelAlone` | PASS |
| 磁盘耗尽 ENOSPC | `TestRestoreRollsBackOnFilesystemErrors` | PASS |
| 只读文件系统 EROFS | 同上（子用例） | PASS |
| 权限拒绝 EACCES | 同上（子用例） | PASS |
| 断网 | 全量 `go test ./...` 在 `--network none` 下通过 | PASS |
| 证书异常/过期 | `TestInspectTLSPairRejectsExpired`、`TestRunFindsExpiredCertificateAndLooseModes` | PASS |
| 配置/日志损坏 | `TestRecoverRefusesCorruptJournalWithoutTouchingFiles`、`TestAuditCorruptMetadataBlocked` | PASS |
| 端口占用 | `TestAuditPortConflictBlocked`、`TestPortAvailableSeesOccupiedLoopback`、`TestGenerateRejectsReservedPublicPort` | PASS |
| 重复执行 | P2 矩阵 Round 2 幂等（M1–M10） | MATCH |
| 并发 | `TestWriteAtomicConcurrentWritersKeepOneCompleteVersion`、`TestRestoreRefusesWhileAnotherProcessHoldsLock`、`TestRepairRefusesWhileAnotherUpdateHoldsTheLock` | PASS |
| 进程中断 SIGKILL | `TestRestoreHardKillAtEveryDurablePointConverges`（6 个持久点） | PASS |
| 陈旧任务/锁 | `TestStalePidFileIsReported`、`TestRepairStaleLockNeedsExplicitFlag` | PASS |
| 回滚失败 | `TestRollbackFailureIsReportedNotHidden`、`TestApplyRollbackFailureKeepsJournal` | PASS |
| 非法输入 | `TestSetInboundPortRejectsInvalid`；P0-A 3 个非法监听值 | PASS |
| 迁移接管/回滚 | `TestActivateSwitchesEntryAndCronOnly`、`TestValidateRejectsDrift`、`TestRecoverActivatingRestoresEntryAndCron`、`TestRecoverAfterMetadataCrashLeavesNoHalfMigration` 等 9 项 | PASS |

## 8. 静态与全量回归

| 检查 | 命令 | 退出码 | 证据 |
| --- | --- | --- | --- |
| gofmt | `gofmt -l cmd internal tests`（要求空） | 0 | `logs/go-static.log` |
| go vet | `go vet ./...` | 0 | 同上 |
| go build | `go build ./...` | 0 | 同上 |
| 离线全量 | `go test -count=1 ./...`（`--network none`） | 0 | `logs/go-test-offline.log` |
| Bash 语法 | `bash -n install.sh scripts/*.sh .github/test/*.sh tests/e2e-diff/*.sh artifacts/audit-remediation/*.sh` | 0 | `logs/bash-syntax.log` |

## 9. P1-A：Bash/Go 矩阵

目录：`tests/e2e-diff/evidence/audit-final-20261119/p2/`。每行同时执行 Bash 与 Go，
Round 1 为主、Round 2 验幂等；L1→L4 分层对照，L4 为真实数据面。

| ID | 场景 | 结论 |
| --- | --- | --- |
| M1 | Reality 标准 | MATCH |
| M2 | Reality + Nginx | MATCH |
| M3 | Reality + ws | MATCH |
| M4 | TLS ws | MATCH |
| M5 | TLS gRPC | MATCH |
| M6 | TLS xHTTP | MATCH |
| M7 | TLS ws+gRPC+xHTTP | MATCH（首轮 Go 侧遇 GitHub 下载 `unexpected EOF`，落盘为 `audit-final-20261119` 的 `BLOCKER`；单独重跑 `audit-final-m7-20261119` 双端、双轮、L4 全 ok） |
| M9 | None ws | MATCH |
| M10 | 独立 relay | MATCH |

9/9 可执行场景为 `MATCH`。首轮有一行（M7）确实是网络瞬时失败，未被隐藏：原始
`BLOCKER` 与重跑证据都保留在仓库中；重跑后 Go/Bash 的安装、两轮幂等与 L4 数据面
全部通过。M8（ACME）与真实 VPS/多版本 Xray 不在本轮可执行范围，按
`BLOCKED`/`NOT_RUN` 记录。

### 9.1 历史 98 项矩阵复跑与断言修正

任务书要求复用历史 98 项矩阵并核查它是否已合并、运行和更新。该矩阵原始证据在
`docs/go/BASH_GO_REAL_RUNTIME_PARITY_REPORT.md`（提交 `ace4a16`，2026-11-08），
本轮在修复后的工作树上重跑：

```bash
MATRIX_BASE_IMAGE=audit-matrix-base:local \
  bash tests/go-parity/matrix/run_matrix_container.sh "$PWD" \
  "$PWD/tests/go-parity/evidence/matrix-20261120-final"
```

结果：98 个 Bash 用例 + 6 个 A1 覆盖组，`54 MATCH / 40 MATCH_CORE_FIELDS /
0 GAP / 4 REFUSED / 6 A1_PASS`，退出码 0。证据见
`tests/go-parity/evidence/matrix-20261120-final/summary.json` 与 `environment.txt`。

首轮复跑出现 20 个 GAP，全部是 TLS / Reality+Nginx 的 `port` 断言。原因是旧断言
拿 Xray 回环后端端口去比 Bash 的公网端口，等于把“两个进程抢同一端口”的旧缺陷
当成预期；P2 M2/M4 的 L4 数据面已证明正确形态是 Nginx 独占公网端口、Xray 走
回环。修正只改测试意图：前置端口模式改为传 `--public-port` 并校验生成的 Nginx
`listen <port>`，不改产品代码，也不跳过任何用例。修正后 GAP 归零，与历史报告
预期的 `54 / 40 / 0 / 4` 一致。

### 9.2 OPS 运营路径

任务书要求覆盖用户、端口、配置、日志、服务、更新、卸载等管理路径。本轮先执行
Go 侧 sweep：

```bash
E2E_RUN_ID=audit-ops-20261120 bash tests/e2e-diff/run_ops_sweep.sh
```

结果 36 PASS / 0 FAIL，覆盖 OPS-01/02/03/11/12/13/14/14a/15/17a/18/20/22/25/
26/28/29 与 OPSS-01。证据：
`tests/e2e-diff/evidence/audit-ops-20261120/assertions.txt`、`ops/`、`run.log`。
这一项仍是 **Go 单侧**，不据此宣称双端 MATCH。

随后用同一双端驱动补跑已在 `run_p2_matrix.sh` 中实现的 5 个 OPS：

```bash
E2E_RUN_ID=audit-ops-dual-20261120 \
  E2E_ONLY=OPS-19,OPS-21,OPS-09,OPS-31,OPS-32 \
  bash tests/e2e-diff/run_p2_matrix.sh
```

结果 5/5 PASS（Bash 与 Go 各执行真实安装、真实 Nginx/Xray 和真实数据面），
运行代码 SHA `1cd8b98c`。证据：
`tests/e2e-diff/evidence/audit-ops-dual-20261120/p2/`。OPS-21 的判定按“本侧必需
检查”计算：Bash 14 项、Go 26 项，`customRuleApplied` 是 Go-only 检查，不要求
Bash 侧满足；两侧 `baselineControl` 和阻断/恢复检查均为 true。

这次 OPS-only 运行暴露了一个测试夹具缺陷：`matrix_get` 用
`next(x for x in matrix['install'] if x['id']==sid)` 读取 OPS 行时会抛
`StopIteration`，虽然 install 仍成功、判定仍 PASS，但日志有噪声。已改为带默认值
的 `next(..., {})`，不影响任何产品行为或既有判定。

提交前已对双端证据做脱敏（UUID、邮箱、私钥、shortId、公网 DNS 替换为
`REDACTED`/`user@example.com`/`127.0.0.1`），PASS/FAIL 计数不变。

其余 18 个 OPS 仍未双端复跑，在 `PARITY_MATRIX.csv` 记为 `NOT_RUN`。
`matrix.json` 的 `go: null` 曾把多项标成缺失：OPS-05/06/07/10/17b/24 分别有
`xray edit --uuid`、`--target`、`xray tls --version`、`--server-names`、
`update nginx`、`schedule run --job geodata-refresh`；OPS-30（语言切换）是
有意差异。

### 9.3 OPS-08 / OPS-27 Go 命令补齐

原先 `matrix.json` 中 OPS-08（在线修改 SNI Guard）与 OPS-27（清空证书）的
`go` 字段为 `null`。本轮在 `241cc99f` 新增：

```text
idleleo xray guard show
idleleo xray guard set --policy isolate|reject|decoy [--decoy-domain D]
                       [--decoy-cert C --decoy-key K] [--decoy-ip IP]
                       [--dry-run] [--json]
idleleo xray cert clear [--yes] [--dry-run] [--json]
```

`xray guard set` 复用 Bash 的三个保留回环端口（9403/9404/9444），只改
`upstream deny` 的服务端口和 `03-isolate.conf`/`03-decoy.conf` 的 include，
不重写整个 mesh；写前捕获文件、`nginx -t` 失败自动还原；decoy 会校验域名解析
到本机（可用 `--decoy-ip` 补充 NAT 公网地址），未提供证书时生成 1 年自签
RSA-2048 对。`xray cert clear` 的**当前语义**（`df3f3838` 起）：只有在能证明
证书属于本项目、且未被 Nginx/Xray/计划任务引用时才删除；`--dry-run` 零写，
删除走 staging + journal，失败恢复；ACME 账户与第三方域名材料保留。§9.3 的
旧描述“真实 root 删除 acme 与 decoy 证书”已被本轮 A1 用例取代。

验证命令与结果：

```bash
docker run --rm -v "$PWD":/src -w /src \
  -e GOFLAGS=-mod=vendor -e GOPROXY=off -e GOTOOLCHAIN=local \
  golang:1.27.4 sh -c '
    go build -o /tmp/idleleo ./cmd/idleleo &&
    go test ./internal/deploy -run "SNIGuard|ClearCertificates" -v &&
    bash tests/e2e-diff/smoke_guard_cert.sh /tmp/idleleo /tmp/ops-guard-cert'
```

结果：`go test ./...` 全绿（deploy 8.0s）；新增 9 个测试覆盖 isolate/reject/
decoy、端口冲突、`nginx -t` 回滚、证书删除与 dry-run；CLI smoke 输出
`OPS-08/OPS-27 smoke: PASS`。证据：
`artifacts/audit-remediation/logs/ops08-27-smoke.log`、`tests/e2e-diff/smoke_guard_cert.sh`。

真实 Nginx 验证（`nginx:1.27-alpine`，容器内真实 root）：

```bash
docker run --rm -v "$PWD":/src -w /src -v /tmp:/out \
  -e GOFLAGS=-mod=vendor -e GOPROXY=off -e GOTOOLCHAIN=local -e CGO_ENABLED=0 \
  golang:1.27.4 go build -o /out/idleleo-linux ./cmd/idleleo
docker run --rm -v /tmp/idleleo-linux:/usr/local/bin/idleleo:ro \
  -v "$PWD/tests/e2e-diff/smoke_guard_nginx.sh":/smoke.sh:ro \
  nginx:1.27-alpine sh /smoke.sh /usr/local/bin/idleleo
```

结果：isolate → reject（deny 9404、删除 03-isolate）、reject → decoy（自签
decoy.local、deny 9444、私钥 0600）、decoy → isolate（deny 9403、只保留一个
include）均执行真实 `nginx -t` 并输出 `syntax is ok` / `test is successful`；
该轮 smoke 当时在真实 root 删除了 acme 与 decoy 证书；**这一行为在第三轮 A1
被收紧**，现在只删除可证明归属且无在用的本项目证书，第三方与账户材料保留。
OPS-08/27 的结论以 `ops08-27-real-nginx.log` 与 A1 新用例为准，最后输出
`OPS-08/OPS-27 real nginx: PASS`。证据：
`artifacts/audit-remediation/logs/ops08-27-nginx.log`、
`tests/e2e-diff/smoke_guard_nginx.sh`。

**验证边界**：该容器没有 init system，脚本用 `systemctl` 桩让 reload 步骤通过；
Nginx 二进制和 `nginx -t` 都是真实的。OPS-08/27 的 Bash 交互答案（策略选择、
确认）尚未接入 `run_p2_matrix.sh`，因此双端结论仍为 `NOT_RUN`，不记为 MATCH。

## 10. 复现入口

```bash
bash artifacts/audit-remediation/p0a_relay_exposure.sh
bash artifacts/audit-remediation/p0c_migration_restore.sh
E2E_RUN_ID=<id> E2E_ONLY=M1,M4,M9 E2E_CONCURRENCY=3 bash tests/e2e-diff/run_p2_matrix.sh
MATRIX_BASE_IMAGE=audit-matrix-base:local bash tests/go-parity/matrix/run_matrix_container.sh "$PWD" "$PWD/tests/go-parity/evidence/matrix-20261120-final"
E2E_RUN_ID=<id> bash tests/e2e-diff/run_ops_sweep.sh
E2E_RUN_ID=<id> E2E_ONLY=OPS-19,OPS-21,OPS-09,OPS-31,OPS-32 bash tests/e2e-diff/run_p2_matrix.sh
docker run --rm -v "$PWD":/src -w /src golang:1.27.4 \
  sh -c 'go build -o /tmp/idleleo ./cmd/idleleo && bash tests/e2e-diff/smoke_guard_cert.sh /tmp/idleleo'
docker run --rm -v /tmp/idleleo-linux:/usr/local/bin/idleleo:ro \
  -v "$PWD/tests/e2e-diff/smoke_guard_nginx.sh":/smoke.sh:ro \
  nginx:1.27-alpine sh /smoke.sh /usr/local/bin/idleleo
```

## 11. 2026-11-20 复审证据

环境：macOS 宿主机 + Docker；Go 统一用
`golang:1.27.4`，`GOFLAGS=-mod=vendor GOPROXY=off GOTOOLCHAIN=local`；
Xray `26.10.31`；Nginx `1.27-alpine`。修复提交 `9f66b22a` + `f217a2fa`，
收尾修复 `1cd248e6`（`config edit --host`、OPS-32 恢复判定）。

### 11.1 静态与全量

| 命令 | 结果 | 日志 |
| --- | --- | --- |
| `gofmt -l cmd internal tests` | 无输出 | `artifacts/audit-remediation/followup-20261120/c1/go.log` |
| `go vet ./...` | exit 0 | 同上 |
| `go build ./...` | exit 0 | 同上 |
| `go test -count=1 ./...` | 全绿 | 同上 |
| 重点包 `-v` + `-race` | 全绿 | `.../c1/targeted-race.log` |
| `bash -n install.sh` | exit 0 | 终端记录 |

### 11.2 分享链路红绿对照

- **pre-fix（`d13fca44`）F28**：在 Docker 内给 `/etc/idleleo` 放入一份 `tls=None`
  的无关元数据，`xray share` 未带 `--root`，结果 **35 passed / 2 failed**，错误正是
  `--public-security none conflicts with runtime stream security=reality`。摘要见
  `artifacts/audit-remediation/followup-20261120/f28-prefix-excerpt.txt`。
- **post-fix**：同一测试 **57 passed / 0 failed**，证据
  `artifacts/audit-remediation/followup-20261120/f28/`。
- 其他受影响 fixture：F08 **129/0**、F18 **178/0**（含 `qrencode`），证据
  `.../f08/`、`.../f18/`。
- 单元测试新增：跨 root 元数据、同路径陈旧哈希（忽略默认值并告警、歧义时拒绝）、
  路径规范化、Reality 拒绝 SNI 当 Host、Reality Host/SNI 分离、显式标志覆盖、
  多用户选择。

### 11.3 矩阵与 P2

| 套件 | 结果 | 证据 |
| --- | --- | --- |
| 98 项 Bash/Go 矩阵 | 104 行 = 54 `MATCH` + 40 `MATCH_CORE_FIELDS` + 4 `REFUSED` + 6 `A1_PASS`，0 GAP | `tests/go-parity/evidence/matrix-fix-20261120-clean/`（`repo_dirty=0`） |
| P2 M1-M10 / E1-E8 / OPS-19/21/09/31/32 | 见 `fix-20261120-p2b` 的逐项 verdict | `tests/e2e-diff/evidence/fix-20261120-p2b/p2/` |
| 复跑前的失败定位 | `fix-20261120-p2`：E1/E7/E8 与 OPS-21 均因 Reality 分享缺少 `--host` 而失败；非产品缺陷，已在驱动中显式传 Host | `tests/e2e-diff/evidence/fix-20261120-p2/p2/` |

### 11.4 隐私与证据卫生

| 检查 | 结果 |
| --- | --- |
| `check_evidence_hygiene.py --mask .` | 0 命中（修复前 4 处本机绝对路径） |
| `test_environment_contract.py` | 通过（生成器剥离校验和路径 + 全量历史 environment.txt 扫描） |
| F28 `commands.log` | 无 `PrivateKey`、无 `x25519 -i` argv；仅 `<redacted command>` |
| `artifacts/audit-remediation/followup-20261120/binaries.sha256` | 记录 pre-fix / post-fix 二进制摘要，二进制本体未入库 |

### 11.5 复现命令

```bash
MATRIX_BASE_IMAGE=audit-matrix-base:local bash tests/go-parity/matrix/run_matrix_container.sh \
  "$PWD" "$PWD/tests/go-parity/evidence/matrix-fix-20261120-clean2"
E2E_RUN_ID=fix-20261120-p2h E2E_ONLY=E7,E8 bash tests/e2e-diff/run_p2_matrix.sh
E2E_RUN_ID=fix-20261120-p2i E2E_ONLY=OPS-32 bash tests/e2e-diff/run_p2_matrix.sh
python3 tests/go-parity/parity/scripts/check_evidence_hygiene.py --mask .
python3 tests/go-parity/matrix/test_environment_contract.py
```

### 11.6 收尾修复复验（`1cd248e6`）

| 项 | 结果 | 证据 |
| --- | --- | --- |
| `gofmt` / `go vet` / `go build` / `go test ./...` | `rc=0`，0 FAIL | `artifacts/audit-remediation/followup-20261120/c3/{gate.rc,go-test.log}` |
| 二进制固定 | `idleleo` `42f2de09…`（`-buildvcs=false -trimpath`）、Xray `26.10.31` `59396499…` | `.../c3/binaries.sha256` |
| F28 / F08 / F18 | **57/0**、**129/0**、**178/0** | `.../c3/{f28,f08,f18}/fixture-result.json` |
| E1-E6（config edit 全场景） | 全部 `allPassed`（E1 6/6、E2 4/4、E3 4/4、E4 5/5、E5 11/11、E6 10/10 checks） | `tests/e2e-diff/evidence/fix-20261120-p2j/p2/` |
| E7 / E8（两侧 `--host 127.0.0.1`） | **13/13**、**14/14** `allPassed`，`run.json.commit=1cd248e6` | `tests/e2e-diff/evidence/fix-20261120-p2h/p2/` |
| 98 项矩阵 | 104 行 = 54 `MATCH` + 40 `MATCH_CORE_FIELDS` + 4 `REFUSED` + 6 `A1_PASS`，0 GAP，`repo_dirty=0` | `tests/go-parity/evidence/matrix-fix-20261120-clean2/` |
| OPS-32（ws / reality） | **PASS / PASS**，`run.json.commit=1cd248e6` | `tests/e2e-diff/evidence/fix-20261120-p2i/p2/OPS-32/` |
| 证据卫生 | `hygiene: 0 finding(s)` | 本轮全仓扫描 |

- **`config edit --host`**：`internal/xraycfg/reality_edit_test.go` 新增
  `TestEditHostBecomesTheDialAddress`（三个链接都拨 `@203.0.113.10:443`、仍带
  `sni=example.com`、不再出现 `@example.com:443`）、
  `TestEditShortIDLinksUseTheExplicitHost`、`TestEditRejectsURLAsHost`；
  `internal/cli` / `internal/deploy` / `internal/xraycfg` 全包测试通过。
- **OPS-32 判定修正**：`stable_recovery` 改为“完整窗口尾部 `2*fail_timeout`
  内 A ≥ 3 且相邻 A 间隔 ≤ `fail_timeout`”。p2d 的原始探测数据用新分析器重算
  同样得到 PASS（reality 链长 bash 9 / go 5，ws 链长 bash 11 / go 10；见
  `artifacts/audit-remediation/followup-20261120/ops32-reanalysis/`），说明
  p2d 的 `BLOCKER` 来自判定口径而非行为差异；本轮以 p2i 的新探测数据为准。
- E7/E8 的驱动与命令行两侧统一用 `--host 127.0.0.1`，`oldLinkCaptured` /
  `backupHasOldShareUri` 不再依赖“SNI 恰好等于探测地址”。

### 11.7 离线包缓存（OPS-19/31/32，FUP-10）

网络抖动不再进入这三项的 verdict：Nginx 发布包与 Xray 配置模板由 runner 预置，
Bash 与 Go 共享同一份缓存，并保留全部既有校验。

| 项 | 结果 | 证据 |
| --- | --- | --- |
| Go 单元 | 4 个 `ResolveFromCache` 测试通过：命中不发任何网络请求；损坏/缺失/build 不符全部失败 | `internal/nginx/artifact_test.go` |
| OPS-19 / OPS-31 / OPS-32（ws + reality） | **PASS**；4 份 bash 安装日志均出现 `Nginx 使用离线缓存` + `使用缓存产物` 与模板 `使用离线缓存: config/...`，0 下载错误 | `tests/e2e-diff/evidence/fix-20261120-cache2/p2/` |
| OPS-19 apt | **PASS**；安装日志出现 `使用离线 apt 缓存, 跳过软件源更新`，`Get:` / `apt-get update` 均为 0 条；阻断 `ports.ubuntu.com` 等归档主机后仍 **PASS** | `.../fix-20261120-apt1/p2/`、`.../fix-20261120-apt2/p2/` |
| 离线证明（GitHub/raw 全部指向 `127.0.0.1`） | OPS-32 **ws PASS / reality PASS** | `tests/e2e-diff/evidence/fix-20261120-cache4/p2/` |
| 缓存清单 | Nginx build `2026.10.15.7679`、arch `arm`、tarball `dc78117f…`；apt `75` 个 .deb（含 fail2ban 及依赖） | `.../cache2/p2/nginx-cache.json`、`.../apt1/p2/apt-cache.json` |

- Nginx 包缓存：runner 先校验 `release-manifest.json` 的
  `versions.nginx_build`、`assets[arch].filename/sha256/size_bytes` 与宿主文件一致，
  才注入 `IDLELEO_NGINX_CACHE=/seed/nginx`。Go 的 `Options.CacheDir` 一旦设置就
  **不访问网络**，缺文件/损坏直接失败（`Nginx cache is incomplete`、
  `sha256 mismatch`），避免“缓存失败被在线下载悄悄替代”。
- 模板缓存：runner 把 `config/vless_reality.json`、`config/vless_tls.json` 播种到
  `/seed/release`；`download_json_file` 命中后仍执行 `jq empty` 校验，损坏即失败。
- apt 缓存：runner 用与 E2E 镜像相同的 `ubuntu:24.04@sha256:…` 下载
  `bc curl dbus git jq lsof python3 qrencode cron fail2ban` 的完整 .deb 闭包
  （75 个）到 `$HOME/.cache/xray-audit/apt/noble-<arch>`，校验非空后注入
  `IDLELEO_APT_CACHE=/seed/apt`。`check_system` 在离线模式下跳过 `apt update`；
  `pkg_install` 若发现缺包则 `dpkg -i` 整个闭包，仍缺包即失败，不回退网络。
- 离线证明命令：

  ```bash
  E2E_RUN_ID=<id> E2E_ONLY=OPS-19 E2E_CONCURRENCY=1 \
    E2E_BLOCK_HOSTS=ports.ubuntu.com,archive.ubuntu.com,security.ubuntu.com,deb.debian.org,github.com,raw.githubusercontent.com,cdn.jsdelivr.net,objects.githubusercontent.com,release-assets.githubusercontent.com \
    bash tests/e2e-diff/run_p2_matrix.sh
  ```


## 12. 第三轮候选验收（2026-11-20，`df3f3838`）

完整报告见 [DOCKER_ACCEPTANCE_20261120.md](DOCKER_ACCEPTANCE_20261120.md)，证据目录
`artifacts/audit-remediation/docker-final-round3-20261120-df3f3838/`。

### 12.1 A1–A5

| ID | 结果 | 证据 |
| --- | --- | --- |
| A1 证书清理所有权/引用/事务 | PASS（Bash 旧风险为 `INTENTIONAL_SAFETY_DELTA`） | `artifacts/go-docker-20261120/a1-red-baseline.log`、`a1-acme-realroot-final.log` |
| A2 分享拨号地址/SNI/归属 | PASS_IMPACT_SCOPED（候选未重跑 F28） | `internal/cli/share_metadata_test.go`；F28 57/0、F08 129/0、F18 178/0 |
| A3 Guard show 不再默认 enabled/isolate | PASS | `.../a3-guard-redgreen.log`、`smoke-guard-cert-final.log` |
| A4 XHTTP 路径 | 非缺陷，语义差异记录 | `.../a4-prefix-probe.log`、`artifacts/go-docker-20261120/a4-xhttp-path.log` |
| A5 已修复项/缓存/OPS-32/Test Install | PARTIAL（Test Install 在 `aa4b9da9` 通过，根因未定位） | `.../p2/OPS-32`、`gate-final.log`、run 44725121834 |

A3 红绿：父提交在“元数据 Reality、无 Nginx guard fragment”时输出
`sniGuard=true policy=isolate`；候选输出 `applicable=false status=not-applicable`。
A4 负例：把候选新增测试复制到父提交 `45666732` 仍然通过，证明 `Generate` 早已
补前导 `/`，不存在可复现断连。

### 12.2 双端与真实运行

| 套件 | 结果 | 证据 |
| --- | --- | --- |
| M1–M10（fresh + 幂等 + L4/L6） | 双端 install rc=0；两轮 L4 ok；幂等 rc2=0 | `tests/e2e-diff/evidence/round3-final-20261120-1821-df3f3838/p2/` |
| E1–E8（Go 编辑） | 67 项检查全满足 | 同上 `E1`…`E8` |
| OPS-09/19/21/31/32 | 双端 PASS | 同上 |
| OPS Go sweep | 36 PASS / 0 FAIL（17 ID） | `tests/e2e-diff/evidence/round3-ops-20261120-1818/` |
| 98 项矩阵 | 54 MATCH + 40 CORE + 4 REFUSED + 6 A1，0 GAP | `tests/go-parity/evidence/matrix-20261120-final/` |
| 冷恢复 | source 8/8、target 19/19 | `tests/e2e-diff/evidence/goevo-coldrestore-docker-final-cold-20261120-df3f3838/` |
| R1/R2/INJ | 106 PASS / 0 FAIL | `tests/e2e-diff/evidence/docker-final-r1-20261120-df3f3838/r1/` |
| P3 xhttp | 62/62 | `tests/e2e-diff/evidence/goevo-p3-docker-final-p3xhttp-20261120-df3f3838/` |
| race（8 包） | rc=0 | `.../race-final.log` |
| CI（`aa4b9da9`） | 7/7 success（含 Test Install） | run 44725121966/21993/21851/22135/21880/21834/21949 |
| CI（HEAD `beb51ab9`） | 7/7 success（30 check pass / 1 skip） | run 44725987921/87933/87816/87872/87940/87830/87943 |

### 12.3 未完成项

- 34 个 OPS：双端 5、Go sweep 17、Go 命令 2、未执行 10。禁止用 Go-only sweep 替代。
- 9 个 subscripts：未逐项确认。
- 多版本 Xray/Bash、第二发行版 smoke：`NOT_RUN`。
- 30 分钟 + 两个调度周期 soak：`NOT_RUN`。
- M8 Bash 纯 ACME：`BASH_DELEGATES_GO`，纯 `acme.sh` `BLOCKED`。
- 公网 CA、外部 IPv6、VPS 重启/掉电：`VPS_DEFERRED`。

### 12.4 结论

- Docker 开发候选：`NO_GO_FOR_DOCKER_QUALIFIED_CANDIDATE`（D4：容器必需项未全部完成）。
- 正式发布：`NO_GO_NOT_AUTHORIZED`（任务书禁止；VPS 项未验证）。

## 13. 2026-11-20 补齐轮（OPS 新增行 / subscripts / soak / 多版本 / Debian）

本节记录 12.3 中 OPS、subscripts、多版本、第二发行版与 30 分钟 soak 的补齐结果；
未覆盖 12.3 的 VPS、公网 CA、外部 IPv6 边界。

### 13.1 OPS 全量回归（`ops-full-3`）

命令：`E2E_ONLY=OPS-04,OPS-05,OPS-06,OPS-07,OPS-17c,OPS-30,OPS-19,OPS-21,OPS-09,OPS-31,OPS-32`。
证据：`tests/e2e-diff/evidence/ops-full-3/p2/`。全部为同一次运行内双侧观测。

| ID | 判定 | 关键事实 |
| --- | --- | --- |
| OPS-04 | `BLOCKER` | Go `config edit --port/--public-port` 返回 `noChanges=true`、`dryRun=true`，Nginx 仍 `listen 443`；同一运行 Bash 已把 Nginx 改为 8443 |
| OPS-05 | `MATCH (allowed-diff)` | 两侧 client id 均已变化；Bash UUIDv5 vs Go 字面量 UUID |
| OPS-06 | `MATCH` | 两侧 target 与 serverNames 一致（去掉端口后比较） |
| OPS-07 | `MATCH` | 两侧 Nginx 由 `#TLSv1.2 1;` 变为 `TLSv1.2 1;` |
| OPS-17c | `MATCH` | Bash cron `auto_update.sh`；Go systemd timer `idleleo-schedule` |
| OPS-30 | `BASH_ONLY` | `language.conf` 由 absent → 新 SHA；Go 无语言命令，不计 dualSide |
| OPS-09/19/21/31/32 | `PASS` | 既有 5 项本轮未退化 |

OPS-10 单独运行（`ops10-2`）：Bash 进入二级 file_manager 后 driver 未驱动，
`NOT_RUN`，不计 PASS。

### 13.2 子脚本（`s-6-1`）

命令：`bash tests/e2e-diff/run_s_scripts.sh`；证据 `s-6-1/s/assertions.txt`、
`run.json`。53 PASS / 5 FAIL。

| 子脚本 | 判定 | 依据 |
| --- | --- | --- |
| S4 | PASS | auto_update 正常/重复/坏元数据；重复不改配置 |
| S5 | PASS | Pebble 真实签发/续期/失败保证书 |
| S6 | `BLOCKED` | `curl: (35) SSL_ERROR_SYSCALL` 访问 `release-assets.githubusercontent.com`；5 条正常下载断言不成立，失败分支通过 |
| S7 | PASS | acme.sh 安装/版本/帮助/缺 state fail-closed |
| S8 | PASS | 沙箱 tcp plan/apply/rollback；真实内核 apply `BLOCKED`（无 bbr） |
| S9 | PASS | speedtest 正常/重复/不可达；历史脚本 `bash -n` |
| S1–S3 | 引用 | OPS-19/21/09/31 证据 |

### 13.3 soak / 多版本 / 第二发行版

| 项 | 结果 | 证据 |
| --- | --- | --- |
| 30 分钟 soak | PASS 30/30 | `soak-30m-1/soak/soak.json`：active、`xray -test` rc=0、`:443` 监听、`NRestarts=0`、RSS < 512MiB |
| 多版本 Xray | PASS | `versions-3/versions/xray-versions.json`：`v26.11.9`、`v26.10.31`、`v26.10.21` 对同一 Reality 配置 `xray -test` rc=0（二进制兼容口径） |
| 第二发行版 | PASS | `debian12-1/p2/`：Debian 12.15 上 M1 安装 rc=0、OPS-19 双端 PASS |

### 13.4 结论修正

- OPS 覆盖从“5 双端 + 10 未执行”更新为：9 双端 PASS（含 1 allowed-diff）、
  OPS-04 双侧观测 `BLOCKER`、19 Go-only、1 BASH_ONLY、4 NOT_RUN。
- subscripts 从“未逐项确认”更新为：S4/S5/S7/S8/S9 PASS，S6 `BLOCKED`，
  S1–S3 引用 OPS 证据。
- 多版本、第二发行版、30 分钟 soak 从 `NOT_RUN` 更新为 PASS（边界见 13.3）。
- Docker 候选仍为 `NO_GO_FOR_DOCKER_QUALIFIED_CANDIDATE`：OPS-04 是真实 Go 缺陷，
  另有 OPS-10/3 项未执行；正式发布仍 `NO_GO_NOT_AUTHORIZED`。
