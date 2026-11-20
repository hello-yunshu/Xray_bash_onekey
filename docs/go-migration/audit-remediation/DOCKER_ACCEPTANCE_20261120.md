# Docker 实机验收与收尾报告（2026-11-20）

> 候选提交：`df3f38381a8d3c4f8c8bc9681d589c891f5133f6`
> 分支：`work/go-hardening-parity-20261119`；PR #182（draft，base `develop/go-native`）
> 审计基线：`4566673290453a3b9e840b4f6206dadd0dfd763f`
> Bash 基线：`install.sh` v3.3.6，pin `0fa7052e`
> 任务书：`Trae_Xray_Go_Docker实机验收与收尾_Goal_20261120.md`
> 本报告只写实际执行过的项；`NOT_RUN` / `VPS_DEFERRED` 不计通过。

## 1. 结论

| 结论 | 判定 | 一句话依据 |
| --- | --- | --- |
| Docker 开发候选 | **NO_GO_FOR_DOCKER_QUALIFIED_CANDIDATE** | 安全整改 A1/A3 与核心双端、真实客户端、迁移、故障注入通过；但 34 个 OPS 仅 5 个双端、9 个 subscripts 未跑、多版本/第二发行版与 30 分钟 soak 未执行，按 D4 不能给 GO |
| 正式发布资格 | **尚未授权 / NO_GO** | 任务书禁止发布与合并；独立 VPS、公网 CA、外部 IPv6、多版本与长期 soak 仍 `VPS_DEFERRED`/`NOT_RUN` |

**没有合并、没有打 tag、没有发布、没有操作生产 VPS。** PR 保持 draft。

## 2. 环境与冻结基线

| 项 | 值 |
| --- | --- |
| 宿主 | macOS arm64；Docker Desktop/OrbStack Linux VM，内核 `7.2.12-orbstack`，cgroup v2，overlayfs |
| Docker | client/server `29.8.2`，原生 arm64（无 amd64 模拟） |
| Go | `golang:1.27.4@sha256:5e8afd49…` |
| E2E | `idleleo-e2e:24.04@sha256:76b8b5d4…` |
| Nginx | `nginx:1.27-alpine@sha256:65645c7b…` |
| Xray | `26.10.31 (a4a3dff, go1.27.3 linux/arm64)` |
| Pebble | `ghcr.io/letsencrypt/pebble@sha256:ddf23064…` |
| Go 二进制 | `604c9f811e848f216efe4dbfcd2ef13ceab0d1e260115fe2715d37cdbc402b09`，`idleleo 0.2.0-phase04 (go)` |
| 构建 | vendored、`GOPROXY=off`、`GOTOOLCHAIN=local`、`CGO_ENABLED=0`（race 用 1） |
| 网络 | 隔离 bridge；真实客户端来自独立容器；离线门禁用 `--network none` |

机器可读快照：`artifacts/audit-remediation/docker-final-round3-20261120-df3f3838/environment.json`
与 `environment-snapshot.txt`。

## 3. 阶段 A：独立审计问题整改

| ID | 问题 | 负例（旧） | 正例（候选） | 结论 |
| --- | --- | --- | --- | --- |
| A1 | 证书清理可能删除第三方/在用证书 | 旧逻辑通配删除；`a1-red-baseline.log` | 真实 root：在用/第三方/ACME other.com 保留；dry-run 零写；staging+journal 失败恢复 | PASS（安全差异登记） |
| A2 | 分享把 SNI 当拨号地址 / 跨 root 元数据污染 | 上轮已复现（F28 35/2） | 路径+SHA 归属、`--host` 强制、Reality 不猜；F28 57/0、F08 129/0、F18 178/0 | PASS_IMPACT_SCOPED（候选未重跑） |
| A3 | `guard show` 缺状态时默认 enabled/isolate | pre-fix：`sniGuard=true policy=isolate`（`a3-guard-redgreen.log`） | candidate：`applicable=false status=not-applicable`；真实 nginx 三策略 + drift/missing | PASS |
| A4 | XHTTP `/xhttp` vs `/xhttp/` | 父提交负例测试**通过**，无可复现断连 | 真实 Xray 26.10.31 四种路径交叉 200/301 | 非缺陷，语义差异记录 |
| A5 | 已修复项/缓存/OPS-32/Test Install | 历史静默退出 | OPS-32 ws+reality 在候选 PASS；缓存与离线门禁 PASS | PARTIAL（Test Install `CI_PENDING`） |

细节与根因：`artifacts/audit-remediation/docker-final-round3-20261120-df3f3838/defects.md`。

A4 的关键事实：候选新增的 `TestEditXHTTPPathAlwaysHasLeadingSlash` 复制到父提交
`45666732` 后仍然通过，说明父提交 `xraycfg.go` 的 `Generate` 已补前导 `/`；
`df3f3838` 的 `normalizeXHTTPPath` 只是把编辑路径统一到一处。按任务书
“只是语义差异就记录，不做全量重写”处理，未回写任何已部署配置。

## 4. 阶段 B：覆盖账本与双端执行

覆盖账本：`case-matrix.csv`（54 行，列含 `bash_rc/go_rc/expected/actual/verdict/
evidence_path/limitations/delta_approval`；未跑项 rc 留空）。

### 4.1 安装模式（M1–M10）

证据：`tests/e2e-diff/evidence/round3-final-20261120-1821-df3f3838/p2/`。

- 10 个场景，Bash 与 Go **各做一次 fresh install**，均 `install rc=0`。
- 每侧两轮真实数据面（L4）均 `ok`；L6（重启/服务）`ok`；第二轮幂等 `rc2=0`。
- 覆盖 Reality 直连、Reality+Nginx、Reality+WS、TLS WS/gRPC/XHTTP、
  多传输、None+WS、独立 Nginx Stream relay、ACME。
- L1 路径差异按 `ED-C01..C15` 登记在 `install-matrix.md`，未静默忽略。
- M8（ACME）见 §5.1，只能算 `DOCKER_EQUIVALENT_WITH_LIMITS`。

### 4.2 编辑场景（E1–E8）

Go 侧 67 项检查全部满足（`allPassed=true`），覆盖改前/改后、旧/新客户端、
目标探测、TLS 证书、shortId 迁移、私钥轮换与回滚。E1–E8 是 Go 独有非交互
路径；Bash 侧没有等价 UUID/编辑入口，因此是 **Go-only 真实执行**，不是双端
MATCH。

### 4.3 OPS

| 范围 | 数量 | 方式 | 结果 |
| --- | --- | --- | --- |
| OPS-09/19/21/31/32 | 5 | Bash 菜单等价路径 + Go CLI，真实 Nginx/Xray/数据面 | 双端 PASS |
| OPS Go sweep | 17 个 ID / 36 断言 | 仅 Go | 36 PASS / 0 FAIL |
| OPS-08/27 | 2 | 仅 Go + 真实 `nginx -t` | PASS |
| 其余 OPS | 10 | 未执行（部分有等价命令未跑） | `NOT_RUN`（OPS-30 为批准的差异） |

**这就是 Docker 候选 NO-GO 的首要原因**：任务书要求 34 个 OPS 一行一个、
逐项双端，且明确“不要留 Go-only sweep 作为替代”。本轮没有做到。

### 4.4 subscripts

原 9 项 subscripts 未逐项确认真实运行、Go 原生替换或有意取消。标 `NOT_RUN`，
不以历史 CI 或空映射替代。

### 4.5 98 项历史矩阵

`tests/go-parity/evidence/matrix-20261120-final/summary.json`：
104 行 = 54 MATCH + 40 MATCH_CORE_FIELDS + 4 REFUSED + 6 A1，**0 GAP**。
该矩阵是配置/功能矩阵，不是真实部署；`summary.git_commit` 字段为 `86d810e5`
（生成元数据），实际在候选工作树重跑，报告不把该字段当作候选 SHA。

## 5. 阶段 C：用 Docker 补齐 VPS 延期项

### 5.1 M8：本地真实 ACME（Pebble）

- Go 侧：`acme_directory=https://pebble:14000/dir`，真实 ACME 协议签发
  `acme_issue_exit=0`，证书加载、续期、计划任务、客户端请求均验证。
- Bash 侧：`bash_install.sh` 在 Pebble 模式**实际调用 `idleleo xray cert issue`**，
  登记为 `BASH_DELEGATES_GO`。镜像是固定 Bash 基线 + 无公网，纯 `acme.sh`
  路径 **BLOCKED**。
- 因此 M8 只能证明 Go ACME 与 Bash 安装流程协同，**不能**声称纯 Bash ACME。
  公网 CA/DNS-01/EAB 记 `VPS_DEFERRED`。

### 5.2 迁移、接管与冷恢复

- R1/R2/INJ：真实旧安装 → Go 接管 → 真实客户端 → 回滚/故障注入，
  `106 PASS / 0 FAIL`（`docker-final-r1-20261120-df3f3838/r1/assertions.txt`）。
- 冷恢复：源容器真实可用 → 备份 → 销毁源容器 → 全新目标容器仅靠备份恢复，
  source 8/8、target 19/19，配置逐字节一致，重启后客户端仍通
  （`goevo-coldrestore-docker-final-cold-20261120-df3f3838/`）。
- P3 xhttp：62/62 PASS（`goevo-p3-docker-final-p3xhttp-20261120-df3f3838/`）。

### 5.3 多版本、发行版与网络

| 项 | 状态 | 说明 |
| --- | --- | --- |
| 2 个真实旧 Xray + 当前版本 | `NOT_RUN` | 未取得固定上游 Release 资产；不伪造版本 |
| 2 个代表旧 Bash 节点 | `NOT_RUN` | 同上 |
| 第二发行版 smoke | `NOT_RUN` | 本轮只有 Ubuntu 24.04 |
| 容器内 IPv6 监听/回环 | PASS | `[::]`/`::1` 已测 |
| 外部公网 IPv6/NAT | `VPS_DEFERRED` | 宿主无公网 IPv6 |

### 5.4 故障与持续运行

- 31 条故障注入既有用例在本轮门禁中通过：无 root、只读、ENOSPC/EROFS/EACCES、
  断网、过期证书、坏配置/journal、端口占用、并发、SIGKILL、陈旧锁、回滚失败、
  迁移接管/回滚。
- A1/A3 新增真实 root 与真实 Nginx 故障场景。
- **30 分钟 + 两个调度周期 soak 未执行**（无现成 runner，未新增架构），
  标 `NOT_RUN`，不声称长期稳定性。

## 6. 三轮审计闭环

| 轮次 | 输入 | 动作 | 输出 |
| --- | --- | --- | --- |
| 第 1 轮 | 审计基线 `45666732` | 逐条复现 A1–A5；A1 红测、A3 红绿探针 | 缺陷与证据清单 |
| 第 2 轮 | 修复提交 `df3f3838` | 定向单测、真实 nginx、真实 root、OPS 双端、P3 xhttp | 修复绿证与残余边界 |
| 第 3 轮 | 候选 `df3f3838` | 全量矩阵、OPS sweep、冷恢复、R1/INJ、98 项矩阵、race、门禁 | 本文与 `final-gates.*` |

三轮之间没有删除失败证据：M7 首轮网络 `unexpected EOF`、A3 pre-fix 默认值、
A4 父提交负例通过、M8 Bash 委托 Go 均保留在仓库中。

## 7. 证据卫生

- 私钥、真实 UUID/shortId、真实域名、宿主绝对路径未写入证据；敏感值用
  `REDACTED`/`127.0.0.1`/`example.com` 替代。
- F28 命令日志已脱敏；fixture root 不在 evidence 目录内。
- 证据不含生产 VPS 数据；所有容器均在本机一次性创建并销毁。

## 8. 复现命令

```bash
# 全量双端矩阵（M1–M10）
E2E_RUN_ID=round3-final-$(date +%Y%m%d-%H%M) bash tests/e2e-diff/run_p2_matrix.sh

# OPS Go sweep
E2E_RUN_ID=round3-ops-$(date +%Y%m%d-%H%M) bash tests/e2e-diff/run_ops_sweep.sh

# OPS 双端 5 项
E2E_RUN_ID=round3-ops-dual E2E_ONLY=OPS-19,OPS-21,OPS-09,OPS-31,OPS-32 \
  bash tests/e2e-diff/run_p2_matrix.sh

# 冷恢复
E2E_RUN_ID=docker-final-cold bash tests/e2e-diff/run_coldrestore.sh

# R1/R2/INJ
E2E_RUN_ID=docker-final-r1 bash tests/e2e-diff/run_r1_upgrade.sh

# P3 xhttp
E2E_RUN_ID=docker-final-p3xhttp E2E_TRANSPORT=xhttp bash tests/e2e-diff/run_p3_hot.sh

# 98 项矩阵
MATRIX_BASE_IMAGE=audit-matrix-base:local \
  bash tests/go-parity/matrix/run_matrix_container.sh "$PWD" \
  "$PWD/tests/go-parity/evidence/matrix-20261120-final"

# 离线门禁 + race
docker run --rm --network none -v "$PWD:/src:ro" -w /src \
  -e GOFLAGS=-mod=vendor -e GOPROXY=off -e GOTOOLCHAIN=local -e GOCACHE=/tmp/gocache \
  golang:1.27.4 bash -c 'export PATH=$PATH:/usr/local/go/bin; go test -count=1 ./...'
docker run --rm --network none -v "$PWD:/src:ro" -w /src \
  -e GOFLAGS=-mod=vendor -e GOPROXY=off -e GOTOOLCHAIN=local -e GOCACHE=/tmp/gocache \
  -e CGO_ENABLED=1 golang:1.27.4 bash -c \
  'export PATH=$PATH:/usr/local/go/bin; go test -race -count=1 ./internal/cli ./internal/deploy ./internal/xraycfg ./internal/store ./internal/change ./internal/backup ./internal/repair ./internal/schedule'
```

## 9. 交付物索引

- 本报告：`docs/go-migration/audit-remediation/DOCKER_ACCEPTANCE_20261120.md`
- 唯一证据目录：`artifacts/audit-remediation/docker-final-round3-20261120-df3f3838/`
  - `environment.json`、`environment-snapshot.txt`
  - `case-matrix.csv`（54 行覆盖账本）
  - `defects.md`（A1–A5 复现/根因/修复/红绿/残余风险）
  - `docker-vps-boundaries.md`
  - `final-gates.json`、`final-gates.md`
  - `race-final.log`、`a3-guard-redgreen.log`、`a4-prefix-probe.log`
- 运行证据：`tests/e2e-diff/evidence/round3-final-20261120-1821-df3f3838/`、
  `round3-ops-20261120-1818/`、`goevo-coldrestore-docker-final-cold-20261120-df3f3838/`、
  `docker-final-r1-20261120-df3f3838/`、`goevo-p3-docker-final-p3xhttp-20261120-df3f3838/`、
  `tests/go-parity/evidence/matrix-20261120-final/`
- 既有审计文档：`AUDIT_ISSUES.md`、`REMEDIATION_PLAN.md`、`PARITY_MATRIX.csv`、
  `TEST_EVIDENCE.md`、`FINAL_AUDIT.md`
