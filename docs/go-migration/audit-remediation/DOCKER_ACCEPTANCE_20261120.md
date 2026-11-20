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
| Docker 开发候选 | **NO_GO_FOR_DOCKER_QUALIFIED_CANDIDATE** | 既有 5 项 OPS 未退化；新增 6 项中 5 项双端 PASS、1 项 `BASH_ONLY`；OPS-04 公网端口 no-op 缺陷已修复并复跑 PASS；OPS-10 与 3 项 OPS 仍 `NOT_RUN`；S4/S5/S7/S8/S9、30 分钟 soak、3 个真实 Xray 版本、Debian 12 smoke 均通过，S6 因外网资产不可达 `BLOCKED`。按 D4 仍不能给 GO |
| 正式发布资格 | **尚未授权 / NO_GO** | 任务书禁止发布与合并；独立 VPS、公网 CA、外部公网 IPv6 仍 `VPS_DEFERRED`；旧 Bash 节点升级矩阵与纯 Bash ACME 未完成 |

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
| A5 | 已修复项/缓存/OPS-32/Test Install | 历史静默退出 | OPS-32 ws+reality 在候选 PASS；缓存与离线门禁 PASS；`aa4b9da9` 上 Test Install 通过 | PARTIAL（静默退出根因未定位） |

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
| OPS-09/19/21/31/32 | 5 | Bash 菜单等价路径 + Go CLI，真实 Nginx/Xray/数据面 | 双端 PASS（本轮全量回归未退化） |
| OPS-04/05/06/07/17c/30（新增） | 6 | 同一次运行内 Bash `expect` 驱动真实 `install.sh` 菜单 + Go CLI，快照比对 | 04/05/06/07/17c 双端 PASS；30 `BASH_ONLY` |
| OPS-10 | 1 | Go CLI 已改 serverNames；Bash 进入二级菜单后未驱动 | `NOT_RUN` |
| OPS Go sweep | 17 个 ID / 36 断言 | 仅 Go | 36 PASS / 0 FAIL |
| OPS-08/27 | 2 | 仅 Go + 真实 `nginx -t` | PASS |
| 其余 OPS | 3 | 未执行 | `NOT_RUN` |

**新增 OPS 的证据与判定口径**（全部在 `tests/e2e-diff/evidence/opsfix-3/p2/`）：

| ID | Bash 观测 | Go 观测 | 判定 |
| --- | --- | --- | --- |
| OPS-04 | `2>2>2` 改端口后 Nginx `listen 8443 reuseport`，Xray active | `xray config edit --port 8444 --public-port 8443` 后 Nginx 同样 `listen 8443`，Xray active | `MATCH`（修复后） |
| OPS-05 | `2>2>1` 自定义映射 → UUIDv5 | `config edit --uuid <literal> --no-probe` 写入同一格式 UUID | `MATCH (allowed-diff)`：取值算法不同、结构等价 |
| OPS-06 | `2>2>3` 改 target + serverNames | `config edit --target <host>:443 --server-names <host>` 一致 | `MATCH` |
| OPS-07 | `2>2>4` 启用 TLSv1.2 → Nginx `TLSv1.2 1;` 取消注释 | `xray tls --version 1.2+` 产生同一行 | `MATCH` |
| OPS-10 | `2>3>2` 进入嵌套 file_manager，driver 未驱动 | CLI 修改 serverNames（Go 侧仅参考） | `NOT_RUN`（不计 PASS） |
| OPS-17c | `5>4` 启用自动更新 → cron `auto_update.sh` | `schedule install --interval 3600` → systemd timer `idleleo-schedule` | `MATCH` |
| OPS-30 | `8` 切换语言 → `language.conf` 变化 | 无 Go 等价命令 | `BASH_ONLY`（不计 dualSide） |

**OPS-04 缺陷已修复**：根因是 `internal/xraycfg` 的 no-op 判定只比对 Xray 运行时 diff；
Reality+Nginx 下公网端口只改 Nginx 前端与分享链接，运行时 inbound 仍是 9443，
空 diff 被误判为 `NoChanges`，CLI 因此提前返回。修复为在 Nginx 前端模式下把
`spec.PublicPort` 与实时前端端口比较（`frontPortChanged`），并补了回归测试
`TestEditPublicPortOnNginxFrontIsNotANoOp`。修复后 `ops04-8` 与 `opsfix-3`
均为双端 `PASS`，Nginx 两侧都监听 8443。

**Docker 候选仍为 NO-GO**：OPS-10 与 3 项 OPS 未执行，OPS-30 无 Go 等价；
不能用 Go-only sweep 替代。

### 4.4 subscripts

`tests/e2e-diff/run_s_scripts.sh` 本轮真实运行，证据 `tests/e2e-diff/evidence/s-6-1/s/`
（`assertions.txt` 53 PASS / 5 FAIL，`run.json`）。

| 子脚本 | 结果 | 说明 |
| --- | --- | --- |
| S4 auto_update | PASS | 正常/重复/坏元数据三路径；重复不改 `install_config.json` |
| S5 ssl_update + Pebble | PASS | 真实 ACME 签发/续期/失败保证书，Nginx/Xray 保持 active |
| S6 geo_update | **BLOCKED** | 下载依赖 `release-assets.githubusercontent.com`，本网络 TLS 失败（`curl: (35)`）；失败分支与回滚断言通过，正常下载 5 条断言不成立，按 spec 记 `BLOCKED` 而非产品 FAIL |
| S7 acme.sh legacy | PASS | 安装、`--version`/`--help`、缺 state 时 fail-closed；真实签发 `BLOCKED`（外部 CA） |
| S8 tcp | PASS | 沙箱 plan/apply/rollback + 历史 `tcp.sh` 下载 `bash -n`；真实内核 apply `BLOCKED`（宿主无 bbr） |
| S9 speedtest | PASS | 正常/重复/不可达服务器；历史 `superspeed.sh` 下载 `bash -n` |
| S1–S3 | 引用 | 直接引用同批次 OPS-19/21/09/31 证据，不重复造数据 |

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
| 2 个真实旧 Xray + 当前版本 | PASS（二进制/配置兼容） | `v26.11.9`、`v26.10.31`、`v26.10.21` 对同一 Reality 配置 `xray -test` 均 rc=0（`versions-3/versions/xray-versions.json`）；不是逐版本完整部署 |
| 2 个代表旧 Bash 节点 | `NOT_RUN` | 未取得旧节点快照，不伪造 |
| 第二发行版 smoke | PASS | Debian 12.15：M1 Reality 安装 + OPS-19 fail2ban 双端 PASS（`debian12-1/p2/`） |
| 容器内 IPv6 监听/回环 | PASS | `[::]`/`::1` 已测 |
| 外部公网 IPv6/NAT | `VPS_DEFERRED` | 宿主无公网 IPv6 |

### 5.4 故障与持续运行

- 31 条故障注入既有用例在本轮门禁中通过：无 root、只读、ENOSPC/EROFS/EACCES、
  断网、过期证书、坏配置/journal、端口占用、并发、SIGKILL、陈旧锁、回滚失败、
  迁移接管/回滚。
- A1/A3 新增真实 root 与真实 Nginx 故障场景。
- **30 分钟 soak 已执行**：`run_soak.sh` 30/30 次（60s 间隔）均满足
  `systemctl is-active xray`、`xray -test` rc=0、`:443` 监听、`NRestarts=0`、
  RSS < 512MiB，`soak.json` verdict=`PASS`（`soak-30m-1/soak/`）。
- 两个调度周期：由 OPS-17c 的 cron/timer 安装与 `schedule status` 断言覆盖；
  未做跨小时的真实触发观察。

## 6. 三轮审计闭环

| 轮次 | 输入 | 动作 | 输出 |
| --- | --- | --- | --- |
| 第 1 轮 | 审计基线 `45666732` | 逐条复现 A1–A5；A1 红测、A3 红绿探针 | 缺陷与证据清单 |
| 第 2 轮 | 修复提交 `df3f3838` | 定向单测、真实 nginx、真实 root、OPS 双端、P3 xhttp | 修复绿证与残余边界 |
| 第 3 轮 | 候选 `df3f3838` | 全量矩阵、OPS sweep、冷恢复、R1/INJ、98 项矩阵、race、门禁 | 本文与 `final-gates.*` |

三轮之间没有删除失败证据：M7 首轮网络 `unexpected EOF`、A3 pre-fix 默认值、
A4 父提交负例通过、M8 Bash 委托 Go 均保留在仓库中。

## 6.1 CI（2026-11-20）

代码候选 `aa4b9da9` 与文档 HEAD `beb51ab9` 推送后，7 个 workflow 均全部
`success`，无失败、无进行中。

### 代码候选 `aa4b9da9`

| Workflow | run id | 结论 |
| --- | --- | --- |
| Go parity stage gate | 44725121966 | success |
| Privacy Guard | 44725121993 | success |
| Rill Xray Agent | 44725121851 | success |
| Go preview qualification (NOT FOR RELEASE) | 44725122135 | success |
| Go real-root change acceptance (container) | 44725121880 | success |
| Test Install | 44725121834 | success |
| Go production parity release qualification | 44725121949 | success |

### 文档 HEAD `beb51ab9`

| Workflow | run id | 结论 |
| --- | --- | --- |
| Go parity stage gate | 44725987921 | success |
| Privacy Guard | 44725987933 | success |
| Rill Xray Agent | 44725987816 | success |
| Go preview qualification (NOT FOR RELEASE) | 44725987872 | success |
| Go real-root change acceptance (container) | 44725987940 | success |
| Test Install | 44725987830 | success |
| Go production parity release qualification | 44725987943 | success |

Test Install 本次通过，但历史“静默退出”的根因未定位，因此 A5 仍记 `PARTIAL`；
不用一次绿色 CI 反推问题已修复。

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

# OPS 新增 6 项 + 既有 5 项全量回归
E2E_RUN_ID=ops-full-3 \
  E2E_ONLY=OPS-04,OPS-05,OPS-06,OPS-07,OPS-17c,OPS-30,OPS-19,OPS-21,OPS-09,OPS-31,OPS-32 \
  bash tests/e2e-diff/run_p2_matrix.sh

# OPS-10（嵌套菜单，预期 NOT-RUN）
E2E_RUN_ID=ops10-2 E2E_ONLY=OPS-10 bash tests/e2e-diff/run_p2_matrix.sh

# 子脚本 S4–S9
E2E_RUN_ID=s-6-1 bash tests/e2e-diff/run_s_scripts.sh

# 30 分钟 soak
E2E_RUN_ID=soak-30m-1 bash tests/e2e-diff/run_soak.sh

# 多版本 Xray（3 个真实 tag）
E2E_RUN_ID=versions-3 bash tests/e2e-diff/run_xray_versions.sh

# 第二发行版 smoke（Debian 12）
E2E_RUN_ID=debian12-1 \
  E2E_IMAGE_TAG=idleleo-e2e:debian12 \
  E2E_IMAGE_DOCKERFILE=tests/e2e-diff/image/Dockerfile.debian12 \
  E2E_ONLY=M1,OPS-19 bash tests/e2e-diff/run_p2_matrix.sh

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
- 本轮新增证据：`tests/e2e-diff/evidence/ops-full-3/p2/`（OPS 全量回归）、
  `opsfix-3/p2/`（OPS-04 修复后 7 项复跑）、`ops04-8/p2/`（单行验证）、
  `ops10-2/p2/`（OPS-10）、`s-6-1/s/`（S4–S9）、`soak-30m-1/soak/`、
  `versions-3/versions/`、`debian12-1/p2/`、`preflight-ops/`。
- 既有审计文档：`AUDIT_ISSUES.md`、`REMEDIATION_PLAN.md`、`PARITY_MATRIX.csv`、
  `TEST_EVIDENCE.md`、`FINAL_AUDIT.md`
