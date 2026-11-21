# Docker 双端验收与三轮闭环 · 2026-11-21

> 本文件是本轮 Goal（`artifacts/intake-20261121/Trae_Xray_收尾独立双端验收_Goal_20261121.md`）
> 的最终中文报告。机器可读账本为 `tests/e2e-diff/ledger.json`，验收看板为
> `docs/go-evolution/hardening/acceptance.json`，二者由同一次运行生成。
> 审计输入为 `artifacts/intake-20261121/Xray_独立审计报告_20261121.md`。

## 1. 冻结基线、环境与构建

| 项 | 值 |
| --- | --- |
| 分支 | `work/go-hardening-parity-20261119` |
| 审计 HEAD | `c0f382f2bbc805556b0dd72b4a800af51de2312c` |
| 本轮修复提交 | `96f77eae8849e1f1a73f0d8e6dfaaac922255f03`（账本 `codeSha` 同值） |
| 固定 Bash | v3.3.6 `0fa7052e`；真实历史安装器 v3.3.2（`install-v3.3.2.sh`） |
| Go 工具链 | `golang:1.27.4`，`CGO_ENABLED=0 GOFLAGS=-mod=vendor GOPROXY=off GOTOOLCHAIN=local` |
| 运行镜像 | `idleleo-e2e:24.04`（`688fabaf2d84`）、`idleleo-e2e:debian12`（`f67ddd3cc98d`）、`nginx:1.27`（1.27.5 + openssl）、`golang:1.27.4` |
| Xray 候选 | `xray_sha256=5939649960deaf535bcd5f7ce0467a2b1d63b72a2758a6f42eade714ae8d5328` |
| idleleo 候选 | `7943fa0802466b9d981dfdbbfca1944407c1c5e037bbb40ccbbdda93359f0c9d` |
| 干净树重建 | 用 `git archive 96f77eae` 在独立容器重建，sha256 与全部验收运行一致（`artifacts/intake-20261121/s0/clean-tree-build.txt`） |

环境快照：`artifacts/intake-20261121/s0/environment.json`；
Go 门禁：`artifacts/intake-20261121/s0/gate.log`；
Bash 语法：`artifacts/intake-20261121/s0/bash-syntax.log`。

## 2. 安全缺陷闭环（S1，先红后绿）

### 2.1 P0 证书清理误删

审计 HEAD 的真实 root Nginx 容器红测 7 项失败，修复后 10/10 通过：

| 用例 | HEAD（红） | 修复后（绿） |
| --- | --- | --- |
| inline-multi（一行多指令） | 误删、keep=0 | rc=0，保留 1 |
| external-include（外部目录 / 非 .conf） | 误删 | rc=0，保留 1 |
| symlink-alias（符号链接别名） | 误删 | rc=0，保留 1 |
| variable-path（`$` 变量证书路径） | removed=-1 崩溃 | rc=0，保留并 warn |
| xray-second-config（第二份 Xray 配置） | 误删 | rc=0，保留 1 |
| quoted-inline（引号内联） | 误删 | rc=0，保留 1 |
| broken-config（损坏配置） | 删除后 `nginx -t` 失败 | rc=0 保留并 warn=1 |
| unused-pair（真实未用证书对） | PASS | PASS removed=2，canary 保留 |
| invalid-nginx-refuse（`nginx -t` 失败） | — | refused，未删除 |
| rollback-fault（提交前注入故障） | — | refused，回滚后 after=0 |

红/绿原始日志：`artifacts/intake-20261121/s1/certclear-head-red.log`、
`artifacts/intake-20261121/s1/certclear-fixed-green.log`。
实现：行内非锚定正则、长名优先、`include` 递归（绝对/相对/glob/托管目录外）、
注释剥离、symlink 真实目标、变量路径 fail-closed、清理前 `nginx -t` 平衡、
移动后提交前 `nginx -t` + `xray -test`，失败回滚并置 `RECOVERY_REQUIRED`。
新增 5 个单测（`internal/deploy/certclear_test.go`）。

### 2.2 P1 Guard 状态误报

HEAD 红测 3 项失败（缺 fragment / 仅有 isolate 端口时仍报 `active`），修复后 6/6：

| 用例 | HEAD（红） | 修复后（绿） |
| --- | --- | --- |
| configured-isolate | active | configured |
| missing-fragment | active | inconsistent |
| reject-configured | active | configured |
| missing-main | inconsistent | inconsistent |
| unreadable-main | inconsistent | inconsistent |
| active-running | active | active |

日志：`artifacts/intake-20261121/s1/guard-head-red.log`、
`artifacts/intake-20261121/s1/guard-fixed-green.log`。
实现：主配置不可读即 `inconsistent`；`port==isolate 且无 isolate fragment` 即
`inconsistent`；配置一致但 nginx.pid 进程不存活时降级为 `configured`。

### 2.3 P2 XHTTP 空白输入与账本

- `--xhttp-path` 显式区分“未提供”与“提供空白”：空串、空格、制表符、首尾空白
  一律拒绝，不再静默保留旧值；`internal/xraycfg/edit_test.go` 新增负例。
- 34 行 OPS 账本由 `tests/e2e-diff/collect/build_ledger.py` 从证据生成，
  每行带真实 Bash 菜单入口、Go 命令、契约、层、证据路径与 runId；
  不再手写、不再让三个摘要互相矛盾。

## 3. 双端与全覆盖结果（S2）

所有 `DUAL_SIDE_VERIFIED` 都来自同一次运行的两个独立容器：Bash 真菜单 /
Go CLI，各自真实 Xray、Nginx、systemd。L0 退出码、L1 文件、L2 结构、
L3 运行态、L4 真实业务请求、L6 重复运行逐层比较。

### 3.1 M1–M10 安装矩阵（`FINAL-M-20261121`）

首轮与幂等轮两侧 rc=0，L4 全部 `ok`：

| 场景 | Bash | Go | 判定 |
| --- | --- | --- | --- |
| M1 reality | rc=0 reality:ok×2 | rc=0 reality:ok×2 | DUAL_SIDE_PASS |
| M2 reality+nginx | rc=0 reality:ok×2 | rc=0 reality:ok×2 | DUAL_SIDE_PASS |
| M3 reality+transport | rc=0 reality+ws:ok | rc=0 reality+ws:ok | DUAL_SIDE_PASS |
| M4 tls ws | rc=0 ws:ok×2 | rc=0 ws:ok×2 | DUAL_SIDE_PASS |
| M5 tls grpc | rc=0 grpc:ok×2 | rc=0 grpc:ok×2 | DUAL_SIDE_PASS |
| M6 tls xhttp | rc=0 xhttp:ok×2 | rc=0 xhttp:ok×2 | DUAL_SIDE_PASS |
| M7 tls ws+grpc+xhttp | rc=0 三传输 ok | rc=0 三传输 ok | DUAL_SIDE_PASS |
| M8 tls acme | rc=0 ws:ok×2 | rc=0 ws:ok×2 | DOCKER_EQUIVALENT_WITH_LIMITS（ED-C14：Bash 走 acme.sh，Go 走本地 Pebble） |
| M9 none ws | rc=0 ws:ok×2 | rc=0 ws:ok×2 | DUAL_SIDE_PASS |
| M10 relay stream | rc=0 relay:ok×2 | rc=0 relay:ok×2 | DUAL_SIDE_PASS |

证据：`tests/e2e-diff/evidence/FINAL-M-20261121/p2/install-matrix.md`。
差异全部登记在 `expected_diffs.json` 的 ED-C01…C15（带 owner/批准/到期），
没有未登记差异，也没有把 ED 当作 PASS 使用。

### 3.2 E1–E8 编辑（`FINAL-M-20261121`）

100 项检查全部 `allPassed=true`（E1 13、E2 13、E3 13、E4 13、E5 11、
E6 10、E7 13、E8 14），每条都包含编辑前后配置、分享链接、运行态与
真实客户端 L4 结果。Bash 侧没有等价的非交互编辑入口，E 行为 `GO_ONLY`，
不冒充双端。

### 3.3 OPS 34 行账本

| 状态 | 数量 | ID |
| --- | --- | --- |
| DUAL_SIDE_VERIFIED | 11 | 04/05/06/07/09/10/17c/19/21/31/32 |
| GO_ONLY | 22 | 01/02/03/08/11/12/13/14/15/16/17a/17b/18/20/22/23/24/25/26/27/28/29 |
| BASH_ONLY | 1 | 30 |
| FAIL | 0 | — |
| BLOCKED | 0 | — |
| NOT_RUN | 0 | — |

| ID | 名称 | 状态 | 证据 |
| --- | --- | --- | --- |
| OPS-01 | 查看用户 | GO_ONLY | FINAL-OPS4-20261121/assertions.txt |
| OPS-02 | 添加用户 | GO_ONLY | FINAL-OPS4-20261121/assertions.txt |
| OPS-03 | 删除用户 | GO_ONLY | FINAL-OPS4-20261121/assertions.txt |
| OPS-04 | 变更端口 | DUAL_SIDE_VERIFIED | FINAL-M-20261121/p2/OPS-04/ops.json |
| OPS-05 | 变更UUID/映射 | DUAL_SIDE_VERIFIED | FINAL-M-20261121/p2/OPS-05/ops.json |
| OPS-06 | 变更target | DUAL_SIDE_VERIFIED | FINAL-M-20261121/p2/OPS-06/ops.json |
| OPS-07 | 变更TLS版本 | DUAL_SIDE_VERIFIED | FINAL-M-20261121/p2/OPS-07/ops.json |
| OPS-08 | SNI Guard | GO_ONLY | FINAL-RR-20261121/realroot/assertions.txt |
| OPS-09 | Nginx负载均衡 | DUAL_SIDE_VERIFIED | FINAL-M-20261121/p2/OPS-09/ops.json |
| OPS-10 | serverNames | DUAL_SIDE_VERIFIED | FINAL-M-20261121/p2/OPS-10/ops.json |
| OPS-11 | 查看配置信息 | GO_ONLY | FINAL-OPS4-20261121/assertions.txt |
| OPS-12 | 实时访问日志 | GO_ONLY | FINAL-OPS4-20261121/assertions.txt |
| OPS-13 | 实时错误日志 | GO_ONLY | FINAL-OPS4-20261121/assertions.txt |
| OPS-14 | 端口实时流量 | GO_ONLY | FINAL-OPS4-20261121/assertions.txt |
| OPS-15 | 服务重启/启动/停止/状态 | GO_ONLY | FINAL-OPS4-20261121/assertions.txt |
| OPS-16 | 证书状态/有效期/自动更新 | GO_ONLY | FINAL-OPS4-20261121/assertions.txt |
| OPS-17a | 更新脚本 | GO_ONLY | FINAL-OPS4-20261121/assertions.txt |
| OPS-17b | 更新Nginx | GO_ONLY | FINAL-RR-20261121/realroot/assertions.txt |
| OPS-17c | 配置自动更新 | DUAL_SIDE_VERIFIED | FINAL-M-20261121/p2/OPS-17c/ops.json |
| OPS-18 | TCP加速 | GO_ONLY | FINAL-OPS4-20261121/assertions.txt |
| OPS-19 | Fail2ban | DUAL_SIDE_VERIFIED | FINAL-M-20261121/p2/OPS-19/ops.json |
| OPS-20 | 流量统计 | GO_ONLY | FINAL-OPS4-20261121/assertions.txt |
| OPS-21 | 流量阻断 | DUAL_SIDE_VERIFIED | FINAL-M-20261121/p2/OPS-21/ops.json |
| OPS-22 | 清除日志 | GO_ONLY | FINAL-OPS4-20261121/assertions.txt |
| OPS-23 | 服务器网速 | GO_ONLY | FINAL-OPS4-20261121/assertions.txt |
| OPS-24 | 刷新GeoData | GO_ONLY | FINAL-OPS4-20261121/assertions.txt |
| OPS-25 | 备份管理文件 | GO_ONLY | FINAL-OPS4-20261121/assertions.txt |
| OPS-26 | 恢复管理文件 | GO_ONLY | FINAL-OPS4-20261121/assertions.txt |
| OPS-27 | 清空证书文件 | GO_ONLY | FINAL-RR-20261121/realroot/assertions.txt |
| OPS-28 | 卸载 | GO_ONLY | FINAL-OPS4-20261121/assertions.txt |
| OPS-29 | Rill AI 状态 | GO_ONLY | FINAL-OPS4-20261121/assertions.txt |
| OPS-30 | 修改语言 | BASH_ONLY | FINAL-M-20261121/p2/OPS-30/ops.json |
| OPS-31 | Reality负载均衡 | DUAL_SIDE_VERIFIED | FINAL-M-20261121/p2/OPS-31/ops.json |
| OPS-32 | 后端故障摘除（ws + reality 上游） | DUAL_SIDE_VERIFIED | FINAL-M-20261121/p2/OPS-32/ops.json |

- 双端证据：`FINAL-M-20261121/p2/OPS-*/ops.json`。
- Go 侧真实点检：`FINAL-OPS4-20261121/assertions.txt`（51 项）覆盖
  01/02/03/11/12/13/14/15/16/17a/18/20/22/23/24/25/26/28/29。
- 真实 root：`FINAL-RR-20261121/realroot/assertions.txt`（26 项）覆盖
  OPS-08 六个策略用例、OPS-27 十个证书清理用例、OPS-17b 的
  1.27.5→1.30.6 组件更新（action/previousVersion/newVersion/health、
  激活新二进制、保留备份）。
- OPS-30：语言切换是 Bash 菜单的本地化偏好，Go CLI 无等价命令；Bash 功能
  未被删除，登记为 `BASH_ONLY`，不宣称对等、不属于安全差异，也没有按
  “已批准取消功能”签收。

### 3.4 S4–S9 子脚本

Bash 3.3.6 实际随安装器提供的是 `auto_update.sh`(S4)、`ssl_update.sh`(S5)、
`geo_update.sh`(S6)、`acme.sh`(S7)、`tcp.sh`(S8)、`superspeed.sh`(S9)；
S1–S3 是旧编号，当前版本不再分发，本轮不作为可执行项。

| 行 | 结果 | 证据 |
| --- | --- | --- |
| S4 auto_update | 9/9 PASS（正常、重复、元数据缺失 fail-safe） | `FINAL-S-20261121/s/S4/` |
| S5 ssl_update | 12/12 PASS（本地 Pebble 真实签发/续期/失败保持旧证书） | `FINAL-S-20261121/s/S5/` |
| S6 geo_update | 首轮 7/9（重复运行因外网 11MB 资产超时）；隔离重跑 11/11 PASS | `FINAL-S-20261121/s/S6/`、`FINAL-S6B-20261121/s/` |
| S7 acme.sh | 安装、`--version`、`--help`、缺状态失败 6/6 PASS；真实签发 BLOCKED（无公网域名/CA） | `FINAL-S-20261121/s/S7/` |
| S8 tcp BBR | 13/13 PASS（plan/apply/重复 noop/rollback、无远端下载、旧脚本语法校验） | `FINAL-S-20261121/s/S8/` |
| S9 superspeed | 6/6 PASS（本地端点吞吐、不可达失败干净退出、旧脚本语法校验） | `FINAL-S-20261121/s/S9/` |

S6 首次失败是外网下载超时，不是产品缺陷；`FINAL-S6B-20261121` 是独立
runId 的绿色重跑，报告与账本分开引用，不混算。

### 3.5 迁移、冷恢复、P3、多版本、第二发行版（S3）

| 项 | 结果 | 证据 |
| --- | --- | --- |
| Bash 3.3.6 接管 R1/R2/I1/I4/INJ | 106 PASS / 0 FAIL | `FINAL-R2-20261121/r1/assertions.txt` |
| 真实历史 Bash 3.3.2 接管 | 13 PASS / 0 FAIL（安装→接管→配置字节不变→流量） | `FINAL-HIST2-20261121/r1/assertions.txt` |
| 双容器冷恢复 | source 8/8 + target 19/19；配置逐字节一致、权限/组、`xray -test`、服务、真实客户端、重启后仍通 | `goevo-coldrestore-FINAL-COLD-20261121/` |
| P3 hot-user raw/ws/grpc/xhttp | 4 × 62/62，含旧凭据失效、热更新不重启、并发、SIGKILL 后恢复 | `goevo-p3-FINAL-P3-{raw,ws,grpc,xhttp}-20261121/` |
| 多版本 Xray | v26.11.9 / v26.10.31 / v26.10.21：`xray -test` + 真实部署 + 客户端业务请求 PASS | `FINAL-VERSIONS2-20261121/versions/xray-versions.json` |
| Debian 12 | M1、M4、OPS-09 双端 PASS | `FINAL-DEBIAN12-20261121/p2/` |

### 3.6 Soak 与调度周期

`FINAL-SOAK-20261121`：31 样本 × 60s，实际 1849s（≥1800s），独立客户端
Reality 握手 + HTTP 业务请求 31/31 `ok`、0 失败；RSS 上限 512MiB 内、
`NRestarts=0`、443 监听、`xray -test` rc=0。随后真实
`idleleo-schedule.timer` 以 15s 间隔跑满两个周期（`timer=active`、`runs=2`），
GeoData 非空且校验和匹配，`state.json` 记录 `result=ok`。
结论 `verdict=PASS`：`FINAL-SOAK-20261121/soak/soak.json`。

## 4. 三轮闭环

| 轮次 | 内容 | 结果 |
| --- | --- | --- |
| 第 1 轮 | 审计 HEAD `c0f382f2` 原样红测 | cert clear 7 失败、guard 3 失败，问题复现 |
| 第 2 轮 | 最小修复后真实 root 定向实跑 | cert 10/10、guard 6/6、XHTTP 负例通过 |
| 第 3 轮 | 冻结提交 `96f77eae` 全量验收（矩阵、OPS、S、R、冷恢复、P3、版本、发行版、spec soak） | 见第 3 节；过程中无功能改动 |

## 5. 门禁

| 门禁 | 结果 | 证据 |
| --- | --- | --- |
| gofmt / go vet / go build / go test | rc=0，25 包 ok | `artifacts/intake-20261121/s0/gate.log` |
| go test -race | rc=0 | `artifacts/intake-20261121/s0/race.log` |
| Bash 语法（安装器 + 驱动） | 全部 rc=0 | `artifacts/intake-20261121/s0/bash-syntax.log` |
| 证据隐私 | 0 findings（38545 文件） | `check_evidence_hygiene.py --mask artifacts/intake-20261121 tests/e2e-diff/evidence tests/go-parity/evidence/matrix-20261121` |
| 98 项配置矩阵 | 104 行：54 MATCH + 40 MATCH_CORE_FIELDS + 4 REFUSED + 6 A1_PASS，0 GAP，`repo_dirty=0` | `tests/go-parity/evidence/matrix-20261121/summary.json` |
| 干净树二进制 | `git archive` 重建 sha256 与全部验收运行一致 | `artifacts/intake-20261121/s0/clean-tree-build.txt` |
| 真实 CI | 7/7 success @ `96f77eae`：stage gate `44798164756`、preview `44798164664`、release qualification `44798164791`、real-root `44798164759`、Test Install `44798164733`、Privacy Guard `44798164734`、Rill Xray Agent `44798164622`；最终文档 head `d399e6bd` 同样 7/7 success（stage `44860271297`、preview `44860271369`、release `44860271325`、real-root `44860271300`、Test Install `44860271291`、Privacy `44860271356`、Rill `44860271269`） | GitHub Actions（PR #182，draft） |

过程中被后续运行取代的中间记录（如 `FINAL-OPS`/`FINAL-OPS2`/`FINAL-OPS3`、
`FINAL-R`、`FINAL-HIST` 与首次 S6）原样保留在证据目录，但**不计入账本**；
账本只引用最终绿色运行，失败原因已在第 3、4 节写明。

证据卫生：本轮发现 Bash 菜单转录与 `nginx -T` 回显了采集机公网地址，
已在采集端新增 `tests/e2e-diff/collect/sanitize_evidence.py`（公网 IPv4/IPv6
改写为文档网段、宿主目录名改写为 `<workspace>`），并对本轮证据完成脱敏；
未改历史日志的结论或状态。

## 6. 未闭合与边界

| 项 | 状态 | 原因 |
| --- | --- | --- |
| 独立 VM 冷恢复/掉电/内核 BBR | VPS_DEFERRED | 任务书禁止生产 VPS；容器已覆盖等价流程 |
| 公网 ACME / DNS-01 / EAB | BLOCKED | 无公网域名与 CA；Go 与 S5 已用本地 Pebble 真签发 |
| S7 acme.sh 真实签发 | BLOCKED | 同上；安装、帮助与失败路径已验 |
| 外部公网 IPv6 / NAT | VPS_DEFERRED | 隔离容器无外部 IPv6 路径 |
| M8 Bash 侧 | DOCKER_EQUIVALENT_WITH_LIMITS | Bash 无本地 CA 注入入口（ED-C14） |
| Test Install 历史静默退出 | PARTIAL | 本轮未复现；不以本地结果替代 CI |
| OPS-30 语言 | BASH_ONLY | Go 无等价命令，Bash 功能未删除 |
| 22 行 OPS 仅 Go 侧 | GO_ONLY | Bash 菜单无对应非交互入口；逐行登记，不造映射 |

## 7. 结论

| 范围 | 结论 |
| --- | --- |
| Docker 开发候选 | `GO_FOR_DOCKER_QUALIFIED_CANDIDATE`：Docker 可验证的适用项全部通过，账本 0 FAIL / 0 BLOCKED / 0 NOT_RUN，P0/P1 已用真实双端运行闭合 |
| 正式发布 / 合并 / tag | `NO_GO_NOT_AUTHORIZED`：任务书禁止；独立 VPS、公网 ACME、外部 IPv6 未验证 |

保持 Go 唯一管理核心；本轮只修安全缺陷与测试/证据工具，没有新增产品
功能、没有架构重构、没有恢复 XTLS ONLY、没有触碰生产 VPS。
