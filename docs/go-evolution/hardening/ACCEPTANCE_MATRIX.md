# 验收矩阵 · 2026-11-19

- 分支：`work/go-hardening-parity-20261119`
- 代码 SHA：`4ab08050`（含 P1 冷恢复与 `--include-geodata` 修复；P3 探针代码为 `911f91d2`）
- 真实 CI SHA：`4f12543e`（仅文档/证据差异；PR #182）
- 基线 SHA：`9b965843dccc955eee8b91903749500f082271f7`（`develop/go-native`）
- 证据用语：`DUAL_SIDE_PASS`、`GO_ONLY_PASS`、`APPROVED_SAFE_DIVERGENCE`、`FAIL`、`NOT_RUN`、`BLOCKED`、`LOCAL_RUN`、`CI_RUN`、`STATIC_ONLY`
- 历史 SHA 的证据必须单独标注；本轮未复跑的项目不得写成当前 PASS。

## 1. 总览

| 项 | 数量 |
|---|---|
| 验收项 | 16 |
| 本轮 `LOCAL_RUN` / `DUAL_SIDE_PASS` 通过 | 12 |
| 本轮 `LOCAL_RUN` `PARTIAL` | 3（T06、T10、T12） |
| `BLOCKED` | 1（T11） |
| 历史 SHA 证据（不计入本轮 PASS） | 0 |
| 本轮 `FAIL` | 0 |

## 2. 逐项矩阵

| ID | 验收项 | 状态 | 本轮证据（命令 / SHA / rc） | 边界说明 |
| --- | --- | --- | --- | --- |
| T01 | 备份越界、条目伪造、压缩炸弹、mode 篡改 | `LOCAL_RUN` PASS | `43ceb680`、`4c9705a9`；`go test ./internal/backup` rc=0；含 `TestVerifyRejects*`、`TestCreateRefuses*`、`TestCreateSkipsAbsentGeodataTree`、`TestCreateStillRefusesSymlinkedGeodataParent`、`TestRestoreRejectsTraversalWithoutTouchingCanary` | 真实磁盘 ENOSPC 由 T03 的注入覆盖 |
| T02 | 恢复成功、失败回滚、快照 | `LOCAL_RUN` PASS | `43ceb680`；`TestRestoreRollsBackWhenServiceApplyFails`、`TestRestoreRefusesWhileJournalIsInterrupted`、`TestRestoreLeavesThirdPartyFilesAlone`；rc=0 | 真实 systemd 重启由 P3 `repair` 场景覆盖 |
| T03 | mid-apply SIGKILL、`recover` 收敛 | `LOCAL_RUN` PASS | `43ceb680`；`TestRestoreHardKillAtEveryDurablePointConverges`（6 个持久点真实 `syscall.Kill` + `WaitStatus.Signaled()`）、`TestRestoreRollsBackOnFilesystemErrors`（ENOSPC/EROFS/EACCES）；rc=0 | 独立 VM 掉电未执行（P3-04） |
| T04 | 冷恢复/独立机器恢复 | `LOCAL_RUN` PASS | `4ab08050`；`E2E_RUN_ID=20261119-cold4 bash tests/e2e-diff/run_coldrestore.sh`：源容器 A 销毁后，全新目标容器 B 恢复，source 8/8、target 19/19、双侧 rc=0；配置逐字节一致、`xray -test` rc=0、服务 active、真实客户端通过 | 两个独立 systemd 容器；独立 VM 仍属 P3-04 `BLOCKED` |
| T05 | repair 符号链接越权、dry-run 零写入、共享锁 | `LOCAL_RUN` PASS | `8ac1385f`；`TestRepairRefusesSymlinkedPaths`、`TestRepairDryRunTakesNoLockAndWritesNothing`、`TestRepairRefusesWhileAnotherUpdateHoldsTheLock`；rc=0 | — |
| T06 | 提权与秘密泄漏 | `LOCAL_RUN` PARTIAL | `43ceb680`；`internal/change` 计划脱敏测试 rc=0；argv 输出无秘密；`TestRestoreRefusesWhileAnotherProcessHoldsLock` 证明更新互斥 | 全量人工渗透审计未做，仅覆盖已知路径 |
| T07 | CI fail-closed 负例（未签收、被修改 gate） | `CI_RUN` PASS | `04d06cf4`；`python3 -m unittest discover -s tests -v` → `Ran 10 tests ... OK`；PR #182 stage gate `44527239779` success | 负例与真实 gate 同 SHA |
| T08 | pending/signed 阶段切换、signed 冒烟 | `CI_RUN` PASS | `04d06cf4`；同 T07 的 10 个测试；PR #182 六条工作流 @ `4f12543e` 全部 success（preview `44527239752`、release `44527239918`、real-root `44527240183`、Test Install `44527240075`、Privacy `44527239956`） | draft PR，未合并 |
| T09 | M1–M10 双端差分 | `DUAL_SIDE_PASS` | `a56a448d`；`E2E_RUN_ID=20261119-p2full`：M1–M10 两侧 `rc=0`、round1/round2 数据面 `reality/ws/grpc/xhttp/relay:ok`、L6 `ok`；`install-matrix.md` | 容器内真实 systemd/Xray/nginx |
| T10 | OPS 34 行双端缺口 | `PARTIAL` | `a56a448d`：OPS-09/19/31/32 `PASS`；`1b519028`：OPS-21 `PASS` | 本轮实跑 5 行，其余 29 行仍 `GO_ONLY_PASS`/`NOT-RUN` |
| T11 | M8 纯 Bash ACME | `BLOCKED` | 镜像无 `acme.sh` 且无外部 ACME 端点；驱动输出 `status=BLOCKED`、rc=3 | `HYBRID_BASH_GO` 有历史证据，不等于纯 Bash |
| T12 | 接管/迁移对等 | `LOCAL_RUN` PARTIAL | `a56a448d`：`run_r1_upgrade.sh` R1/R2 85 PASS / 1 INJ FAIL（Nginx 下载 partial file）；`43ceb680`：`E2E_RUN_ID=20261119-inj E2E_PATHS=inj E2E_ONLY=M4` 26/26 PASS | 仍是容器内旧安装，不是独立 VM（P3-04） |
| T13 | doctor 证据分级与真实客户端探针 | `LOCAL_RUN` PASS | `911f91d2`/`de43a36b`；raw/ws/grpc/xhttp 四条 P3 各 62/62、`E13b` rc=0；`20261119-m10relay2` relay `relay-probe=ok`、rc=0、`REAL_CLIENT_PASS` | relay 证明转发而非 VLESS；证书链/外部 origin 见 limitations |
| T14 | update preflight readiness | `LOCAL_RUN` PASS | `04d06cf4`；`go test ./internal/componentupdate` rc=0；`not-run` → `compatible=false`、`readiness=unverified` | 真实多版本二进制矩阵未执行 |
| T15 | hot-user 持久化/崩溃/移除回归 | `LOCAL_RUN` PASS | `de43a36b`；`E2E_RUN_ID=20261119-p3raw2` 及 ws/grpc/xhttp 变体各 62/62，driver_rc=0 | 容器内真实 systemd/Xray/nginx/TLS origin |
| T16 | 全量回归 | `LOCAL_RUN` PASS | `4ab08050`；`gofmt -l cmd internal tests` 无输出；`go vet ./...` rc=0；`go build ./...` rc=0；`go test -count=1 ./...` rc=0（25 个包 `ok`，0 FAIL） | 同一 SHA 上真实 CI 六项 success |

## 3. 关键证据索引

| 证据 | 路径 |
|---|---|
| 机器可读看板 | `docs/go-evolution/hardening/acceptance.json` |
| S0 基线 | `docs/go-evolution/hardening/00-baseline.md` |
| P1 安全/恢复 | `docs/go-evolution/hardening/01-security-recovery.md` |
| P2 CI/双端 | `docs/go-evolution/hardening/02-ci-and-bash-go-parity.md` |
| P3 原生体验 | `docs/go-evolution/hardening/03-native-experience.md` |
| P2 全量矩阵 | `tests/e2e-diff/evidence/20261119-p2full/p2/install-matrix.md` |
| P2 OPS-21 复跑 | `tests/e2e-diff/evidence/20261119-ops21/p2/OPS-21/` |
| relay 真实探针 | `tests/e2e-diff/evidence/20261119-m10relay2/p2/M10/go/doctor-relay.json` |
| 双容器冷恢复 | `tests/e2e-diff/evidence/goevo-coldrestore-20261119-cold4/run.json`、`summary.md` |
| P3 raw 运行记录 | `tests/e2e-diff/evidence/goevo-p3-20261119-p3raw2/run.json` |
| P3 ws/grpc/xhttp | `tests/e2e-diff/evidence/goevo-p3-20261119-p3{ws2,grpc2,xhttp2}/run.json` |
| P3 客户端探针 | `tests/e2e-diff/evidence/goevo-p3-20261119-p3raw2/container/driver/E13b-doctor-probe/stdout.txt` |
| 接管/迁移 | `tests/e2e-diff/evidence/20261119-r1/r1/assertions.txt`、`.../20261119-inj/r1/assertions.txt` |

## 4. 不计入 PASS 的项

- OPS 34 行中的 29 行：`GO_ONLY_PASS`/`NOT_RUN`，不能写成 `DUAL_SIDE_PASS`。
- 所有独立 VM、生产 VPS、真实 ACME：`BLOCKED`。
- 本矩阵中的 relay `REAL_CLIENT_PASS` 证明的是 Nginx Stream 转发，不得表述为 VLESS 用户会话。

## 5. 2026-11-20 复审项

| ID | 项 | 状态 | 证据 | 边界 |
|---|---|---|---|---|
| F01 | F28 Reality 分享跨 root 污染 | `LOCAL_RUN` PASS | pre-fix 35/2 → post-fix 57/0；`artifacts/audit-remediation/followup-20261120/c3/f28/` | 容器内 fixture，非真实 VPS |
| F02 | Reality Host 与 SNI 分离 | `LOCAL_RUN` PASS | `share_metadata_test.go` 10 例；F08 129/0、F18 178/0 | 要求调用方提供 `--host` 属预期行为变更 |
| F03 | `environment.txt` 宿主路径 | `LOCAL_RUN` PASS | 生成器剥离路径；`test_environment_contract.py` 2 tests OK | CI 需在新提交上复跑 |
| F04 | F28 临时私钥泄漏 | `LOCAL_RUN` PASS | `commands.log` 仅 `<redacted>`；fixture root 移出 evidence | 历史工件未逐个重写，仅本次新增证据 |
| F05 | Go 全量门禁 | `LOCAL_RUN` PASS | `.../c3/gate.rc`（gofmt/vet/build/test 均 `rc=0`） | — |
| F06 | 98 项矩阵 | `LOCAL_RUN` PASS | 104 行 0 GAP、`repo_dirty=0`；`tests/go-parity/evidence/matrix-fix-20261120-clean2/` | 容器内，无真实部署 |
| F07 | P2 编辑与 OPS | `LOCAL_RUN` PASS | E1-E6 全绿；E7 13/13、E8 14/14；OPS-32 ws/reality PASS；`.../fix-20261120-p2j`、`.../fix-20261120-p2h`、`.../fix-20261120-p2i` | 容器内 systemd/Xray/Nginx |
| F08 | 真实 CI | `CI_PASS` | `5f382902` 上 6 条 workflow 全 success：stage 44671935449、privacy 44671935247、release 44671935222、preview 44671935256、real-root 44671935218、test-install 44671935238 | 不能用本地结果替代 |
| F09 | `config edit --host`（FUP-08） | `LOCAL_RUN` PASS | `reality_edit_test.go` 3 例；E7/E8 双侧 `--host 127.0.0.1` 全绿 | `--host` 只影响链接渲染，不写配置字段 |
| F10 | OPS-32 恢复判定（FUP-09） | `LOCAL_RUN` PASS | 尾部 `2*fail_timeout` 规则；p2i ws/reality PASS；p2d 重算 PASS | 判定口径修正，探测数据未改 |
| F11 | OPS-19/31/32 离线包缓存（FUP-10） | `LOCAL_RUN` PASS | Nginx 包 + 模板缓存命中，0 下载错误；`.../fix-20261120-cache2/p2/`；阻断 GitHub/raw 后 OPS-32 ws/reality 仍 PASS：`.../fix-20261120-cache4/p2/` | 只覆盖 Nginx 与配置模板，apt/统计脚本可选下载不在判定链 |
| F12 | OPS-19 apt 离线缓存（FUP-11） | `LOCAL_RUN` PASS | 75 个 .deb 闭包；`Get:` / `apt-get update` 0 条；阻断 `ports.ubuntu.com` 等归档主机后仍 PASS：`.../fix-20261120-apt2/p2/` | 仅 apt；`xray_stats` 可选在线更新未缓存 |

**结论**：复审项全部为容器内验证；F09/F10 在 `1cd248e6` 上复验，F08 在
`5f382902` 上 6 条 CI 全绿。发布/合并判断仍 **NO-GO**（独立 VM、公网 ACME、
IPv6、多版本矩阵未验证）。

## 6. 第三轮 Docker 候选（2026-11-20，`df3f3838`）

> 本节证据独立于 §1–§5 的历史 SHA；未在候选 SHA 复跑的项不提升为 PASS。
> 完整报告：`docs/go-migration/audit-remediation/DOCKER_ACCEPTANCE_20261120.md`。

| ID | 验收项 | 状态 | 候选证据 | 边界 |
| --- | --- | --- | --- | --- |
| G01 | A1 证书清理所有权/引用/事务 | `LOCAL_RUN` PASS | `a1-red-baseline.log`、`a1-acme-realroot-final.log`、`certclear_test.go` | Bash 旧行为为安全差异 |
| G02 | A2 分享 Host/SNI/归属 | `PASS_IMPACT_SCOPED` | `share_metadata_test.go`；F28 57/0 等 | 候选未重跑 F28 |
| G03 | A3 Guard 状态推导与回滚 | `LOCAL_RUN` PASS | `a3-guard-redgreen.log`、`smoke-guard-cert-final.log` | Bash 交互 `NOT_RUN` |
| G04 | A4 XHTTP 路径 | `NO_DEFECT_SEMANTIC_DIFF` | `a4-prefix-probe.log`、`a4-xhttp-path.log` | 不做全量重写 |
| G05 | M1–M10 双端 fresh/幂等/L4/L6 | `DUAL_SIDE_PASS` | `round3-final-20261120-1821-df3f3838/p2/` | M8 为 `DOCKER_EQUIVALENT_WITH_LIMITS` |
| G06 | E1–E8 编辑 | `GO_ONLY_PASS` | 同上 E1–E8，67 项检查 | Bash 无非交互等价入口 |
| G07 | OPS 双端 5 行 + Go sweep 36/0 | `PARTIAL` | `round3-final…/p2/`、`round3-ops-20261120-1818/` | 34 行未全部双端，不满足 B4 |
| G08 | 冷恢复 + R1/R2/INJ + P3 | `DUAL_SIDE_PASS`/`LOCAL_RUN` PASS | cold 27/27、R1 106/0、P3 62/62 | 容器内，非独立 VM |
| G09 | 98 项矩阵 + race + 门禁 | `LOCAL_RUN` PASS | 54/40/0/4/6；8 包 race rc=0；gate rc=0 | 配置矩阵非真实部署 |
| G10 | Test Install 静默退出 | `CI_PASS`（根因未定位） | `aa4b9da9` run 44725121834 success | 本次未复现；不声称已修复 |

**候选结论**：`NO_GO_FOR_DOCKER_QUALIFIED_CANDIDATE`。阻断项是 B4 的 34 OPS 与
9 subscripts、C3 多版本/第二发行版、C4 soak；不是 A1–A5 的安全整改。

## 7. 2026-11-21 独立双端验收（产品代码 `96f77eae`）

| ID | 项 | 状态 | 证据 | 边界 |
| --- | --- | --- | --- | --- |
| H01 | P0 证书清理误删 | `FIXED_VERIFIED` | HEAD 7 红 → 10/10，真实 root | `artifacts/intake-20261121/s1/` |
| H02 | P1 Guard 状态误报 | `FIXED_VERIFIED` | HEAD 3 红 → 6/6 | 同上 |
| H03 | P2 XHTTP 空白输入 | `FIXED_VERIFIED` | 空白负例 + 单测 | `internal/xraycfg/edit_test.go` |
| H04 | 账本一致性 | `FIXED_VERIFIED` | 34 行自动生成，0 FAIL/NOT_RUN | `tests/e2e-diff/ledger.json` |
| H05 | M1–M10 | 10/10 `DUAL_SIDE_PASS` | fresh+幂等+L4+L6 | M8 为等价含限制 |
| H06 | E1–E8 | 100/100 `allPassed` | Go-only | Bash 无非交互入口 |
| H07 | OPS 34 | 13 双端 + 20 Go-only + 1 Bash-only | 真实菜单/CLI/root | 逐行登记，不造映射 |
| H08 | S4–S9 | 9/12/17/6/13/6 PASS | 真实子脚本 | S7 签发 BLOCKED |
| H09 | R1/R2/I/INJ + 历史 | 106/0 + 13/0（3.3.2）+ 52/0（3.3.3） | 容器 systemd | 非独立 VM |
| H10 | 冷恢复 + P3 | 27/27 + 4×62/62 | 销毁源容器/热更新 | 非独立 VM |
| H11 | 多版本 + Debian 12 | 3 版本 + M1/M4/OPS-09 PASS | 真实二进制/第二发行版 | — |
| H12 | Soak + 调度 | 31/31、1849s、两周期 | 真实客户端+l4 | — |
| H13 | 98 项矩阵 | 104 行 0 GAP | `repo_dirty=0` | 配置矩阵非真实部署 |
| H14 | 真实 CI | 7/7 success | PR #182 @ `96f77eae`、`c3d4f904` | draft，不发布 |
| H15 | OPS-04/10 强度 | PASS | 新端口 L4/share/幂等/越界拒绝；`nginx -t` 与片段字节比较 | `FINAL-M2-20261121/p2/` |
| H16 | F28/F08/F18 最终 SHA | 57/0、129/0、178/0 | 干净 worktree + 真实 xray | `artifacts/intake-20261121/s1/features-final/` |
| H17 | amd64 + 环境证据 | PASS | amd64 构建/测试；OS/systemd/bash/xray sha256 | `artifacts/intake-20261121/s0/` |
| H18 | Bash 用户菜单双端 | OPS-01/02 `DUAL_SIDE_PASS`；OPS-03 `DIFF` | 真实 `2>1>1/2/3` 菜单与 Go `user list/add/remove` 各自独立容器 | OPS-03 删除后 shortId Bash 清理、Go 保留 |

**未闭合（NOT_DONE）**：冷恢复仅 Reality（缺 TLS/relay/multi 与端到端故障
注入）；Bash 私钥重建菜单未驱动；OPS-03 shortId 未收敛；
XHTTP 尾/重复斜杠数据面未在最终 SHA 重跑。

**候选结论**：`NO_GO_FOR_DOCKER_QUALIFIED_CANDIDATE`。Docker 可验证的适用项
全部通过，但上述 `NOT_DONE` 类别仍未完成；独立 VPS、公网 ACME/DNS-01、
外部 IPv6 仍为 `VPS_DEFERRED`/`BLOCKED`，正式发布与合并保持
`NO_GO_NOT_AUTHORIZED`。
