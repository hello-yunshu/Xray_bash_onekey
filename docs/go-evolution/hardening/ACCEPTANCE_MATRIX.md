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
