# 验收矩阵 · 2026-11-19

- 分支：`work/go-hardening-parity-20261119`
- 代码 SHA：`04d06cf41988647ba0738ddbc67d9a4589b3dc12`（P3 完成态）
- 基线 SHA：`9b965843dccc955eee8b91903749500f082271f7`（`develop/go-native`）
- 证据用语：`DUAL_SIDE_PASS`、`GO_ONLY_PASS`、`APPROVED_SAFE_DIVERGENCE`、`FAIL`、`NOT_RUN`、`BLOCKED`、`LOCAL_RUN`、`CI_RUN`、`STATIC_ONLY`
- 历史 SHA 的证据必须单独标注；本轮未复跑的项目不得写成当前 PASS。

## 1. 总览

| 项 | 数量 |
| --- | --- |
| 验收项 | 16 |
| 本轮 `LOCAL_RUN` 通过 | 11 |
| 历史 SHA 证据（不计入本轮） | 2 |
| `PARTIAL` | 1 |
| `BLOCKED` | 3 |
| 本轮 `FAIL` | 0 |

## 2. 逐项矩阵

| ID | 验收项 | 状态 | 本轮证据（命令 / SHA / rc） | 边界说明 |
| --- | --- | --- | --- | --- |
| T01 | 备份越界、条目伪造、压缩炸弹、mode 篡改 | `LOCAL_RUN` PASS | `8ac1385f`；`go test ./internal/backup -run 'TestVerifyRejects|TestCreateRefuses|TestCreateRejects'`；rc=0 | ENOSPC 未注入，见 T02/T03 的故障注入范围 |
| T02 | 恢复成功、失败回滚、快照 | `LOCAL_RUN` PASS | `8ac1385f`；`TestRestoreRollsBackWhenServiceApplyFails`、`TestRestoreRefusesWhileJournalIsInterrupted`；rc=0 | 真实 systemd 重启仅在 P3 容器的 `repair` 场景覆盖 |
| T03 | mid-apply SIGKILL、`recover` 收敛 | `LOCAL_RUN` PASS | `8ac1385f`；`TestRestoreHardKillConvergesWithExplicitRecover`（`syscall.Kill` + `WaitStatus.Signaled()`）；rc=0 | 独立 VM 掉电未执行 |
| T04 | 冷恢复/独立机器恢复 | `BLOCKED` | 无可用独立 VM，本轮未执行 | 发布前必须补做 |
| T05 | repair 符号链接越权、dry-run 零写入、共享锁 | `LOCAL_RUN` PASS | `8ac1385f`；`TestRepairRefusesSymlinkedPaths`、`TestRepairDryRunTakesNoLockAndWritesNothing`、`TestRepairRefusesWhileAnotherUpdateHoldsTheLock`；rc=0 | — |
| T06 | 提权与秘密泄漏 | `LOCAL_RUN` PARTIAL | `8ac1385f`；`internal/change` 计划脱敏测试 rc=0；argv 输出无秘密 | 全量人工渗透审计未做，仅覆盖已知路径 |
| T07 | CI fail-closed 负例（未签收、被修改 gate） | `LOCAL_RUN` PASS | `04d06cf4`；`python3 -m unittest discover -s tests -v` → `Ran 10 tests ... OK`；rc=0 | 真实 GitHub Actions 未触发，见 T08 |
| T08 | pending/signed 阶段切换、signed 冒烟 | `LOCAL_RUN` PASS | `04d06cf4`；同 T07 的 10 个测试；`actionlint .github/workflows/go-preview-qualification.yml` rc=0 | 真实 CI 复跑 `NOT_RUN` |
| T09 | M1–M10 双端差分 | `HISTORICAL_RUN` | `6ad3be97` 的 `goevo-p2-rerun-20261119-0345-6ad3be97`；M1–M10 PASS | 非当前 SHA，不计入本轮 PASS |
| T10 | OPS 34 行双端缺口 | `PARTIAL` | `6ad3be97` 历史证据；`matrix.json` 仅 5 行 `DUAL_SIDE_PASS`，29 行 `GO_ONLY_PASS` | 29 行仍无双端证据 |
| T11 | M8 纯 Bash ACME | `BLOCKED` | 镜像无 `acme.sh` 且无外部 ACME 端点；驱动输出 `status=BLOCKED`、rc=3 | `HYBRID_BASH_GO` 有历史证据，不等于纯 Bash |
| T12 | 接管/迁移对等 | `BLOCKED` | 本轮未执行；需独立 VM 与真实旧安装 | 不得用容器结果替代 |
| T13 | doctor 证据分级与真实客户端探针 | `LOCAL_RUN` PASS | `04d06cf4`；`go test ./internal/doctor ./internal/clientprobe` rc=0；P3 驱动 `E13b` rc=0，`evidenceLevel=REAL_CLIENT_PASS` | relay 为 `NOT_RUN`（无后端凭据）；证书链/外部 origin 见 limitations |
| T14 | update preflight readiness | `LOCAL_RUN` PASS | `04d06cf4`；`go test ./internal/componentupdate` rc=0；`not-run` → `compatible=false`、`readiness=unverified` | 真实多版本二进制矩阵未执行 |
| T15 | hot-user 持久化/崩溃/移除回归 | `LOCAL_RUN` PASS | `04d06cf4`；`E2E_RUN_ID=20261119-p3b bash tests/e2e-diff/run_p3_hot.sh`；62/62，driver_rc=0 | 容器内真实 systemd/Xray/nginx/TLS origin |
| T16 | 全量回归 | `LOCAL_RUN` PASS | `04d06cf4`；`gofmt -l cmd internal` rc=0；`go vet ./...` rc=0；`go build ./...` rc=0；`go test -count=1 ./...` rc=0（25 包 ok，0 FAIL） | — |

## 3. 关键证据索引

| 证据 | 路径 |
| --- | --- |
| S0 基线 | `docs/go-evolution/hardening/00-baseline.md` |
| P1 安全/恢复 | `docs/go-evolution/hardening/01-security-recovery.md` |
| P2 CI/双端 | `docs/go-evolution/hardening/02-ci-and-bash-go-parity.md` |
| P3 原生体验 | `docs/go-evolution/hardening/03-native-experience.md` |
| P3 运行记录 | `tests/e2e-diff/evidence/goevo-p3-20261119-p3b/run.json` |
| P3 断言 | `tests/e2e-diff/evidence/goevo-p3-20261119-p3b/container/driver/assertions.txt` |
| P3 客户端探针 | `tests/e2e-diff/evidence/goevo-p3-20261119-p3b/container/driver/E13b-doctor-probe/stdout.txt` |
| P2 双端历史 | `tests/e2e-diff/evidence/goevo-p2-rerun-20261119-0345-6ad3be97/p2/run.json` |

## 4. 不计入 PASS 的项

- 当前 SHA 的真实 GitHub Actions：`NOT_RUN`（未 push，遵守不合并/不发布约束）。
- 当前 SHA 的 M1–M10 与 OPS 双端：`HISTORICAL_RUN`/`PARTIAL`，不能写成 `DUAL_SIDE_PASS`。
- 所有 VM、生产 VPS、真实 ACME：`BLOCKED`。
