# 执行轨迹 · 2026-11-19

分支：`work/go-hardening-parity-20261119`（从 `develop/go-native` @ `9b965843` 创建）

## 阶段状态

| 阶段 | 任务 | 状态 | 提交 | 关键证据 |
| --- | --- | --- | --- | --- |
| S0 | 清理、分支、SHA/工具链、基线门禁 | 完成 | `59adbce4` | `00-baseline.md`；gofmt/vet/test/build rc=0 |
| P1-01 | `backup.Verify` 严格清单/边界；`Create` 原子写入 | 完成 | `8ac1385f` | `internal/backup/hardening_test.go` |
| P1-02 | `Restore` 锁 + journal + `recover` + SIGKILL | 完成 | `8ac1385f` | `TestRestoreHardKillConvergesWithExplicitRecover` |
| P1-03 | `repair` 符号链接边界、dry-run 零写入、共享锁 | 完成 | `8ac1385f` | `internal/repair/hardening_test.go` |
| P1-04 | 变更计划/argv 脱敏复测 | 完成（既有覆盖） | — | `internal/host/exec_test.go`、`internal/host/gate_test.go` rc=0 |
| P2-01 | 三条 CI 红灯根因修复 | 完成 | `4c986c26` | `Ran 10 tests ... OK`、`73 passed, 0 failed`、actionlint rc=0 |
| P2-02 | pending/signed 阶段 fail-closed | 完成 | `4c986c26` | `check_signed_stage.py`；`test_signed_ledger_*` |
| P2-03 | OPS 双端缺口与 M8 纯 Bash | 完成（诚实分级） | `4c986c26` | `matrix.json`：5 dual / 29 go-only；M8 `BLOCKED` |
| P3-01 | doctor 三层证据 + 真实客户端探针 | 完成 | `04d06cf4` | `internal/clientprobe`；P3 `E13b` rc=0，`REAL_CLIENT_PASS` |
| P3-02 | update preflight readiness | 完成 | `04d06cf4` | `readiness=unverified` 测试；`go test ./internal/componentupdate` rc=0 |
| P3-03 | hot-user 回归 | 完成 | `04d06cf4` | `20261119-p3b`：62/62，driver_rc=0 |
| P3-04 | 独立 VM / 生产边界 | `BLOCKED` | — | 无可用 VM，未伪造 |
| 报告 | 7 份审计交付物 | 完成 | 待提交 | `docs/go-evolution/hardening/` |

## 真实执行记录

| 日期 | 命令 | 结果 |
| --- | --- | --- |
| 2026-11-19 | `go test -count=1 ./...`（`golang:1.27.4`，SHA `04d06cf4`） | rc=0，25 包 ok，0 FAIL |
| 2026-11-19 | `gofmt -l cmd internal` / `go vet ./...` / `go build ./...` | 全部 rc=0 |
| 2026-11-19 | `python3 -m unittest discover -s tests -v`（`tests/go-parity/parity`） | `Ran 10 tests ... OK` |
| 2026-11-19 | `python3 .github/test/test_color_output.py` | `73 passed, 0 failed` |
| 2026-11-19 | `E2E_RUN_ID=20261119-p3b bash tests/e2e-diff/run_p3_hot.sh` | `RESULT: PASS`，62/62，driver_rc=0 |
| 2026-11-19 | `actionlint .github/workflows/go-preview-qualification.yml` | rc=0 |
| 2026-11-19 | `bash -n tests/e2e-diff/drivers/*.sh`（改动文件） | rc=0 |

## 未执行项

| 项 | 状态 | 原因 |
| --- | --- | --- |
| 真实 GitHub Actions 复跑 | `NOT_RUN` | 未 push；遵守不合并/不发布约束 |
| 独立 VM 冷恢复/掉电 | `BLOCKED` | 无 VM |
| 纯 Bash ACME（M8） | `BLOCKED` | 镜像无 `acme.sh`，无外部 ACME 端点 |
| 接管/迁移对等 | `BLOCKED` | 需真实旧安装与独立 VM |
| 生产 VPS | `BLOCKED` | 任务书禁止 |
| 真实多版本 Xray 候选矩阵 | `NOT_RUN` | 无多个真实候选二进制 |

## 边界声明

- 本轮没有合并 `main`、没有 tag/release、没有操作生产 VPS、没有 push。
- 容器内真实 systemd/Xray/nginx/TLS origin 的结果标记为 `LOCAL_RUN`，不是 `CI_RUN` 或生产验证。
- 历史 SHA `6ad3be97` 的 M1–M10/OPS 证据单独标注，不复用为当前 SHA 的通过。
