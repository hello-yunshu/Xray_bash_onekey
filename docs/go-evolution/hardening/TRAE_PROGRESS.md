# 执行轨迹 · 2026-11-19

分支：`work/go-hardening-parity-20261119`（从 `develop/go-native` @ `9b965843` 创建）

## 阶段状态

| 阶段 | 任务 | 状态 | 提交 | 关键证据 |
| --- | --- | --- | --- | --- |
| S0 | 清理、分支、SHA/工具链、基线门禁 | 完成 | `59adbce4` | `00-baseline.md`；gofmt/vet/test/build rc=0 |
| P1-01 | `backup.Verify` 严格清单/边界；`Create` 原子写入 | 完成 | `8ac1385f`、`43ceb680` | `internal/backup/hardening_test.go`；canary/第三方文件/坏 journal |
| P1-02 | `Restore` 锁 + journal + `recover` + SIGKILL | 完成 | `8ac1385f`、`43ceb680` | 六个持久点真实 SIGKILL；ENOSPC/EROFS/EACCES |
| T04 | 双容器冷恢复、可选 GeoData 缺失修复 | 完成 | `4c9705a9`、`4ab08050` | `20261119-cold4`：source 8/8、target 19/19、真实客户端 |
| P1-03 | `repair` 符号链接边界、dry-run 零写入、共享锁 | 完成 | `8ac1385f` | `internal/repair/hardening_test.go` |
| P1-04 | 变更计划/argv 脱敏复测 | 完成（既有覆盖） | — | `internal/host/exec_test.go`、`internal/host/gate_test.go` rc=0 |
| P2-01 | 三条 CI 红灯根因修复 | 完成 | `4c986c26` | `Ran 10 tests ... OK`、`73 passed, 0 failed`、actionlint rc=0 |
| P2-02 | pending/signed 阶段 fail-closed | 完成 | `4c986c26` | `check_signed_stage.py`；`test_signed_ledger_*` |
| P2-03 | OPS 双端缺口与 M8 纯 Bash | 完成（诚实分级） | `1b519028` | 5 行 OPS 实跑 PASS；29 行仍 go-only；M8 `BLOCKED` |
| P3-01 | doctor 三层证据 + 真实客户端探针 | 完成 | `04d06cf4`、`911f91d2` | 四条传输 + relay 均 `REAL_CLIENT_PASS` |
| P3-02 | update preflight readiness | 完成 | `04d06cf4` | `readiness=unverified` 测试；`go test ./internal/componentupdate` rc=0 |
| P3-03 | hot-user 回归 | 完成 | `de43a36b` | raw/ws/grpc/xhttp 各 62/62，driver_rc=0 |
| P3-04 | 独立 VM / 生产边界 | `BLOCKED` | — | 无可用 VM，未伪造 |
| 报告 | 7 份审计交付物 | 完成 | 待提交 | `docs/go-evolution/hardening/` |

## 真实执行记录

| 日期 | 命令 | 结果 |
|---|---|---|
| 2026-11-19 | `go test -count=1 ./...`（`golang:1.27.4`，SHA `4ab08050`） | rc=0，25 个包 `ok`，0 FAIL |
| 2026-11-19 | `E2E_RUN_ID=20261119-cold4 bash tests/e2e-diff/run_coldrestore.sh` | source 8/8、target 19/19，双侧 rc=0 |
| 2026-11-19 | PR #182 @ `4f12543e`：stage / preview / release / realroot / Test Install / Privacy | 六条工作流全部 success（run id 见 `02` §2.4） |
| 2026-11-19 | PR #182 @ `4ab08050` 首轮 | stage/Privacy 因文档 `::` 被 IPv6 卫生规则命中；修文档后复跑通过 |
| 2026-11-19 | `gofmt -l cmd internal tests` / `go vet ./...` / `go build ./...` | 全部 rc=0 |
| 2026-11-19 | `python3 -m unittest discover -s tests -v`（`tests/go-parity/parity`） | `Ran 10 tests ... OK` |
| 2026-11-19 | `python3 .github/test/test_color_output.py` | `73 passed, 0 failed` |
| 2026-11-19 | `E2E_RUN_ID=20261119-p2full E2E_CONCURRENCY=4 bash tests/e2e-diff/run_p2_matrix.sh` | M1–M10 双端 rc=0；E1–E8 allPassed；OPS 4/5 PASS，OPS-21 bash 环境失败 |
| 2026-11-19 | `E2E_RUN_ID=20261119-ops21 E2E_ONLY=OPS-21 ...` | `[OPS-21] verdict=PASS`（`1b519028`） |
| 2026-11-19 | `E2E_RUN_ID=20261119-m10relay2 E2E_ONLY=M10 ...` | doctor relay rc=0，`REAL_CLIENT_PASS`（`911f91d2`） |
| 2026-11-19 | `E2E_RUN_ID=20261119-r1 E2E_PATHS=both ...` | 85 PASS / 1 INJ 外网超时（`a56a448d`） |
| 2026-11-19 | `E2E_RUN_ID=20261119-inj E2E_PATHS=inj E2E_ONLY=M4 ...` | 26 PASS / 0 FAIL（`43ceb680`） |
| 2026-11-19 | `run_p3_hot.sh`（raw/ws/grpc/xhttp，SHA `de43a36b`） | 各 62/62，driver_rc=0 |
| 2026-11-19 | `actionlint .github/workflows/go-preview-qualification.yml` | rc=0 |
| 2026-11-19 | `bash -n tests/e2e-diff/drivers/*.sh tests/e2e-diff/run_*.sh` | rc=0 |

## 未执行项

| 项 | 状态 | 原因 |
|---|---|---|
| 真实 GitHub Actions 复跑 | `CI_RUN` PASS | PR #182（draft，base `develop/go-native`）@ `4f12543e`：六条工作流 success |
| 独立 VM 冷恢复/掉电 | `BLOCKED` | 无 VM |
| 纯 Bash ACME（M8） | `BLOCKED` | 镜像无 `acme.sh`，无外部 ACME 端点 |
| 接管/迁移独立 VM | `PARTIAL` | 容器 R1/R2/INJ 已跑；独立 VM 未做 |
| 生产 VPS | `BLOCKED` | 任务书禁止 |
| 真实多版本 Xray 候选矩阵 | `NOT_RUN` | 无多个真实候选二进制 |
| OPS 其余 29 行 | `GO_ONLY_PASS` / `NOT_RUN` | 本轮只实跑 5 行 |

## 边界声明

- 本轮没有合并 `main`、没有 tag/release、没有操作生产 VPS。
- 工作分支已 push 并创建 draft PR #182（base `develop/go-native`），只用于真实 CI；未合并。
- 容器内真实 systemd/Xray/nginx/TLS origin 的结果标记为 `LOCAL_RUN`，不是 `CI_RUN` 或生产验证。
- 历史 SHA `6ad3be97` 的 M1–M10/OPS 证据不再作为本轮依据；本轮已用 `a56a448d`/`911f91d2` 复跑。
- relay 的 `REAL_CLIENT_PASS` 只证明 Nginx Stream 转发，不是 VLESS 会话。

## 2026-11-20 第三轮 Docker 验收（候选 `df3f3838`）

| 项 | 结果 | 证据 |
| --- | --- | --- |
| A1 证书清理 | PASS（真实 root，红绿） | `artifacts/go-docker-20261120/a1-*.log` |
| A2 分享 Host/SNI | PASS_IMPACT_SCOPED（候选未重跑） | `share_metadata_test.go`；F28 57/0 |
| A3 Guard | PASS（pre-fix `enabled/isolate` → `not-applicable`） | `.../a3-guard-redgreen.log` |
| A4 XHTTP | 非缺陷（父提交负例测试通过） | `.../a4-prefix-probe.log` |
| A5 缓存/OPS-32 | PASS；Test Install 在 `aa4b9da9` CI 通过，根因未定位 | `.../p2/OPS-32`、run 44725121834 |
| M1–M10 | 双端 rc=0；两轮 L4/L6 ok；幂等 rc2=0 | `round3-final-20261120-1821-df3f3838/p2/` |
| E1–E8 | 67 项 Go 检查全满足 | 同上 |
| OPS 双端 | 5 行 PASS | 同上 |
| OPS Go sweep | 36/0 | `round3-ops-20261120-1818/` |
| 98 项矩阵 | 0 GAP | `matrix-20261120-final/` |
| 冷恢复 | 27/27 | `goevo-coldrestore-docker-final-cold-20261120-df3f3838/` |
| R1/R2/INJ | 106/0 | `docker-final-r1-20261120-df3f3838/r1/` |
| P3 xhttp | 62/62 | `goevo-p3-docker-final-p3xhttp-20261120-df3f3838/` |
| race | 8 包 rc=0 | `.../race-final.log` |
| CI | `aa4b9da9` 7/7 success（含 Test Install） | run 44725121966/21993/21851/22135/21880/21834/21949 |
| CI（HEAD） | `beb51ab9` 7/7 success（30 check pass / 1 skip） | run 44725987921/87933/87816/87872/87940/87830/87943 |
| CI（OPS-04 修复） | `1e73c19b` 7/7 success | run 44772637951/44772638262/44772637991/44772637947/44772637993/44772637944/44772638045 |

未完成（第三轮时）：OPS 34 全双端（5/34）、9 个 subscripts、多版本/第二发行版、
30 分钟 soak、纯 Bash ACME、公网 CA/外部 IPv6/VPS 重启。

**结论**：Docker 开发候选 `NO_GO_FOR_DOCKER_QUALIFIED_CANDIDATE`；
正式发布 `NO_GO_NOT_AUTHORIZED`。PR 保持 draft。

## 2026-11-20 补齐轮（OPS 新增行 / subscripts / soak / 多版本 / Debian）

| 项 | 结果 | 证据 |
| --- | --- | --- |
| OPS 新增 04/05/06/07/17c/30 | 04/05/06/07/17c 双端 PASS；30 `BASH_ONLY`；OPS-04 的 Go no-op 已修复 | `tests/e2e-diff/evidence/opsfix-3/p2/` |
| OPS-10 | `PASS`（嵌套 file_manager 已驱动） | `tests/e2e-diff/evidence/ops10-3/p2/` |
| OPS 既有 09/19/21/31/32 | 全量回归 PASS，未退化 | `ops-full-3/p2/` |
| subscripts S4–S9 | S4/S5/S7/S8/S9 PASS；S6 `BLOCKED`（外网资产不可达） | `tests/e2e-diff/evidence/s-6-1/s/` |
| 30 分钟 soak | PASS 30/30 | `tests/e2e-diff/evidence/soak-30m-1/soak/soak.json` |
| 多版本 Xray | PASS（v26.11.9/v26.10.31/v26.10.21 `xray -test`） | `tests/e2e-diff/evidence/versions-3/versions/` |
| 第二发行版 | PASS（Debian 12.15 M1 + OPS-19） | `tests/e2e-diff/evidence/debian12-1/p2/` |
| preflight | Go `xray tls`/`config edit`/`schedule`/`update` 能力确认 | `tests/e2e-diff/evidence/preflight-ops/` |

未完成（补齐后）：OPS-16/17b/23/24 双端驱动未接入（17b/24 已有 Go 命令）、S6 需外网 GitHub 资产、纯 Bash ACME、
公网 CA、外部公网 IPv6、生产 VPS。OPS-04 的 Go `NoChanges` 误判已修复并有回归测试。

**结论不变**：Docker 开发候选 `NO_GO_FOR_DOCKER_QUALIFIED_CANDIDATE`；
正式发布 `NO_GO_NOT_AUTHORIZED`。PR #182 保持 draft。
