# 最终审计 · 2026-11-19

## 1. 结论

| 范围 | 结论 | 理由 |
| --- | --- | --- |
| 合并到 `main` | **NO-GO** | 真实 CI 未复跑、独立 VM 未验收、OPS 29 行无双端证据 |
| 发布正式版本 / tag | **NO-GO** | 同上；且任务书禁止本轮发布 |
| 合并到 `develop/go-native` | **GO（作为候选）** | 当前 SHA 全量 Go 门禁与 P3 真实场景通过；P1/P2 代码有定向负例 |
| 生产 VPS 操作 | **禁止** | 任务书约束 |

本轮未执行 `git push`、未合并 `main`、未创建 tag/release、未连接生产 VPS。

## 2. 交付物

| 交付物 | 状态 | 路径 |
| --- | --- | --- |
| S0 基线 | 完成 | `docs/go-evolution/hardening/00-baseline.md` |
| P1 安全/恢复报告 | 完成 | `docs/go-evolution/hardening/01-security-recovery.md` |
| P2 CI/双端报告 | 完成 | `docs/go-evolution/hardening/02-ci-and-bash-go-parity.md` |
| P3 原生体验报告 | 完成 | `docs/go-evolution/hardening/03-native-experience.md` |
| 验收矩阵 | 完成 | `docs/go-evolution/hardening/ACCEPTANCE_MATRIX.md` |
| 最终审计 | 完成 | `docs/go-evolution/hardening/FINAL_AUDIT.md` |
| 执行轨迹 | 完成 | `docs/go-evolution/hardening/TRAE_PROGRESS.md` |

代码提交：

| SHA | 内容 |
|---|---|
| `59adbce4` | S0 基线报告 |
| `8ac1385f` | P1：备份/恢复事务化、符号链接边界、repair 锁 |
| `4c986c26` | P2：CI 红灯修复、ANSI 历史分类、signed-stage 冒烟 |
| `04d06cf4` | P3：doctor 证据分级与真实客户端探针、preflight readiness、hot-user 探针断言 |
| `43ceb680` | P1 加固：六个持久点 SIGKILL、ENOSPC/EROFS/EACCES、并发锁/坏 journal/第三方文件/canary；P3 传输参数化 |
| `1b519028` | P2：M10 内联 relay doctor 探针；OPS-21 离线 geo 提示 |
| `911f91d2` | doctor：relay 以 nginx unit 判定健康；relay `--client-probe` |
| `de43a36b` | P3 runner：修复 `set -u` 下空数组展开（原始安装路径） |
| `4c9705a9` | P1：`backup create --include-geodata` 在可选 GeoData 树缺失时不再整体失败 |
| `4ab08050` | P1：双容器冷恢复用例（源机销毁、目标机恢复、权限/验证器/服务/真实客户端） |

## 3. P0/P1 缺陷闭环

| ID | 原缺陷 | 处理 | 复核 |
| --- | --- | --- | --- |
| B-01 | `Verify` 不拒绝额外条目、不校验 mode、无大小上限 | 重写为流式、精确集合、mode/size、压缩炸弹边界 | `internal/backup/hardening_test.go` |
| B-02 | `Create` 直接写最终路径、允许写入受管树 | 临时文件 + `os.Link` 不覆盖 + `Verify` 失败回滚 + 拒绝受管树内归档 | `TestCreate*` |
| B-03 | `Restore` 无锁、无 journal、无条件删除旧文件、SIGKILL 不收敛 | 共享 flock + 持久化 journal + 快照 + `recover` + 真实 SIGKILL 注入 | `TestRestoreHardKillAtEveryDurablePointConverges`（6 点）、`TestRestoreRollsBackOnFilesystemErrors`、`TestRestoreRefusesWhileAnotherProcessHoldsLock`、`TestRecoverRefusesCorruptJournalWithoutTouchingFiles` |
| B-04 | repair 跟随符号链接、正式运行无共享锁 | 逐级 `Lstat`、`O_NOFOLLOW`、正式运行持锁、dry-run 零写入 | `internal/repair/hardening_test.go` |
| B-05 | 恢复暂存 `filepath.Join` 可越界 | 组件级安全路径解析 + 受管根约束 | `TestRestoreRefusesSymlinkComponent`、`TestRestoreRejectsTraversalWithoutTouchingCanary` |

P1 定向测试共 41 个 `Test*` 函数（`internal/backup` 33、`internal/repair` 8），其中本轮新增 8 个测试与 9 个子测试点；
P3 新增客户端探针与 readiness 测试。当前 SHA 全量 `go test -count=1 ./...` 25 个包 `ok`、0 FAIL（见第 7 节）。

## 4. CI 红灯闭环

| 红灯 | 根因 | 修复 | 本轮证据 |
| --- | --- | --- | --- |
| `test_unverified_release_must_fail` | 测试把“账本全 PENDING”写死 | 在隔离副本上重写账本状态，分别验证 pending rc=2 与 signed rc=3 | `Ran 10 tests ... OK` |
| `check_preview_gate.py` 在签收后必红 | 强制账本 28 PENDING | 新增 signed 阶段检测；signed 时运行 `check_signed_stage.py`，无发布权限 | 同上；`actionlint` rc=0 |
| `Test Install` ANSI 扫描 | 历史日志与 fixture 混为一类 | 按 `production-output-risk/docs/test-fixture/canonical-payload/historical-evidence` 分类 | `73 passed, 0 failed`，`production-risk=0` |

真实 GitHub Actions：`NOT_RUN`（未 push）。workflow 变更已通过本地 actionlint，不能据此声称 CI 已绿。

## 5. 仍未闭合的风险

| 风险 | 等级 | 现状 | 发布前要求 |
| --- | --- | --- | --- |
| 冷恢复（容器） | P1 | 已闭合 | `20261119-cold4`：源容器销毁后目标容器恢复，8/8 + 19/19，真实客户端通过 |
| 独立 VM 冷恢复/掉电恢复 | P1 | `BLOCKED` | 至少一次真实 VM 全流程（P3-04） |
| 真实 CI 复跑 | P1 | `NOT_RUN` | push 到受保护分支并保存 run id |
| OPS 29 行无双端证据 | P1 | `GO_ONLY_PASS` | 逐项补双端或正式批准安全差异 |
| 纯 Bash ACME（M8） | P1 | `BLOCKED` | 提供 `acme.sh` 与可达 ACME 端点后重跑 |
| 接管/迁移独立 VM | P1 | `PARTIAL` | 容器 R1/R2/INJ 已过（85+26 断言），仍需旧版真实安装 + 独立 VM |
| 真实多版本 Xray 候选矩阵 | P2 | `NOT_RUN` | 缓存至少 2 个真实历史版本并跑 preflight |
| relay 真实客户端探针 | P2 | 已闭合（转发层） | `20261119-m10relay2`：`REAL_CLIENT_PASS`；发布说明须写明这是 HTTP 经 Nginx Stream，不是 VLESS 会话 |
| 全量人工渗透审计 | P2 | `PARTIAL` | 发布前安全评审 |

## 6. 不得使用的表述

- 不得把 `go test` 通过写成“Bash/Go 双端通过”。
- 不得把 `exit 0`、JSON 匹配、Go 单边运行写成 `DUAL_SIDE_PASS`。
- 不得把 `20261119-r1` 中唯一的 INJ 外网失败写成产品回归；已用 `20261119-inj` 重跑并通过。
- 不得把 relay 的 `REAL_CLIENT_PASS` 写成 VLESS 用户会话；它证明的是 Nginx Stream 转发。
- 不得把容器内 systemd 结果写成真实 VM 或生产验证。
- 不得把 `compatible=true` 当作“配置已验证兼容”；必须同时看 `readiness=verified`。

## 7. 复现命令

```bash
# 全量 Go 门禁（当前 SHA 911f91d2）
docker run --rm -v "$PWD:/src:ro" -w /src \
  -e CGO_ENABLED=0 -e GOFLAGS=-mod=vendor -e GOPROXY=off -e GOTOOLCHAIN=local \
  -e GOCACHE=/tmp/gocache golang:1.27.4 bash -c \
  'export PATH=$PATH:/usr/local/go/bin; gofmt -l cmd internal tests; go vet ./...; go build ./...; go test -count=1 ./...'

# CI fail-closed 负例
cd tests/go-parity/parity && python3 -m unittest discover -s tests -v

# ANSI 分类
python3 .github/test/test_color_output.py

# P2 全量矩阵（9 个安装 + 8 个编辑 + 5 个 OPS）
E2E_RUN_ID=<run-id> E2E_CONCURRENCY=4 bash tests/e2e-diff/run_p2_matrix.sh

# 接管/注入
E2E_RUN_ID=<run-id> E2E_PATHS=both bash tests/e2e-diff/run_r1_upgrade.sh
E2E_RUN_ID=<run-id> E2E_PATHS=inj E2E_ONLY=M4 bash tests/e2e-diff/run_r1_upgrade.sh

# P3 真实场景（raw / ws / grpc / xhttp）
E2E_RUN_ID=<run-id> bash tests/e2e-diff/run_p3_hot.sh
E2E_RUN_ID=<run-id> E2E_TRANSPORT=ws bash tests/e2e-diff/run_p3_hot.sh
E2E_RUN_ID=<run-id> E2E_TRANSPORT=grpc bash tests/e2e-diff/run_p3_hot.sh
E2E_RUN_ID=<run-id> E2E_TRANSPORT=xhttp bash tests/e2e-diff/run_p3_hot.sh
```
