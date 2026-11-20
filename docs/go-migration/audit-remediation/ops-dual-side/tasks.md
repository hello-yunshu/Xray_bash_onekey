# Tasks: OPS 双侧补齐（可执行项）

依赖：`spec.md` 已批准。所有命令在仓库根目录执行，每个 E2E 运行使用新的 `E2E_RUN_ID`。

## T1. 能力 preflight
- [x] 在 `idleleo-e2e:24.04` 内执行 `idleleo xray tls --help`、`idleleo xray config edit --help`、`idleleo update --help`。
- [x] 输出保存到 `tests/e2e-diff/evidence/<RUN_ID>/preflight/`。
- [x] 依据实测结果决定 OPS-07/10/17b 是否保留 `go: null`。
- 验证：`preflight/*.txt` 非空，结论写入 spec 3.3 的落地记录。

## T2. 新增 Bash OPS driver
- [x] 创建 `tests/e2e-diff/drivers/bash_ops.exp`，实现 `step/ask/navigate/harness_error` 与 OPS-04/05/06/07/10/17c/30 流程。
- [x] 超时/EOF → `exit 124`；前置缺失 → `blocked.json` + `exit 3`；嵌套菜单 → `nested.json` + `exit 3`。
- 验证：`expect -f ... ` 在容器内对 OPS-04 真实执行 rc=0；故意改错正则时 rc=124。

## T3. Runner 接入
- [x] `run_p2_matrix.sh` 新增 `ops_base_install`、`ops_bash_menu`、`ops_snapshot`、`ops_generic_verdict`、`ops_simple_job`。
- [x] `ops_job` 与 `OIDS` 增加 OPS-04/05/06/07/17c/30。
- [x] 保留 `E2E_ONLY` 子集与 `scope.json` 语义。
- 验证：`bash -n tests/e2e-diff/run_p2_matrix.sh` 通过；`E2E_ONLY=OPS-04` 可只跑该行。

## T4. 判定器
- [x] `ops_generic_verdict` 按 spec 第 4 节实现每条断言。
- [x] 缺证据 → `HARNESS-ERROR`；不允许单侧 PASS。
- 验证：空目录输入得到 `HARNESS-ERROR`；构造两侧快照得到预期 PASS/BLOCKER。

## T5. matrix.json 对齐
- [x] 按 preflight 结果更新 OPS-05/06/07/10/17b/30 的 `go`、`verdict`、`notes`。
- [x] 不存在的命令一律保持 `null`。
- 验证：`python3 -m json.tool tests/e2e-diff/matrix.json >/dev/null`。

## T6. OPS-04/05 分组实跑
- [x] `E2E_ONLY=OPS-04,OPS-05 bash tests/e2e-diff/run_p2_matrix.sh`。
- [x] 复核缺陷归属：Go 侧 `config edit --port/--public-port` 为 no-op；按 spec §7 不改 `internal/` 业务代码，OPS-04 记 `BLOCKER`。
- 验证：两份 `ops.json` 无 HARNESS-ERROR，Bash/Go rc=0。

## T7. OPS-06/07 分组实跑
- [x] `E2E_ONLY=OPS-06,OPS-07 bash tests/e2e-diff/run_p2_matrix.sh`。
- [x] 记录 OPS-06 回源探测拒绝分支（BLOCKED）或成功分支（PASS）。
- 验证：`ops.json` 判定与证据一致；OPS-07 若无 Go 能力则记 `go-missing`。

## T8. OPS-17c/30 分组实跑
- [x] `E2E_ONLY=OPS-17c,OPS-30 bash tests/e2e-diff/run_p2_matrix.sh`。
- [x] 验证：OPS-17c 双侧 cron 存在；OPS-30 记 `BASH-ONLY` 且不计入 dualSide。

## T9. 全量 OPS 回归
- [x] 运行 OPS 全量组合（新增 6 行 + 既有 5 行，`ops-full-3`）。
- [x] 确认 OPS-09/19/21/31/32 结论未退化。
- 验证：汇总 `scope.json` 与实际执行列表一致。

## T10. 子脚本与浸泡
- [x] `bash tests/e2e-diff/run_s_scripts.sh`，S4–S9 有真实证据，S1–S3 引用 OPS 证据。
- [x] 新增并运行 `run_soak.sh`（30×60s），产出 `soak.json`。
- 验证：`soak.json` 中 `iterations=30` 且 `failedIteration=null`；S 脚本每项有 rc 记录。

## T11. 多版本与第二发行版
- [x] 新增并运行 `run_xray_versions.sh`，覆盖最近 3 个稳定版 + 26.10.31。
- [x] 新增 `image/Dockerfile.debian12` 并跑 `E2E_ONLY=M1,OPS-19`。
- 验证：`xray-versions.json` 每版本有 tag/sha256/verdict；Debian 结果单独记录。

## T12. 文档、提交与 CI
- [x] 更新 DOCKER_ACCEPTANCE/TRAE_PROGRESS/TEST_EVIDENCE/PARITY_MATRIX/acceptance.json。
- [ ] 提交并推送分支，等待 7 个工作流全绿。
- [ ] 输出中文最终报告；PR #182 保持 draft。
- 验证：新 HEAD CI 7/7 success；JSON 全部可解析；dualSide 计数只含 PASS 行。
