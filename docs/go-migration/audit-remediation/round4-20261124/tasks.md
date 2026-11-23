# 任务清单：补齐真实业务事实证据

对应规格：`docs/go-migration/audit-remediation/round4-20261124/spec.md`

## T1 静态改动与语法检查
- [x] `ops_generic_verdict` OPS-10 写 `details.{bash,go}.serverNames`
- [x] `ops_simple_job` Bash OPS-04 采集 `share-bash.txt/.rc/.uri`
- [x] `ops_generic_verdict` OPS-04 写 `details` 三项业务事实
- [x] `ops_state_probe`/`ops_state_verdict` OPS-08 写 `details.sniProbe`
- [x] `ops32_merge` 写 `details.{bash,go}.faultRemoved/recovered`
- [x] `client_config.py` 支持 `--email/--uuid`；`l4.sh` 透传
- [x] `ops_users_job`/`ops_users_verdict` OPS-01/02 写 `clientConnected`
- 验证：`bash -n` 与 `py_compile` 均通过（STATIC_OK）

## T2 定向真实运行（新 runId）
- [x] `round4-bizfacts2-50415119`（`E2E_ONLY=OPS-01,OPS-04,OPS-08,OPS-10,OPS-32`）：OPS-32/01/04/10 PASS；OPS-08 首版判定器 `NameError`，失败原样保留
- [x] 修复 `report` 作用域与已知 SNI 取值后，`round4-bizfacts3-50415119`（`E2E_ONLY=OPS-08`）双端 PASS
- [x] 逐行检查 6 个 `ops.json`：`details` 业务事实齐全且来自真实观测
- [x] 保留两轮控制台日志与每步证据，记录退出码 0

## T3 账本重建与核对
- [x] 运行 `build_ledger.py --allow-repo-write`（三份矩阵证据 + Go sweep，`--code-sha 50415119`）
- [x] 计数：19 DUAL / 1 GO_ONLY / 13 FAIL / 1 BLOCKED / 0 NOT_RUN，退出码 1
- [x] 目标 6 行均升为 DUAL；OPS-20 仍 GO_ONLY、OPS-17b 仍 BLOCKED、13 行 FAIL 未自行批准

## T4 报告与交付
- [x] 更新 `FINAL_AUDIT_20261124.md`（业务事实、复跑、账本、未闭合项）
- [x] 更新 `defects.json` 与 `evidence-index.json`（新 run provenance、R4-B4）
- [x] 追加 `TRAE_PROGRESS.md`
- [ ] 提交并 push `work/go-hardening-parity-20261119`
- [x] 不做：合并主线、tag、发布、生产 VPS、自行批准差异

## 完成标准
- 每个升为 DUAL 的行都有双侧 `details` 真实业务事实与对应日志。
- 未能成立的行保持 BLOCKED/FAIL，并写明真实原因。
- 账本、报告、证据索引三者 SHA 与计数一致。
