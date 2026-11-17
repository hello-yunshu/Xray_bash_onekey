# G-4 / G-5 / G-6 任务

## G-4 M8 ACME harness

- [x] T1 `run_p2_matrix.sh`：新增 `prepare_pebble_assets` / `start_pebble` / `wait_pebble`
- [x] T2 `run_p2_matrix.sh`：`start_server` 可选挂载、`l4_transports` M8=ws、case M8
- [x] T3 `run_p2_matrix.sh`：`run_bash_round` M8 注入 SSL_CERT_FILE / ACME directory
- [x] T4 `bash_install.sh`：`E2E_ACME=1` 跳过自签证书、种入 idleleo、记录模式
- [x] T5 `drivers/go_acme.sh`：cert issue → install，复用既有采集
- [x] T6 `matrix.json`：M8 go.argv/driver/acme，跑通后 eligible/verified 置真
- [x] T7 `E2E_ONLY=M8` 双跑两次（各含 round1/2），核对 rc、探针、L4、verdict、issuer
- [x] T8 证据入库 + `tasks.md` G-4 + parity 文档更新

## G-5 C6 direct TLS

- [x] T9 `internal/xraycfg/directtls.go`：`PatchDirectTLS` + 窄断言 + 校验规则
- [x] T10 `ModeTLSDirect` 与 `EditRuntime` 分流；`editBase` 识别 direct TLS
- [x] T11 `internal/deploy/edit.go`：对校验、跳过续期/metadata、direct 探针、回滚
- [x] T12 `xraycfg` 表驱动单测（负例 1-4、正例 5-8、结构保持 9）
- [x] T13 `deploy` 单测：可编辑、证书对不匹配、探针通过、探针失败回滚
- [x] T14 `C6_test.py` E2E：负例 rc=2 与 sha 不变、真实编辑、dry-run JSON
- [x] T15 固定镜像双跑证据 + hygiene；C6 关闭文档 + tasks.md G-5
- [x] T16 两次提交：`feat(C6)` 与 `test(C6)`（`85cdc392` / `03405437`）

## G-6 发布验收（本地部分）

- [x] T17 `tests/go-parity/evidence/g6-2026-11-17/release-gate.out`（rc=2、pending 28）
- [x] T18 `signoff-audit.md`：F01-F28 状态/测试/证据/签收行逐行核对
- [x] T19 `ci-closeout.md`：CI 结清步骤与不可本地替代项
- [x] T20 `docs/plans/p2/tasks.md` G-6：本地子项勾选，CI 项注明阻塞
- [x] T21 校验 `install.sh`、ledger、遗留文件未被改动；工作区只留允许的遗留物

## 验收（全部满足才算完成）

- [x] G-4：两次独立 run 的 M8 双侧 round1/2 rc=0、L4 ws 通过、PASS、issuer=Pebble
- [x] G-5：`go test ./internal/xraycfg ./internal/deploy` 通过、`C6_test.py` 通过
- [x] G-6：三份证据存在且 gate 输出可复现；CI 项保持未完成且未伪造
- [x] 全程无 push/merge/tag、`install.sh` 未改、ledger 未改
