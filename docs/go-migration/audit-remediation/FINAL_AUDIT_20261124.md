# Trae Xray 第四轮审计收尾修复与最终独立验收报告

- 日期：2026-11-24
- 分支：`work/go-hardening-parity-20261119`
- 审计基线：`8f9673ce9d5ec485bb360cb932a5ce381475885e`
- 本轮候选（被推送 HEAD）：`5041511998575851eb5cb16533e9fe999d29d5a8`
- 产品代码修复提交：`8a457bec`（A1/A2/B1/B2/B3 + provenance）；`50415119` 仅修改验收运行器的 provenance 写入路径与测试，不改产品代码
- 结论：`NO_GO_FOR_DOCKER_QUALIFIED_CANDIDATE`；`RELEASE_AUTHORIZED = NO`

> 本报告只把有真实证据的结论写成通过。账本仍有 21 行未闭合，因此不为“全绿”做任何口径调整、退出码补写或自行批准。

## 0. 结论摘要

| 项目 | 结果 | 依据 |
| --- | --- | --- |
| 第四轮 4 个核心修复（D03/D04/D05/D06/D02） | 已修复并有红→绿证据 | 第 3 节 |
| A1 证书所有权（路径绑定、嵌套 marker、第三方 ACME） | 已修复；两条可执行复现红→绿，嵌套 marker 未复现仅作纵深防御 | `repro/red-8f9673ce.log`、`repro/green-50415119.log` |
| A2 Guard 运行态 | 已修复；不再用 `/proc/<pid>` 目录 mtime 推断启动时间，reload 记录绑定 PID+starttime | 同上 |
| B1 验收污染 | 已修复；28 个账本测试前后正式工件逐字节不变 | `repro/b1-red.log`、`repro/b1-green.log` |
| B2 账本证据归属/业务事实 | 已修复；严格契约使缺业务事实的行变为 BLOCKED | 第 5 节 |
| B3 批准来源/指纹/有效期 | 工具已修复；旧批准绑定旧证据指纹，新候选 13 行需重新批准 | 第 7 节 |
| 真实双端回归 | 全量矩阵在候选上执行完成，退出码 0；E1–E8 仅 Go 侧 | 第 4 节 |
| 正式账本 | 13 DUAL / 3 GO_ONLY / 13 FAIL / 5 BLOCKED / 0 NOT_RUN，退出码 1 | `tests/e2e-diff/ledger.json` |
| 发布授权 | **NO**；未合并主线、未打 tag、未发布、未操作生产 VPS | 第 8 节 |

## 1. S0 基线确认

1. 拉取远程并核对：初始工作树干净，HEAD 与 `origin/work/go-hardening-parity-20261119` 同步于 `8f9673ce`。
2. 审计发现“仍然存在”的直接证据：
   - `8f9673ce` 提交的 `docs/go-evolution/hardening/acceptance.json` 中 `ops.codeSha = "test"`、`failIds = ["OPS-08"]`、`notRun = 33`，与正式 ledger 的 20/8/6 不一致——B1 污染是已提交事实，不是推测。
   - 同一版本的 `tests/e2e-diff/approvals/round3-20261122.json` 为 `schemaVersion=1`，条目只有 `id/approvedBy/reason/scope`——B3 缺少可核对来源、指纹与有效期。
   - 旧账本把 OPS-04 记为 `DUAL_SIDE_VERIFIED`，而其证据 `sharePort.bash=null`、`listening443=false`——B2 的“只看 verdict/rc”是可复现的放行。
   - 在 `8f9673ce` 上运行同一份复现测试，A1 未登记同内容副本被删、A2 未绑定实例的 reload 记录被判 active（见第 3 节）。
3. 环境：macOS arm64 + Docker Desktop；systemd 容器镜像 `idleleo-e2e:24.04`；Go 镜像 `golang:1.27.4`（`GOFLAGS=-mod=vendor GOPROXY=off GOTOOLCHAIN=local`）；真实 seed Xray `26.11.9`（`sha256 c2d1e66a…`），Bash 脚本 `3.3.6`，Nginx `2026.10.15.7679`。
4. 本轮没有修改验收口径以取得通过，也没有补写任何退出码；`round4-2ac2f0c3` / `round4-8a457bec` 两次失败尝试的原始日志保留。

## 2. 审计发现逐项复核

| 审计项 | 复核结果 | 本轮动作与证据 |
| --- | --- | --- |
| D01 TLS/variable 路径 | 未闭环，未在本轮改动 | 沿用上一轮定向回归；本轮未宣称完整 CLI 闭环 |
| D02 同域 ACME 归属 | 已按“保守保留”收敛 | `planACMEState` 只有目录内存在路径绑定 `.managed-by-idleleo` 才删除；`TestReproThirdPartyACMEDirSurvives` 红→绿；OPS-27 显示 Bash 仍会删第三方 canary，Go 不会 |
| D03 证书所有权 | 已关闭 | 所有权行升级为 `file=…\ttype=…\tsha256=…`，拒绝绝对路径/越界/非普通文件；未登记同内容副本保留；嵌套 `.user-managed` 整树保护（纵深防御，未复现） |
| D04 Guard 运行态 | 已关闭（保留数据面残余） | 读取 `/proc/<pid>/stat` starttime 与 `/proc/stat` btime；reload 记录写 PID/StartTicks，校验实例一致；不再用目录 mtime。仍不声称证明 SNI 数据面 |
| D05 验收污染 | 已关闭 | 写入门禁 + 测试隔离 + 28 个测试 + `guard_acceptance_artifacts.sh`；正式三工件重建后一致且无 `test` |
| D06 证据归属/业务事实 | 已补齐主要部分，剩余一项 | 新增 provenance、业务事实、批准指纹/有效期、supersedes；DIFF 行的“预期 rc”未实现（差异声明没有 `expectedRc` 字段，未补造） |
| D07 全双端 | 本轮未全绿，且有证据缺口 | 13 DUAL；OPS-01/02/04/08/10/32 因缺业务事实未达 DUAL；详见第 5/6 节 |
| D08 M8 纯 Bash | 未改变 | M8 仍为 Bash wrapper 委托 Go Pebble；本轮未重建旧架构 |
| D09 账本读取 run 身份 | 部分关闭 | 现在读取每个 run 的 commit、二进制、脚本、驱动、镜像、runId；新增 supersedes/fixedBy/history；rank 规则未改 |
| D10 XHTTP 路径 | 未在本轮改动 | 沿用定向回归；未宣称所有入口/尾斜杠全覆盖 |
| 新增 1 验收污染 | 已关闭 | 同 D05 |
| 新增 2 Guard 状态误报 | 已关闭（同 D04） | 同 D04 |
| 新增 3 证书所有权 | 已关闭（同 D02/D03） | 同 D02/D03 |
| 新增 4 批准授权 | 工具已关闭，授权待用户 | 批准文件升级 v2 并记录会话来源；新候选证据需重新批准 |

## 3. 修复与红→绿复现

同一份 `repro/round4_repro_test.go.txt` 在基线 `8f9673ce` 与候选 `50415119` 上分别运行：

| 用例 | 8f9673ce | 50415119 | 含义 |
| --- | --- | --- | --- |
| `TestReproUnregisteredIdenticalCopyIsKept` | FAIL（未登记副本被删） | PASS | A1 内容哈希认领缺陷已修复 |
| `TestReproThirdPartyACMEDirSurvives` | FAIL（第三方 ACME 目录被删） | PASS | D02 已收敛为保守保留 |
| `TestReproUnboundReloadRecordDoesNotProveActive` | FAIL（verified=true） | PASS | A2 旧策略误报已修复 |
| `TestReproNestedUserMarkerProtectsSubtree` | PASS | PASS | 该夹具未复现删除；按源码风险做纵深防御，不虚报红 |

- B1：基线运行账本测试会把正式 `acceptance.json` 从 `fd1a6dcf…` 改写为其它内容；修复后同一套 28 个测试前后逐字节一致，并有独立门禁脚本。
- B2/B3：`test_build_ledger.py` 28/28 通过，覆盖“PASS 缺 provenance”“旧 SHA 证据”“缺业务事实”“批准指纹不符”“批准过期”“FAIL 无据覆盖”等负例。
- 新增 Go 单元测试：`internal/deploy/certclear_round3_test.go`、`internal/deploy/guard_round3_test.go` 锁定上述行为。

## 4. 真实回归执行记录

| 命令 | 结果 | 证据 |
| --- | --- | --- |
| `go test -count=1 ./...`（`golang:1.27.4`，候选 `50415119`） | 25 个包 ok，0 FAIL，退出码 0 | `logs/go-test-50415119.log` |
| `E2E_RUN_ID=round4-full-50415119 bash tests/e2e-diff/run_p2_matrix.sh` | 退出码 0；M1–M10 双端×2 轮 40 个 `install.rc`/`rc.txt` 全 0；E1–E8 共 8 个场景 allPassed=true（100 项检查记录中期望项全部满足）；34 行 OPS 全部执行 | `tests/e2e-diff/evidence/round4-full-50415119/` |
| `E2E_RUN_ID=round4-final-50415119-sweep bash tests/e2e-diff/run_ops_sweep.sh` | 57 PASS / 0 FAIL，退出码 0；账本不据此伪造 `goExit` | `tests/e2e-diff/evidence/round4-final-50415119-sweep/` |
| `E2E_RUN_ID=round4-final-50415119 … E2E_ONLY=OPS-01,…` | 退出码 0；用于先验证运行器 provenance 写入 | `tests/e2e-diff/evidence/round4-final-50415119/` |
| `bash tests/e2e-diff/collect/guard_acceptance_artifacts.sh` | PASS：测试前后正式工件字节一致 | 本轮输出 |
| 账本重建 | 退出码 1（FAIL 行存在，符合严格契约） | `repro/ledger-build-50415119.log` |

说明：
- E1–E8 目录只有 `go` 侧证据，Bash 私钥重建菜单仍未覆盖，与审计 D07 一致。
- 矩阵覆盖正常与异常分支：E1–E4 含成功/回滚/拒绝/非法编辑，E5–E8 为只读/缺证书/坏配置等；OPS 中 OPS-17b 的 Bash 分支超时被记为 BLOCKED，而不是通过。
- 未重跑历史 98 项独立矩阵核对、公网 CA/IPv6、宿主 BBR、生产 VPS。

## 5. 正式账本（`tests/e2e-diff/ledger.json`）

计数：`DUAL_SIDE_VERIFIED=13`、`GO_ONLY=3`、`FAIL=13`、`BLOCKED=5`、`NOT_RUN=0`、`APPROVED_DIFF=0`、`APPROVED_SINGLE_SIDE=0`；退出码 1。三份摘要（`ledger.json` / `matrix.json` / `acceptance.json`）的 `codeSha` 与计数一致，`acceptance.json` 不再包含 `test` 数据。

| 行 | 状态 | 判定/退出码 | 说明 |
| --- | --- | --- | --- |
| OPS-01 | GO_ONLY | PASS / bash=None go=None | 仅 Go 单侧断言（sweep）；双端运行结果为 BLOCKED（缺业务事实） |
| OPS-02 | GO_ONLY | PASS / bash=None go=None | 仅 Go 单侧断言（sweep）；双端运行结果为 BLOCKED（缺业务事实） |
| OPS-03 | FAIL | DIFF / bash=None go=None | shortId residue after remove: bash=1 go=2 (baseline 1/1)；approval fingerprint does not match the cited evidence for OPS-03 |
| OPS-04 | BLOCKED | PASS / bash=0 go=0 | bash side has no business evidence block；go side has no business evidence block |
| OPS-05 | DUAL_SIDE_VERIFIED | PASS / bash=0 go=0 | 两端 PASS 且业务事实满足 |
| OPS-06 | DUAL_SIDE_VERIFIED | PASS / bash=0 go=0 | 两端 PASS 且业务事实满足 |
| OPS-07 | DUAL_SIDE_VERIFIED | PASS / bash=0 go=0 | 两端 PASS 且业务事实满足 |
| OPS-08 | BLOCKED | PASS / bash=0 go=0 | bash side has no business evidence block；go side has no business evidence block |
| OPS-09 | DUAL_SIDE_VERIFIED | PASS / bash=0 go=0 | 两端 PASS 且业务事实满足 |
| OPS-10 | BLOCKED | PASS / bash=0 go=0 | bash side has no business evidence block；go side has no business evidence block |
| OPS-11 | DUAL_SIDE_VERIFIED | PASS / bash=0 go=0 | 两端 PASS 且业务事实满足 |
| OPS-12 | FAIL | DIFF / bash=124 go=0 | Bash menu entry is an unbounded 'tail -f' stream; Go emits a finite journald snapshot；approval fingerprint does not match the cited evidence for OPS-12 |
| OPS-13 | FAIL | DIFF / bash=124 go=0 | Bash menu entry is an unbounded 'tail -f' stream; Go emits a finite journald snapshot；approval fingerprint does not match the cited evidence for OPS-13 |
| OPS-14 | FAIL | DIFF / bash=124 go=0 | Bash entry is the interactive iftop UI; Go is a bounded stats query；bash output bytes=5007 |
| OPS-15 | DUAL_SIDE_VERIFIED | PASS / bash=0 go=0 | 两端 PASS 且业务事实满足 |
| OPS-16 | FAIL | DIFF / bash=0 go=0 | Bash menu 4>2>1/4>2>2 shows certificate status/validity; Go 'cert renew --dry-run' is a renewal preflight；bash rc=0 |
| OPS-17a | FAIL | PASS / bash=None go=None | approval fingerprint does not match the cited evidence for OPS-17a |
| OPS-17b | BLOCKED | BLOCKED / bash=124 go=3 | Nginx update needs the fixed local trusted package used by the real-root job；bash rc=124 go rc=3 |
| OPS-17c | DUAL_SIDE_VERIFIED | PASS / bash=0 go=0 | 两端 PASS 且业务事实满足 |
| OPS-18 | FAIL | PASS / bash=None go=None | approval fingerprint does not match the cited evidence for OPS-18 |
| OPS-19 | DUAL_SIDE_VERIFIED | PASS / bash=0 go=0 | 两端 PASS 且业务事实满足 |
| OPS-20 | GO_ONLY | PASS / bash=None go=None | 仅 Go 单侧断言（sweep）；双端运行结果为 BLOCKED（缺业务事实） |
| OPS-21 | DUAL_SIDE_VERIFIED | PASS / bash=0 go=0 | 两端 PASS 且业务事实满足 |
| OPS-22 | DUAL_SIDE_VERIFIED | PASS / bash=0 go=0 | 两端 PASS 且业务事实满足 |
| OPS-23 | FAIL | PASS / bash=None go=None | approval fingerprint does not match the cited evidence for OPS-23 |
| OPS-24 | FAIL | PASS / bash=None go=None | approval fingerprint does not match the cited evidence for OPS-24 |
| OPS-25 | FAIL | DIFF / bash=0 go=0 | Bash backup operates on the managed tree (tar archive); Go backup operates on JSON metadata；bash rc=0 |
| OPS-26 | FAIL | DIFF / bash=0 go=0 | Bash restore/import operates on the managed tree (tar archive); Go restore/import operates on JSON metadata；bash rc=0 |
| OPS-27 | FAIL | DIFF / bash=None go=None | Bash backup menu 7>3 deletes the whole certificate directory after one confirm; Go requires managed ownership proof；Bash removed the third-party canary (rm -rf entire cert dir) |
| OPS-28 | DUAL_SIDE_VERIFIED | PASS / bash=0 go=0 | 两端 PASS 且业务事实满足 |
| OPS-29 | DUAL_SIDE_VERIFIED | PASS / bash=0 go=0 | 两端 PASS 且业务事实满足 |
| OPS-30 | FAIL | BASH_ONLY / bash=0 go=0 | approval fingerprint does not match the cited evidence for OPS-30 |
| OPS-31 | DUAL_SIDE_VERIFIED | PASS / bash=0 go=0 | 两端 PASS 且业务事实满足 |
| OPS-32 | BLOCKED | PASS / bash=0 go=0 | bash side has no business evidence block；go side has no business evidence block |

解读：
- 13 行 FAIL 中，12 行是“已记录差异/单侧证据等待对本次候选重新批准”（批准指纹绑定 `99997da0` 的旧证据），OPS-03 还包含真实的 shortId 残留差异（Bash=1、Go=2）。
- 5 行 BLOCKED：OPS-04/08/10/32 是运行 PASS 但驱动未产出业务事实块；OPS-17b 是 Bash 分支超时 124、Go rc=3。
- OPS-01/02 的双端运行结果为 BLOCKED（缺真实新用户连接证据），账本 rank 取了更强的 Go 单侧断言，`history` 中保留被阻断的双端结果。

## 6. 未闭合项与证据缺口

| 编号 | 内容 | 状态 |
| --- | --- | --- |
| R4-OPEN-01 | OPS-01/02 未做真实新用户 VLESS 连接，缺 `clientConnected` 业务事实 | EVIDENCE_GAP |
| R4-OPEN-02 | OPS-04/08/10/32 运行通过但驱动未记录 `portListening`/`sniProbe`/`serverNames`/`faultRemoved+recovered` | EVIDENCE_GAP |
| R4-OPEN-03 | 13 行差异/单侧证据需用户对本次候选重新批准；旧批准不可静默复用 | APPROVAL_PENDING |
| R4-OPEN-04 | OPS-17b Bash 菜单超时 124（依赖本地可信 Nginx 包） | ENV_LIMITED |
| R4-OPEN-05 | E1–E8 仅 Go 侧；Bash 私钥重建菜单未覆盖 | COVERAGE_GAP |
| R4-OPEN-06 | 生产 VPS/公网 ACME/IPv6/宿主 BBR/掉电恢复未验证 | VPS_DEFERRED |
| R4-OPEN-07 | DIFF 行“预期退出码”尚未按差异内容校验 | TOOLING_PARTIAL |

## 7. 批准与授权状态

- 旧批准文件 `approvals/round3-20261122.json` 已升级为 v2：每条含 `opId`、`provenance`（引用上一轮会话“按推荐批准”，注明为会话文本、无外部签名）、`fingerprintOf`、`fingerprint`、`expiresAt=2026-12-31`。
- 由于本轮证据为新 run，旧指纹不再匹配，账本没有把任何差异行自动写成通过，也没有由开发工具自行续期或扩范围。
- 当前需要用户决定：是否对本次候选的 13 行（OPS-03/12/13/14/16/17a/18/23/24/25/26/27/30）按各自差异说明重新批准。未获批准前，它们保持 FAIL。

## 8. 边界声明与最终判定

- 未合并 `main`/`develop`，未打 tag，未正式发布，未操作生产 VPS。
- 容器内真实 systemd/Xray/Nginx 结果标记为 `LOCAL_DOCKER_RUN`，不是生产验证。
- `round4-aa680ddf` 为同产品代码的历史运行器产物，因 provenance 写入路径缺陷后以 `round4-full-50415119` 重跑；本报告不引用其手工补齐证据作为正式结论。
- **Docker 开发候选：`NO_GO_FOR_DOCKER_QUALIFIED_CANDIDATE`**（21 行未闭合）。
- **正式发布：`RELEASE_AUTHORIZED = NO`**（缺批准与生产边界验证）。
