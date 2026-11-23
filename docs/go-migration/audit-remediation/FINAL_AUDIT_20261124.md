# Trae Xray 第四轮审计收尾修复与最终独立验收报告

- 日期：2026-11-24
- 分支：`work/go-hardening-parity-20261119`
- 审计基线：`8f9673ce9d5ec485bb360cb932a5ce381475885e`
- 本轮候选（产品代码 SHA）：`5041511998575851eb5cb16533e9fe999d29d5a8`
- 证据/报告提交：`2f607180140b8504423b85fdc9110b9ccbe5d332`（`git diff 50415119..2f607180 -- cmd internal install.sh` 为空，即不含产品代码变更）；本轮补充证据与账本提交：`b988ee6d71733114edf652ae68ddda422a1d19e4`（产品 diff 同为 0）
- 产品代码修复提交：`8a457bec`（A1/A2/B1/B2/B3 + provenance）；`50415119` 仅修改验收运行器的 provenance 写入路径与测试，不改产品代码
- 补充证据提交：`tests/e2e-diff/evidence/round4-bizfacts2-50415119`、`round4-bizfacts3-50415119`（在 `50415119` 的独立 worktree 上运行，产品代码与二进制 SHA 不变）
- 结论：`NO_GO_FOR_DOCKER_QUALIFIED_CANDIDATE`；`RELEASE_AUTHORIZED = NO`

> 本报告只把有真实证据的结论写成通过。账本仍有 15 行未闭合（13 FAIL + 1 BLOCKED + 1 GO_ONLY），因此不为“全绿”做任何口径调整、退出码补写或自行批准。

## 0.1 业务事实补证（本轮追加）

| OPS | 新增真实观测 | 证据 |
| --- | --- | --- |
| OPS-01/02 | 新增用户后以该 email 发起 VLESS 请求成功；双端 `clientConnected=true`，增删计数与列表对比一致 | `round4-bizfacts2-50415119/p2/OPS-01/ops.json` |
| OPS-04 | 双端 `portListening=true`、`clientConnected=true`、`shareInfo` 非空（Bash `install.sh -s`，Go `share --json`） | 同上 `OPS-04/ops.json` |
| OPS-08 | 双端真实 `openssl s_client`：已知 SNI 握手成功，未知 SNI 被 `ssl_reject_handshake` 拒绝 | `round4-bizfacts3-50415119/p2/OPS-08/ops.json` |
| OPS-10 | 双端 `serverNames=ops10.example.com reality;` | `round4-bizfacts2-50415119/p2/OPS-10/ops.json` |
| OPS-32 | 两个上游均观测到 `removedAt` 与 `stableRecovery`；双端 `faultRemoved=true`、`recovered=true` | 同上 `OPS-32/ops.json` |

首次 OPS-08 判定器因 `NameError: report` 未生成 `ops.json`；该失败原样保留在
`round4-bizfacts2`，修复后在同一候选 worktree 上以 `round4-bizfacts3` 重跑通过。
驱动改动只涉及验收运行器，不改变产品代码（`git diff 50415119..HEAD -- cmd internal install.sh` 为空）。

## 0.2 结论摘要

| 项目 | 结果 | 依据 |
| --- | --- | --- |
| 第四轮 4 个核心修复（D03/D04/D05/D06/D02） | 已修复并有红→绿证据 | 第 3 节 |
| A1 证书所有权（路径绑定、嵌套 marker、第三方 ACME） | 已修复；两条可执行复现红→绿，嵌套 marker 未复现仅作纵深防御 | `repro/red-8f9673ce.log`、`repro/green-50415119.log` |
| A2 Guard 运行态 | 已修复；不再用 `/proc/<pid>` 目录 mtime 推断启动时间，reload 记录绑定 PID+starttime | 同上 |
| B1 验收污染 | 已修复；28 个账本测试前后正式工件逐字节不变 | `repro/b1-red.log`、`repro/b1-green.log` |
| B2 账本证据归属/业务事实 | 已修复；严格契约使缺业务事实的行变为 BLOCKED | 第 5 节 |
| B3 批准来源/指纹/有效期 | 工具已修复；旧批准绑定旧证据指纹，新候选 13 行需重新批准 | 第 7 节 |
| 真实双端回归 | 全量矩阵在候选上执行完成，退出码 0；E1–E8 仅 Go 侧；另加两轮定向业务事实回归 | 第 4 节 |
| 正式账本 | 19 DUAL / 1 GO_ONLY / 13 FAIL / 1 BLOCKED / 0 NOT_RUN，退出码 1 | `tests/e2e-diff/ledger.json` |
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
| D06 证据归属/业务事实 | 已关闭 | 新增 provenance、业务事实、批准指纹/有效期、supersedes；OPS-01/02/04/08/10/32 已补真实业务观测；DIFF 行的“预期 rc”仍未实现（差异声明没有 `expectedRc` 字段，未补造） |
| D07 全双端 | 19 行双端；剩余缺口均为历史差异/环境边界 | OPS-01/02/04/08/10/32 已由定向回归升为 DUAL；OPS-20 仍只有 Go 单侧；详见第 5/6 节 |
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
| `E2E_RUN_ID=round4-bizfacts2-50415119 E2E_ONLY=OPS-01,OPS-04,OPS-08,OPS-10,OPS-32 bash tests/e2e-diff/run_p2_matrix.sh` | 退出码 0；OPS-32/01/04/10 PASS，OPS-08 首次因判定器 `NameError` 未产出 ops.json（已在下一轮修复并重跑） | `tests/e2e-diff/evidence/round4-bizfacts2-50415119/`、`logs/bizfacts2.console.log` |
| `E2E_RUN_ID=round4-bizfacts3-50415119 E2E_ONLY=OPS-08 bash tests/e2e-diff/run_p2_matrix.sh` | 退出码 0；OPS-08 双端 PASS，已知 SNI 握手成功、未知 SNI 被 `ssl_reject_handshake` 拒绝 | `tests/e2e-diff/evidence/round4-bizfacts3-50415119/`、`logs/bizfacts3.console.log` |
| `bash tests/e2e-diff/collect/guard_acceptance_artifacts.sh` | PASS：28 个测试前后正式工件字节一致 | 本轮输出 |
| 账本重建 | 退出码 1（FAIL 行存在，符合严格契约） | `repro/ledger-build-bizfacts.log` |

说明：
- E1–E8 目录只有 `go` 侧证据，Bash 私钥重建菜单仍未覆盖，与审计 D07 一致。
- 矩阵覆盖正常与异常分支：E1–E4 含成功/回滚/拒绝/非法编辑，E5–E8 为只读/缺证书/坏配置等；OPS 中 OPS-17b 的 Bash 分支超时被记为 BLOCKED，而不是通过。
- 未重跑历史 98 项独立矩阵核对、公网 CA/IPv6、宿主 BBR、生产 VPS。

## 5. 正式账本（`tests/e2e-diff/ledger.json`）

计数：`DUAL_SIDE_VERIFIED=19`、`GO_ONLY=1`、`FAIL=13`、`BLOCKED=1`、`NOT_RUN=0`、`APPROVED_DIFF=0`、`APPROVED_SINGLE_SIDE=0`；退出码 1。三份摘要（`ledger.json` / `matrix.json` / `acceptance.json`）的 `ops.codeSha` 均为 `50415119`，`acceptance.json` 的 `ops.counts` 与账本一致；`ops.codeSha` 不再是测试值。

| 行 | 状态 | 判定/退出码 | 说明 |
| --- | --- | --- | --- |
| OPS-01 | DUAL_SIDE_VERIFIED | PASS / bash=0 go=0 | 新增用户后由该 email 发起真实 VLESS 请求成功（`clientConnected=true`），并完成删除 |
| OPS-02 | DUAL_SIDE_VERIFIED | PASS / bash=0 go=0 | 同 OPS-01；邮箱/UUID 规则与真实连接均由本次运行验证 |
| OPS-03 | FAIL | DIFF / bash=None go=None | shortId residue after remove: bash=1 go=2 (baseline 1/1)；approval fingerprint does not match the cited evidence for OPS-03 |
| OPS-04 | DUAL_SIDE_VERIFIED | PASS / bash=0 go=0 | `portListening=true`、`clientConnected=true`、`shareInfo` 非空（Bash 来自 `install.sh -s`，Go 来自 `share --json`） |
| OPS-05 | DUAL_SIDE_VERIFIED | PASS / bash=0 go=0 | 两端 PASS 且业务事实满足 |
| OPS-06 | DUAL_SIDE_VERIFIED | PASS / bash=0 go=0 | 两端 PASS 且业务事实满足 |
| OPS-07 | DUAL_SIDE_VERIFIED | PASS / bash=0 go=0 | 两端 PASS 且业务事实满足 |
| OPS-08 | DUAL_SIDE_VERIFIED | PASS / bash=0 go=0 | `sniProbe`：已知 SNI 握手成功（TLSv1.3），未知 SNI 被 `ssl_reject_handshake` 拒绝；双端 isolate 片段与 nginx active |
| OPS-09 | DUAL_SIDE_VERIFIED | PASS / bash=0 go=0 | 两端 PASS 且业务事实满足 |
| OPS-10 | DUAL_SIDE_VERIFIED | PASS / bash=0 go=0 | `serverNames` 双端均为 `ops10.example.com reality;`，来自真实 `nginx -T` 快照 |
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
| OPS-20 | GO_ONLY | PASS / bash=None go=None | 仅 Go 单侧断言（sweep 的 `trafficBytes>0`）；本轮未补 Bash 侧流量业务事实 |
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
| OPS-32 | DUAL_SIDE_VERIFIED | PASS / bash=0 go=0 | 两个上游均真实观测到 `removedAt` 与 `stableRecovery`；双端 `faultRemoved=true`、`recovered=true` |

解读：
- 19 行 DUAL 中，OPS-01/02/04/08/10/32 是本次补充证据后新达成的；其余 13 行沿用全量矩阵结果。
- 13 行 FAIL 中，12 行是“已记录差异/单侧证据等待对本次候选重新批准”（批准指纹绑定 `99997da0` 的旧证据），OPS-03 还包含真实的 shortId 残留差异（Bash=1、Go=2）。
- 1 行 BLOCKED（OPS-17b）：Bash 分支超时 124、Go rc=3，需要本地可信 Nginx 包，属环境边界。
- OPS-20 仅 Go 单侧；账本没有把单侧断言伪装成双端。
- 补充证据使用独立 worktree（HEAD=`50415119`）运行，`productCodeSha` 与二进制 SHA 均为 `50415119`/`9147144e…`，与全量矩阵一致；OPS-08 首轮因判定器 `NameError` 未产出 `ops.json`，失败原样保留在 `round4-bizfacts2`，修复后以 `round4-bizfacts3` 重跑。

## 6. 未闭合项与证据缺口

| 编号 | 内容 | 状态 |
| --- | --- | --- |
| R4-OPEN-01 | OPS-01/02 真实新用户 VLESS 连接 | CLOSED（`round4-bizfacts2`：双端 `clientConnected=true`） |
| R4-OPEN-02 | OPS-04/08/10/32 业务事实 | CLOSED（`round4-bizfacts2/3`：`portListening`/`shareInfo`/`sniProbe`/`serverNames`/`faultRemoved+recovered`） |
| R4-OPEN-03 | 13 行差异/单侧证据需用户对本次候选重新批准；旧批准不可静默复用 | APPROVAL_PENDING |
| R4-OPEN-04 | OPS-17b Bash 菜单超时 124（依赖本地可信 Nginx 包） | ENV_LIMITED |
| R4-OPEN-05 | E1–E8 仅 Go 侧；Bash 私钥重建菜单未覆盖 | COVERAGE_GAP |
| R4-OPEN-06 | 生产 VPS/公网 ACME/IPv6/宿主 BBR/掉电恢复未验证 | VPS_DEFERRED |
| R4-OPEN-07 | DIFF 行“预期退出码”尚未按差异内容校验 | TOOLING_PARTIAL |
| R4-OPEN-08 | OPS-20 只有 Go 单侧 `trafficBytes`，Bash 侧流量未采集 | EVIDENCE_GAP |

## 7. 批准与授权状态

- 旧批准文件 `approvals/round3-20261122.json` 已升级为 v2：每条含 `opId`、`provenance`（引用上一轮会话“按推荐批准”，注明为会话文本、无外部签名）、`fingerprintOf`、`fingerprint`、`expiresAt=2026-12-31`。
- 由于本轮证据为新 run，旧指纹不再匹配，账本没有把任何差异行自动写成通过，也没有由开发工具自行续期或扩范围。
- 当前需要用户决定：是否对本次候选的 13 行（OPS-03/12/13/14/16/17a/18/23/24/25/26/27/30）按各自差异说明重新批准。未获批准前，它们保持 FAIL。

## 8. 边界声明与最终判定

- 未合并 `main`/`develop`，未打 tag，未正式发布，未操作生产 VPS。
- 容器内真实 systemd/Xray/Nginx 结果标记为 `LOCAL_DOCKER_RUN`，不是生产验证。
- `round4-aa680ddf` 为同产品代码的历史运行器产物，因 provenance 写入路径缺陷后以 `round4-full-50415119` 重跑；本报告不引用其手工补齐证据作为正式结论。
- **Docker 开发候选：`NO_GO_FOR_DOCKER_QUALIFIED_CANDIDATE`**（15 行未闭合：13 FAIL + 1 BLOCKED + 1 GO_ONLY）。
- **正式发布：`RELEASE_AUTHORIZED = NO`**（缺批准与生产边界验证）。
