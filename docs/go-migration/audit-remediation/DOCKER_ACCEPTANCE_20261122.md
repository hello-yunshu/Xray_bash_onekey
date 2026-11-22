# 第三轮缺陷整改与最终验收（Docker 审计）— 2026-11-22

- 分支：`work/go-hardening-parity-20261119`
- 候选代码提交：`99997da0f8772a814a61c32516d49d75a9de2672`（产品代码冻结）；审计基线：`28463d4f`
- 环境：Go 1.27.4（vendored、离线）、`idleleo-e2e:24.04` / `idleleo-e2e:debian12`、`nginx:1.27`、真实 systemd 容器、真实根目录 `/`
- 结论：**NO-GO**。全部 34 项 OPS 已有本轮证据，20 项双端等价；8 项行为差异未获外部批准、5 项仅 Go 侧、1 项 Bash-only，不能宣称“34 项全部双端验证”。

## 1. 本轮真正修改的产品代码

本轮优先修改产品缺陷，不以新增测试证据或修改验收报告代替修复。

### P0-1 证书清理动态路径漏扫与越权删除

`internal/deploy/certclear.go`

- `ssl_certificate*` / `include` 指令解析允许跨行空白，动态变量路径（`$`、`{}`）不再被静默跳过，而是整次扫描 fail-closed。
- include 深度超过 `maxScanDepth`、glob 零匹配、`WalkDir` 出错、受管 Nginx 已安装但主配置缺失、Xray 配置不可读，均视为扫描不完整；不完整时拒绝删除。
- 删除所有权只认“内容哈希绑定的 `.managed-by-idleleo` 记录”（`sha256=`）。文件名、域名、所在目录、目录 marker 本身都不再构成所有权证明。
- 目录只有在内部每个常规文件都被各自目录的哈希记录绑定、且没有任何有效配置引用时才整体删除；存在软链、特殊文件、未知所有权或引用时整目录保留。
- ACME 状态（`~/.acme.sh/<domain>_ecc`）仅在 `<domain>.cer` 的叶证书 DER SHA-256 与“本轮计划删除的项目证书”完全一致时删除；账户、CA、用户管理证书、不匹配状态一律保留并逐目录记录。

`internal/acme/acme.go`

- `markManaged` 写入 `managed-by=idleleo` 以及 cert/key 两条内容哈希，作为后续清理的所有权依据；签发成功后调用。

### P0-2 SNI Guard 运行态不可信

`internal/deploy/guard.go`

- `active` 需要同时满足：`/proc/<pid>/exe` 身份匹配受管 Nginx、进程存活、进程启动时间晚于所有策略文件 mtime，或存在内容指纹匹配的 reload 记录。
- 否则降级为 `configured` / `runtime-unverified` / `drift`，不再把“文件写好了”当成“运行态已生效”。
- `MetadataSynced` 只有在 enabled/策略/decoy 全部一致时才为 true，所有 drift 分支均为 false。

### D10 XHTTP 路径 Unicode 空白

`internal/xraycfg/edit.go`、`internal/xraycfg/xraycfg.go`

- 安装、生成、编辑、分享导入共用 `ValidateXHTTPPath`：空串、任意 Unicode 空白、控制字符一律拒绝；`normalizeXHTTPPath` 不再 `TrimSpace`。

### OPS-03 shortId 删除语义

`internal/xraycfg/users.go`、`internal/cli/xray.go`

- 删除用户后，若 inbound 级 `shortIds` 非空，输出明确说明：shortId 不可归属、全部保留，可用 `xray edit --short-id-remove` 显式清理。行为本身未改变，差异未被掩盖。

## 2. 验收账本加固（build_ledger.py）

旧账本的问题：吞掉 FAIL、把 DIFF 当通过、接受没有退出码或没有 `ops.json` 的不完整证据。本轮修复：

- `FAIL/MISMATCH/GAP/DIFF/ERROR` 永远为 FAIL，优先级最高。
- `EXPECTED_DIFF/ALLOWED_DIFF` 必须由外部批准文件（含 `approvedBy`、`reason`）命名，否则为 FAIL；获批也只记为 `APPROVED_DIFF`，不记为双端等价。
- `PASS` 但任一侧退出码非零 → FAIL；双端 `PASS` 缺退出码 → BLOCKED。
- 目录缺 `ops.json` 时，读取 `shortid-difference.json` 等“已声明差异”文件；已声明差异不再消失，未批准即 FAIL。
- sweep 证据必须有可读 `assertions.txt`、行格式合法且至少一条 OPS 断言，否则拒绝。
- 有 FAIL 返回 1；严格模式下存在非双端行返回 2；`--allow-incomplete` 只能显式放宽返回码，不能改变分类。

契约测试：`python3 tests/e2e-diff/collect/test_build_ledger.py -q` → **14/14 OK**。

## 3. 真实环境回归证据（全部绑定候选 `99997da0`）

| 证据 | 路径 | 结果 |
| --- | --- | --- |
| Go 门禁（golang:1.27.4） | 容器内 `gofmt -l ./cmd ./internal`、`go vet ./...`、`go build ./cmd/idleleo ./cmd/idleleo-recover`、`go test -count=1 ./...`、`CGO_ENABLED=1 go test -race -count=1 ./internal/...` | 全部通过（ALL-OK） |
| 全量双端矩阵 M1–M10 / E1–E8 / OPS | `tests/e2e-diff/evidence/round3-final-20261122-99997da0/p2` | 已完成；OPS 逐行 verdict 已入账 |
| OPS-32 故障摘除（480 突发 / 120 稳态，0.5s） | `tests/e2e-diff/evidence/round3-final-20261122-99997da0-ops32b/p2/OPS-32` | ws / reality 两个 upstream 均 PASS；每 worker 2–3 次失败、稳定恢复 |
| OPS-09/19/21/31 双端退出码补齐 | `tests/e2e-diff/evidence/round3-final-20261122-99997da0-opsrc/p2` | 4 行全部 PASS，`opsRc` 均为 0/0 |
| R1/R2 接管（M1/M4，双端） | `tests/e2e-diff/evidence/round3-final-20261122-99997da0-r1b/r1` | 104 PASS；2 条 I4 断言因夹具缺离线 Nginx 缓存误判 |
| M4 故障注入（I1/I2/I4，含只读拒绝与恢复日志） | `tests/e2e-diff/evidence/round3-final-20261122-99997da0-injfix/r1` | 26 PASS / 0 FAIL（修复夹具后重跑，覆盖并取代上条中的 2 条失败） |
| Go CLI OPS sweep（真实安装 + 真实网络） | `tests/e2e-diff/evidence/round3-final-20261122-99997da0-sweep2/assertions.txt` | 57 PASS / 0 FAIL |
| 真实根 Nginx（OPS-08/17b/27） | `tests/e2e-diff/evidence/round3-final-20261122-99997da0-realroot/realroot/assertions.txt` | 26 PASS / 0 FAIL |
| P3 热更新 | `tests/e2e-diff/evidence/goevo-p3-round3-final-20261122-99997da0` | 62 PASS / 0 FAIL，`RESULT: PASS` |
| S 系列脚本 / ACME | `tests/e2e-diff/evidence/round3-final-20261122-99997da0/s/assertions.txt` | 64 PASS / 0 FAIL（含 Pebble 续期成功与失败回滚） |
| Xray 多版本 | `tests/e2e-diff/evidence/round3-final-20261122-99997da0/versions/run.log` | v26.11.9 / v26.10.31 / v26.10.21 三版本 config+deploy 全 PASS |
| 第二发行版 Debian 12 | `tests/e2e-diff/evidence/round3-final-20261122-99997da0-deb12/p2` | M1/M4 双端 round1+round2 `install_exit=0` |
| Soak ≥1800s | `tests/e2e-diff/evidence/round3-soak-20261122/soak/run.log` | 31/31，elapsed=1870s，client_ok=31 / fail=0，RSS 16–19 MiB，timer active runs=2 |
| 冷恢复（reality/TLS/relay/multi） | `tests/e2e-diff/evidence/goevo-coldrestore-round3-d09{a,e,f,h}-20261122-*` | 全部 `RESULT: PASS`（21/0、21/0、15/0、23/0） |
| 故障注入套件 | `tests/e2e-diff/evidence/round3-inj2-20261122/r1/assertions.txt` | 42 PASS / 0 FAIL |

说明：证书清理驱动用例本轮修正了夹具——`unused-pair`、`invalid-nginx-refuse`、`rollback-fault` 三个场景必须像产品一样写入内容哈希所有权记录，否则在保守模型下“无所有权即保留”是正确行为。该修改是使夹具符合新的所有权契约，不是放宽断言。R1 夹具补充了与全量矩阵一致的离线 Nginx/模板缓存，避免网络超时把接管回归误判为失败；断言本身未放宽。

## 4. 账本结果（唯一事实来源）

来源：`tests/e2e-diff/ledger.json`（由 `build_ledger.py` 从上述真实证据生成）

| 状态 | 数量 | 行 |
| --- | --- | --- |
| DUAL_SIDE_VERIFIED | 20 | OPS-01/02/04/05/06/07/08/09/10/11/15/17c/19/20/21/22/28/29/31/32 |
| GO_ONLY | 5 | OPS-17a/17b/18/23/24 |
| FAIL | 8 | OPS-03/12/13/14/16/25/26/27（已声明差异，未获外部批准） |
| BASH_ONLY | 1 | OPS-30 |
| BLOCKED | 0 | 无 |
| APPROVED_DIFF | 0 | 无外部批准文件 |
| NOT_RUN | 0 | 分母保持 34，未缩减 |

严格模式退出码为 1（存在 FAIL 行）；`--allow-incomplete` 仅放宽返回码，不改变分类。

## 5. 未完成与未批准事项（保持 NO-GO）

1. **OPS-03 shortId 差异未获批准**：Bash 删除其生成的短 ID，Go 因 inbound 级不可归属而保留。需要产品负责人明确是否允许。
2. **OPS-27 双端不等价**：Bash 菜单“清空证书文件”（`install.sh` action 37）执行 `rm -rf "$ssl_chainpath"/*`，整目录删除且无所有权证明；Go 仅在能证明所有权时删除。这是本轮安全加固的预期差异，**未自行批准**。
3. **OPS-12/13/14/16/25/26 已声明差异未获批准**：日志查看（`tail -f` vs 有限 journal）、流量视图（iftop vs `stats`）、证书续期入口（菜单 vs `renew --dry-run`）、备份导出（tar vs metadata JSON）等人机交互/输出格式差异，需要产品负责人逐项确认。
4. **OPS-17a/17b/18/23/24 仅 Go 侧证据**：OPS-17a 需要公共发布清单、OPS-17b 需要固定本地包、OPS-18 的 BBR 状态属于宿主内核、OPS-23/24 依赖真实外部下载；隔离容器无法双端复现。Go 侧行为已验证，Bash 侧本轮有真实菜单尝试记录（rc=124/不可达），未记为通过。
5. **OPS-30 为 Bash-only**：契约本身为 `bash-only`，Go 无对应入口。
6. 未合并、未打 tag、未正式发布、未操作任何生产 VPS。

## 6. 最终结论

- 两个 P0 证书安全问题与 Guard 运行态问题已在真实 Docker 环境中修复并通过回归。
- 验收账本不再吞掉失败、不再忽略已声明差异、不再接受不完整证据；34 项 OPS 均有本轮证据，无 BLOCKED / NOT_RUN。
- 但仍有 8 项未获批准的行为差异、5 项仅 Go 侧证据、1 项 Bash-only，不能宣称“34 项全部双端等价”。
- 因此本轮候选版本 **不得发布**，结论为 **NO-GO**；需产品负责人批准上述差异或补齐双端证据后才能转为 GO。

## 7. 独立复审 D01–D10 逐条处置

| ID | 复审问题 | 处置 | 证据 |
| --- | --- | --- | --- |
| D01 | 证书清理漏扫动态变量路径 | `ssl_certificate*`/`include` 跨行解析；含 `$`/`{}` 时整次扫描 fail-closed | `internal/deploy/certclear.go`；realroot `OPS-27 variable-path` PASS |
| D02 | ACME 状态误归属 | 仅当 `<domain>.cer` 叶证书 DER SHA-256 与本轮删除项目证书一致才删状态 | `internal/deploy/certclear.go`、`internal/acme/acme.go`；realroot 26/0 |
| D03 | 目录 marker/递归/扫描错误 | 所有权只认内容哈希绑定记录；目录需逐文件绑定且无有效引用才整体删除 | realroot `OPS-27 inline-multi/external-include/symlink-alias/xray-second-config/unused-pair` 全 PASS |
| D04 | Guard 运行态不可信 | `active` 需进程身份、存活、启动时间晚于策略文件或内容指纹 reload 记录 | `internal/deploy/guard.go`；realroot `OPS-08` 六个场景 PASS |
| D05 | 账本吞掉失败 | FAIL/非零退出码/矛盾证据优先；严格模式返回 1/2，分类不可被 `--allow-incomplete` 改变 | `tests/e2e-diff/collect/build_ledger.py`；14/14 契约测试 |
| D06 | 证据完整性被忽略 | `PASS` 缺双端退出码→BLOCKED；差异声明文件不消失；sweep 断言格式非法即拒绝 | 本轮 OPS-09/19/21/31/32 补 `opsRc` 后转为 DUAL；`round3-final-...-opsrc`、`...-ops32b` |
| D07 | 剩余 OPS 未双端 | 补跑 34 行；20 项双端等价，8 项差异待批准，5 项仅 Go，1 项 Bash-only，0 BLOCKED | `tests/e2e-diff/ledger.json` |
| D08 | M8 场景描述错误 | 修正为 Go ACME 签发 + `--transport ws`，与 M1/M4 区分 | `tests/e2e-diff/matrix.json` M8 |
| D09 | SHA 绑定不足 | 账本记录 `codeSha=99997da0…`；所有证据 runId 与冻结候选绑定 | `tests/e2e-diff/ledger.json`；p3 日志 `commit=99997da0…` |
| D10 | XHTTP 路径 Unicode 空白被接受 | 区分“未提供”与“空白”，空白拒绝 | `internal/xraycfg` 测试；S/P3 回归通过 |


