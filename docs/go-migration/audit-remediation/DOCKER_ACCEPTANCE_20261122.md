# 第三轮缺陷整改与最终验收（Docker 审计）— 2026-11-22

- 分支：`work/go-hardening-parity-20261119`
- 候选代码提交：`64aed994`（本轮产品修改与证据）；审计基线：`28463d4f`
- 环境：Go 1.27.4（vendored、离线）、`idleleo-e2e:24.04`、`nginx:1.27`、真实 systemd 容器、真实根目录 `/`
- 结论：**NO-GO**。产品缺陷已修复并有真实环境证据，但验收账本仍未达到“全部 OPS 双端验证”，且存在一项未获批准的行为差异。

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

契约测试：`python3 tests/e2e-diff/collect/test_build_ledger.py -q` → **13/13 OK**。

## 3. 真实环境回归证据

| 证据 | 路径 | 结果 |
| --- | --- | --- |
| Go 全量 vet/build/test（golang:1.27.4） | 容器内 `go vet ./...`、`go build ./cmd/idleleo ./cmd/idleleo-recover`、`go test ./... -count=1` | 全部通过；此后再无 Go 代码修改 |
| Go CLI OPS sweep（真实 Go 安装 + 真实网络 origin） | `tests/e2e-diff/evidence/round3-fix-20261122-1742/assertions.txt` | 51 PASS / 0 FAIL |
| 真实根 Nginx（OPS-17b/08/27） | `tests/e2e-diff/evidence/round3-fix-20261122-realroot2/realroot/assertions.txt` | 26 PASS / 0 FAIL |
| 证书清理 10 个真实根场景 | 同上 `ops/OPS-27.log` | 全部 PASS（含动态变量、外部 include、软链、用户管理、第三方 canary、配置损坏、非法配置拒绝、回滚注入） |
| Guard 真实 Nginx 场景 | 同上 `ops/OPS-08.log` | 全部 PASS（configured/active/缺失/不可读/拒绝） |

说明：证书清理驱动用例本轮修正了夹具——`unused-pair`、`invalid-nginx-refuse`、`rollback-fault` 三个场景必须像产品一样写入内容哈希所有权记录，否则在保守模型下“无所有权即保留”是正确行为。该修改是使夹具符合新的所有权契约，不是放宽断言。

## 4. 账本结果（唯一事实来源）

来源：`tests/e2e-diff/ledger.json`（由 `build_ledger.py` 生成）

| 状态 | 数量 | 行 |
| --- | --- | --- |
| DUAL_SIDE_VERIFIED | 8 | OPS-01/02/04/05/06/07/10/17c |
| GO_ONLY | 19 | 其余仅有 Go 侧证据的行（含 OPS-08/17b/27） |
| FAIL | 1 | OPS-03（shortId 差异，未获外部批准） |
| BASH_ONLY | 1 | OPS-30 |
| BLOCKED | 5 | OPS-09/19/21/31/32（`ops.json` 声明 PASS 但无任何退出码，属不完整证据） |
| APPROVED_DIFF | 0 | 无 |
| NOT_RUN | 0 | 分母保持 34，未缩减 |

严格模式退出码为 1（存在 FAIL 行）。

## 5. 未完成与未批准事项（保持 NO-GO）

1. **OPS-03 shortId 差异未获批准**：Bash 删除其生成的短 ID，Go 因 inbound 级不可归属而保留。本轮只增加说明，未擅自批准差异。需要产品负责人明确是否允许。
2. **OPS-27 双端不等价**：Bash 菜单“清空证书文件”（`install.sh` action 37）执行 `rm -rf "$ssl_chainpath"/*`，整目录删除且无所有权证明；Go 仅在能证明所有权时删除。这是本轮安全加固的预期差异，本轮**未自行批准**，OPS-27 仅记为 Go 侧证据。
3. **OPS-09/19/21/31/32**：旧证据只有 `verdict=PASS`、没有双端退出码，新账本按不完整证据记为 BLOCKED，需重跑补齐。
4. **完整 34 项 OPS 双端对照未在本轮完成**：本轮只重跑了受修改影响的 Go 侧与真实根场景；未受影响的历史双端证据继续沿用。
5. **Phase 3 冻结后统一回归未覆盖**：冷恢复、soak 1800s、多 Xray 版本、第二发行版、S 系列脚本、迁移/接管等未在本轮重跑。历史上通过不等于本轮候选通过。
6. 未合并、未打 tag、未正式发布、未操作任何生产 VPS。

## 6. 最终结论

- 两个 P0 证书安全问题与 Guard 运行态问题已在真实 Docker 环境中修复并通过回归。
- 验收账本不再吞掉失败、不再忽略已声明差异、不再接受不完整证据。
- 但 34 项 OPS 中仍有 1 项 FAIL、5 项 BLOCKED、19 项仅 Go 侧证据，且存在一项未获批准的行为差异。
- 因此本轮候选版本 **不得发布**，结论为 **NO-GO**。
