# 第三阶段：低中断用户管理试点与最终资格审查

- 分支：`work/go-evolution-audit-20261118`（未合并 `main`，未打 tag，未发布）
- 基线：`develop/go-native` = `d4858a1150d3f83202e95aa9dfea2244832c8b3e`
- 本阶段代码提交：`2d9a27af`（repair/doctor 权限与锁）、`d8950cd7`（热用户与运维摘要）
- 实跑时间：2026-11-19，镜像 `idleleo-e2e:24.04`，证据 run.json 记录 commit `46457193`，Xray `26.10.31 a4a3dff`（go1.27.3）
- 证据目录：
  - `tests/e2e-diff/evidence/goevo-p3-p3-final-015931/`：热用户/修复/摘要实机套件（60 pass / 0 fail）
  - `tests/e2e-diff/evidence/p3-edits/p2/`：E1–E8 编辑回归（E1–E4 PASS，E5–E8 因无外网 BLOCKED）
  - `tests/e2e-diff/evidence/goevo-p3-final-matrix/`：全矩阵重跑尝试（被宿主无外网阻断，仅保留失败轨迹）

## 1. 结论

1. **默认能力与实验能力已分层**。`xray user add/remove` 的默认路径仍是“提交配置 + 受控重启”；只有显式 `--experimental-hot` 才走 Xray API 热应用。未验证的 UUID 轮换、shortId、Reality 私钥、端口、传输仍只走稳定事务。
2. **两个事实源收敛可复现**。持久化配置先写、后应用；API 未启用时退出码 `8`，报告 `persisted=true / applied=false`，配置已含新用户；启用 API 后重试以 `persisted=false / applied=true` 收敛，且配置 SHA-256 不变。
3. **真实客户端证据有界但完整**：新增用户能连通本地 origin；删除用户后新连接被服务端拒绝（客户端 curl rc=7）；删除前已建立的慢连接正常完成；其余用户（B）在删除、重启、修复重启后均保持可连通；并发两个热加都成功；进程重启后配置与内存一致。
4. **实机故障注入发现并修复一个真实回归**：`repair` 把运行配置改成 `0600 root:root`、conf 目录 `0750 root:root`，下次重启 xray 用户读不到配置。修复为 `0640` + 组 `xray`，并新增 `doctor` 的 `service-access` 检查（以服务账户实际 `test -r`），不再以“服务当前 active”掩盖未来启动失败。
5. **运维摘要只读、无新增常驻组件**：`ops summary` 复用 status/journal/systemd 输出端口、证书到期、最近变更、近期失败与重启次数，不引入数据库、守护进程或 Web。
6. **发布资格：NO-GO（对正式发布）**。F01–F28 账本仍为 28 项 `PENDING_GO_IMPLEMENTATION`，`check_release_gate.py` 输出 `RELEASE BLOCKED: pending 28; missing executable feature tests 0; JSON statuses alone never grant success`（rc=2）；受保护 CI 与真实 VPS/VM 证据当前不可得，按规则保持 PENDING，未通过“改状态”规避。

## 2. 环境与真实性

| 项 | 事实 |
|---|---|
| 宿主机 | macOS arm64，无 Go 工具链 |
| 构建 | `golang:1.27.4`，`CGO_ENABLED=0 GOFLAGS='-mod=vendor -buildvcs=false' GOPROXY=off` |
| 单元测试 | `gofmt -l` 无输出；`go vet ./cmd/... ./internal/...` 通过；`go test ./internal/... ./cmd/...` 全部通过 |
| 实机 | `idleleo-e2e:24.04`：systemd、真实 Xray、openssl、iproute2 |
| 安装 | 容器内 `idleleo xray install --mode reality --domain www.cloudflare.com --target 127.0.0.1:8443 --port 443 --container`，`install_rc=0` |
| 写入契约 | `IDLELEO_ALLOW_SYSTEM_WRITES=I_ACCEPT_CONTAINER_ONLY` + `--container`，只写一次性容器 |
| 证据卫生 | `check_evidence_hygiene.py`：P3 套件 0 findings / 62 files；编辑回归 0 findings / 423 files；无 UUID 明文（驱动内置脱敏） |
| 外网 | 本次运行容器**无外网**：宿主机 DNS 把 `ip.me` 等解析到 `198.18.x`，容器内 `curl`/`Get` 均 `network is unreachable` |

单元测试与实机都针对**当前提交构建出的二进制**（证据 run.json 的 `commit` 为 `46457193`，包含 `2d9a27af` + `d8950cd7` 的全部代码）。

## 3. 实验性热用户变更（G06）

### 3.1 语义与顺序

| 项 | 实现 |
|---|---|
| opt-in | `--experimental-hot`；未给出时行为与之前完全一致 |
| 真相源 | `/etc/idleleo/conf/xray/config.json`（经 `internal/change` 原子事务、备份、锁） |
| 顺序 | ① 提交配置（含校验、备份、回滚）→ ② 读取新配置定位 API → ③ `xray api adu/rmu` → ④ 轮询 `inbounduser` 确认 |
| API 未启用 | 热应用失败，退出码 `8`，`persisted=true/applied=false`，配置不回滚（用户已持久化，重启即生效） |
| 半失败重试 | 若目标用户已与期望一致，视为成功；重试不重写配置（`persisted=false/applied=true`） |
| 并发 | 热操作持有 `run/lock/idleleo-hot.lock`，最多等待 15s；并发加用户不会交叉写 |
| 崩溃恢复 | 配置先落盘；E2b 在“持久化后、应用前”SIGKILL，重启后同一凭据可用 |
| 退出码 | `8` 热应用半失败；`22` 锁冲突；其余沿用既有码 |

### 3.2 实机断言（60/60 PASS）

| 段 | 证据 | 结果 |
|---|---|---|
| E1 | `xray api status` 未启用；`configured=false` | PASS |
| E2 | 无 API 热加 B：rc=8，配置已含 B，`applied=false` | PASS |
| E2b | 崩溃恢复：未应用的 B 在运行态被拒；SIGKILL 后重启，同一 B 凭据连通 | PASS |
| E3 | `xray api enable`：`changed=true/reachable=true`，仅一个 api inbound，xray active，`api lsi` 可达 | PASS |
| E4 | 重试收敛：rc=0，`persisted=false/applied=true`，配置 SHA 不变，运行态含 B | PASS |
| E5 | 真实客户端 B 经 VLESS+Reality 取到 `hot-ok-fast` | PASS |
| E6/E7 | 热加 A；A 真实连通；挂起一个 6s 慢请求 | PASS |
| E8 | 热删 A：配置与运行态均无 A；慢请求仍返回 `hot-ok-slow`；B 仍连通；A 凭据的新连接被拒（rc=7） | PASS |
| E9 | 重启后 B 仍通、A 仍不存在、配置 SHA 不变 | PASS |
| E10 | 并发热加 C/D 均 rc=0，配置与运行态都有 | PASS |
| E11 | 权限回归：`doctor` rc=1 且 `service-access` fail；`repair` rc=0 后 `0640`、组 `xray`、重启 active、B 真连 | PASS |
| E12 | `ops summary --json`/文本：主端口、10085、lastChange、restartCount | PASS |
| E13 | 最终 `doctor` rc=0 | PASS |

**不宣称“零中断”**：证据只覆盖“Reality + VLESS + HandlerService 的用户 add/remove”在 Xray 26.10.31 上的有界行为。其他协议、UUID 轮换、shortId、Reality 密钥、端口、传输仍会重启。

### 3.3 测试环境约束（非产品缺陷）

1. **Reality target 必须支持 X25519MLKEM768**。Xray 26 与 target 握手时优先该组；OpenSSL/Python 只提供 X25519 时服务端报 `REALITY: hs.handshake() err: payload[0]: 8, padding: -4`。测试因此使用 Go 1.27 的最小 TLS 1.3 origin（`tests/e2e-diff/drivers/p3_tls_target.go`）。
2. **freedom 出站会黑洞回环/私网目标**（`proxy/freedom: blocked target: …, blackholing connection`）。测试把“公网外观地址”`1.2.3.4/32` 绑到 `lo`，origin 绑 `0.0.0.0`，使数据面真实经过本地链路。

这两条只影响本地化测试拓扑，不改变产品行为。

## 4. 运维摘要（G07）

`idleleo ops summary [--json]` 输出：

- `status`：复用 `status` 的只读报告；
- `ports`：运行配置中的监听端口/协议/监听地址/tag；
- `certificate`：路径、是否存在、`notAfter`、剩余天数、SAN；
- `lastChange`：journal 最近一条变更；
- `recentFailures`：journal 中近期失败记录；
- `restartCount`：由 journal/服务状态推导。

实现约束：纯读、无写盘、无新数据库/守护进程/Web。journal 同时兼容整文件 JSON 数组（当前真实格式）与历史 JSONL。

### 4.1 复用与去重（C2）

| 重复点 | 处理 |
|---|---|
| `repair` 与 `doctor` 各自用锁文件 mtime 判断“更新中” | 统一为 `host.LockHeld` 的真实 `flock` 探测，两个命令共用一套语义 |
| `change.Journal.Record` 与 `ops` 各自解析 journal | 新增 `change.Journal.Read`，写入与读取共用同一解码器；`ops` 只做薄封装 |
| 状态、证书、端口、journal、systemd 各自读取 | `ops.Summary` 复用 `app.Status` 与 `change.Journal`，仅新增只读投影 |
| 资源探测 | 未新增后台探测；`ops summary` 每次按需读取，无缓存进程 |

没有做未经测量的性能承诺：本阶段未引入基准测试，因此不宣称 CPU/内存改善。

## 5. 本轮修复的问题

| 问题 | 影响 | 修复 |
|---|---|---|
| repair 把运行配置收紧为 `0600 root:root`、conf 目录 `0750 root:root` | 下次 `systemctl restart xray` 失败（服务账户读不到配置），且当时 `doctor` 仍报健康 | 配置 `0640`，conf 与配置文件组对齐 `xray`；新增 `service-access` 检查，以 xray 身份 `test -r` 配置并 `test -x` conf |
| `repair`/`doctor` 仅凭锁文件 mtime 判断“更新锁被持有” | 任何刚完成的变更都会被误报 | 改用真实 `flock` 探测（`host.LockHeld`）；未持有且文件陈旧 → stale warn；`repair --fix-lock` 可清理 |
| `ops summary --json` 被 `cli.go` 少传一级子命令 | 输出帮助并 rc=2 | 传完整 args |
| 并发热加第二个请求直接失败 | 并发用户变更不可用 | 新增 `host.AcquireUpdateWait`，热路径等待 15s |
| 热加用户 flow 取首用户而非目标用户 | 运行态与配置可能不一致 | `hotuser.Add` 使用目标用户的 flow/level |
| `adu` 对已存在用户返回非 0 | 半失败重试无法收敛 | 失败后比对 `Lookup`，已一致即成功 |
| journal 按 JSONL 解析真实 JSON 数组失败 | 摘要缺 lastChange | 先整体解析数组，再回退 JSONL |

## 6. 完整回归与资格状态

### 6.1 今日实跑

| 维度 | 结果 | 说明 |
|---|---|---|
| P3 热用户/修复/摘要套件 | **60 PASS / 0 FAIL** | `goevo-p3-p3-final-015931` |
| E1–E4（配置编辑：UUID/端口/target/serverNames） | **PASS** | `p3-edits/p2`，`allPassed=true` |
| E5/E6（TLS 证书编辑，Nginx 前置） | **BLOCKED** | TLS 安装需下载受管 Nginx 构件，容器无外网 |
| E7/E8（shortId 自动、Reality 私钥轮换） | **BLOCKED** | 编辑前的真实 Reality 客户端需外部 target，容器无外网 |
| M1–M10 双端全矩阵 | **BLOCKED（本次）** | Bash 安装需 `ip.me` 公网 IP 与 GeoData 下载；容器 DNS 黑洞 |
| Go 单元/集成测试 | **PASS** | 全包 `go test` 通过；gofmt/vet 干净 |
| 证据卫生 | **PASS** | 0 findings |

全矩阵重跑尝试保留在 `goevo-p3-final-matrix/`：M1–M3 的 Bash 侧安装以 `[错误] 无法获取公网IP地址, 安装终止!` 结束，Go 侧 TLS 安装报 `Nginx build version unavailable: … network is unreachable`。这是**环境故障**，按规则记录为 BLOCKED，不当作产品 FAIL，也不把旧证据冒充成本次复跑。

### 6.2 沿用证据（同分支、较早提交）

`tests/e2e-diff/evidence/20261118-0605-full`（commit `47a370e5`）记录：M1–M10 双端 `rc=0`、L4 两轮真实客户端通过、L6 幂等通过；E1–E8 全部 PASS；OPS-09/19/21/31/32 PASS。该证据早于本阶段提交，但本阶段未改动安装器、Reality/TLS/relay 生成逻辑；改动集中在 `xray user add/remove`、`repair`、`doctor`、`ops`。

### 6.3 账本与门禁

- `feature_contracts.json`：28 项仍为 `PENDING_GO_IMPLEMENTATION`，**未修改**。
- `check_release_gate.py`：`RELEASE BLOCKED: pending 28; missing executable feature tests 0; JSON statuses alone never grant success`（rc=2）。
- 原因：规则要求受保护 CI 与真实 VPS/VM 证据；当前环境无法提供，保持 PENDING。
- 未执行：合并 `main`、打 tag、发布 Release、改生产机器。

### 6.4 CI、隐私、依赖与夹具扫描（C3）

| 项 | 结果 | 证据与说明 |
|---|---|---|
| CI 回归 | PASS（本地等价）/ NOT_RUN（远程与 stage gate） | 本地等价全绿：`check_evidence_hygiene.py --mask .` 0 findings/14360 文件；`test_ledger_transition.py` 17 tests OK；A2 比较器 `SELFTEST_PASS mutations=14 baseline=MATCH`；`gofmt`/`go vet`/全库 `go test`/`go build` 通过。分支未推送，远程受保护 CI 无运行；需要 `legacy` 检出的 stage gate 未跑 |
| 隐私 | PASS（本阶段） | 证据卫生扫描 0 findings；驱动对 UUID 脱敏；未提交私钥或证书（Reality target 证书运行时生成、随容器销毁）；未写入宿主公网 IP 或个人路径 |
| 依赖许可 | PASS | `go.mod`/`go.sum` 相对基线未变，未新增 vendor 代码 |
| 夹具可重复性 | PASS（离线场景）/ BLOCKED（外网场景） | `run_p3_hot.sh` 每次从源码构建、生成新 UUID/密钥与自签 origin，不依赖外部 target；依赖外网的 M1–M10/E5–E8 标 BLOCKED |
| 文档与命令示例 | PASS | 帮助文本已加入 `ops summary`、`xray api status\|enable`、`--experimental-hot`；本报告命令可直接复演 |

未覆盖清单（如实记录）：断电/极端退出仅以重启与半失败重试近似，未做真实断电；bridge（Bash→Go 迁移）沿用 P1/P2 证据，本次未复跑；并发仅测两路；IPv6 未覆盖。

## 7. GO/NO-GO 建议

- **正式发布：NO-GO**。28 项契约未签收，缺少受保护 CI 与真实节点证据；M1–M10/E5–E8 今日未能复跑。
- **保留实验能力：GO（带标记）**。热用户变更默认关闭，仅在 `--experimental-hot` 下可用；默认路径不变。
- **默认能力：GO（有界）**。repair/doctor 的权限回归已修复并有实机证据；`ops summary` 只读。
- **剩余风险**：
  1. 外部网络恢复后需重跑 M1–M10 与 E5–E8，确认 TLS/ACME/relay 未被本阶段改动影响（预期无影响）。
  2. 热变更只对 Reality+VLESS 用户增删给出证据；其他协议与密钥轮换不承诺低中断。
  3. 真实 VPS 上的 systemd/journald、证书续期与断电场景仍未取证。
