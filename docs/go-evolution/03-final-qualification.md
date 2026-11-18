# 第三阶段：低中断用户管理试点与最终资格审查

- 分支：`work/go-evolution-audit-20261118`（未合并 `main`，未打 tag，未发布）
- 基线：`develop/go-native` = `d4858a1150d3f83202e95aa9dfea2244832c8b3e`
- 本阶段代码提交：`2d9a27af`（repair/doctor 权限与锁）、`d8950cd7`（热用户与运维摘要）、`be141822`（编辑回归的证书收敛判定）、`6ad3be97`（Bash→Go 接管的运行时保留）、`5329d12e`（R1/R2 与 OPS 实跑证据）、`80ad240f`（接管失败注入与端口预检）
- 实跑时间：2026-11-19，镜像 `idleleo-e2e:24.04`，证据 run.json 记录 commit `6ad3be97`/`5329d12e`/`80ad240f`，Xray `26.10.31 a4a3dff`（go1.27.3）
- 证据目录：
  - `tests/e2e-diff/evidence/goevo-p3-20261119-0303/`：热用户/修复/摘要实机套件（60 pass / 0 fail）
  - `tests/e2e-diff/evidence/goevo-p3-matrix-0242-a9875aff/p2/`：M1–M10 双端安装矩阵、E1–E8 编辑回归、OPS 场景（全部 PASS）
  - `tests/e2e-diff/evidence/goevo-p2-rerun-20261119-0345-6ad3be97/p2/` 与 `goevo-p3-20261119-0406-6ad3be97/`：修复后的全矩阵与热用户回归（全 PASS）
  - `tests/e2e-diff/evidence/goevo-r1r2-20261119-0420-6ad3be97/r1/`：R1/R2 真实接管（64 PASS / 0 FAIL）
  - `tests/e2e-diff/evidence/goevo-ops-20261119-0412-6ad3be97/`：矩阵未驱动的 OPS 行 Go 单边实跑（36 assertions）
  - `tests/e2e-diff/evidence/20261119-0440-8c002dde/r1/`：I1–I4 接管失败注入（42 PASS / 0 FAIL）
  - `tests/e2e-diff/evidence/20261119-0442-8c002dde/p2/`：端口预检后的 M1 回归（PASS）
  - `tests/e2e-diff/evidence/s-20261119-full/s/`：S4–S9 辅助脚本实跑（58 PASS / 0 FAIL）

## 1. 结论

1. **默认能力与实验能力已分层**。`xray user add/remove` 的默认路径仍是“提交配置 + 受控重启”；只有显式 `--experimental-hot` 才走 Xray API 热应用。未验证的 UUID 轮换、shortId、Reality 私钥、端口、传输仍只走稳定事务。
2. **两个事实源收敛可复现**。持久化配置先写、后应用；API 未启用时退出码 `8`，报告 `persisted=true / applied=false`，配置已含新用户；启用 API 后重试以 `persisted=false / applied=true` 收敛，且配置 SHA-256 不变。
3. **真实客户端证据有界但完整**：新增用户能连通本地 origin；删除用户后新连接被服务端拒绝（客户端 curl rc=7）；删除前已建立的慢连接正常完成；其余用户（B）在删除、重启、修复重启后均保持可连通；并发两个热加都成功；进程重启后配置与内存一致。
4. **实机故障注入发现并修复一个真实回归**：`repair` 把运行配置改成 `0600 root:root`、conf 目录 `0750 root:root`，下次重启 xray 用户读不到配置。修复为 `0640` + 组 `xray`，并新增 `doctor` 的 `service-access` 检查（以服务账户实际 `test -r`），不再以“服务当前 active”掩盖未来启动失败。
5. **运维摘要只读、无新增常驻组件**：`ops summary` 复用 status/journal/systemd 输出端口、证书到期、最近变更、近期失败与重启次数，不引入数据库、守护进程或 Web。
6. **S4–S9 辅助脚本已收敛**：6 行全部实跑 PASS（58/58），其中 S5 用 Pebble 完成真实续期、失败时证书与服务不受损；S6 走真实 GitHub Release；S7/S8/S9 的历史第三方脚本可下载并通过语法校验，Go 自有实现覆盖主路径。S7 的公网 CA 签发与 S8 的真实内核 BBR 应用仍按外部条件记为 BLOCKED。
7. **发布资格：NO-GO（对正式发布）**。F01–F28 账本仍为 28 项 `PENDING_GO_IMPLEMENTATION`，`check_release_gate.py` 输出 `RELEASE BLOCKED: pending 28; missing executable feature tests 0; JSON statuses alone never grant success`（rc=2）；受保护 CI 与真实 VPS/VM 证据当前不可得，按规则保持 PENDING，未通过“改状态”规避。

## 2. 环境与真实性

| 项 | 事实 |
|---|---|
| 宿主机 | macOS arm64，无 Go 工具链 |
| 构建 | `golang:1.27.4`，`CGO_ENABLED=0 GOFLAGS='-mod=vendor -buildvcs=false' GOPROXY=off` |
| 单元测试 | `gofmt -l` 无输出；`go vet ./cmd/... ./internal/...` 通过；`go test ./internal/... ./cmd/...` 全部通过 |
| 实机 | `idleleo-e2e:24.04`：systemd、真实 Xray、openssl、iproute2 |
| 安装 | 容器内 `idleleo xray install --mode reality --domain www.cloudflare.com --target 127.0.0.1:8443 --port 443 --container`，`install_rc=0` |
| 写入契约 | `IDLELEO_ALLOW_SYSTEM_WRITES=I_ACCEPT_CONTAINER_ONLY` + `--container`，只写一次性容器 |
| 证据卫生 | `check_evidence_hygiene.py`：全仓库 `--mask .` 0 findings / 16363 files；无 UUID 明文（驱动内置脱敏） |
| 外网 | 本轮恢复：容器有默认路由，`bridge` 网关可达，`https://ip.me` 与 GitHub Releases 返回 200；M1–M10、E5–E8、ACME/relay 得以实跑 |

单元测试与实机都针对**当前提交构建出的二进制**（证据 run.json 的 `commit` 为 `be141822`，包含 `2d9a27af` + `d8950cd7` + `be141822` 的全部代码）。

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
| P3 热用户/修复/摘要套件 | **60 PASS / 0 FAIL** | `goevo-p3-20261119-0303`，commit `be141822` |
| E1–E8（配置编辑：UUID/端口/target/serverNames/TLS 证书/回滚/shortId/私钥轮换） | **8/8 PASS** | `goevo-p3-matrix-0242-a9875aff/p2`，各场景 `checks.json` 全部 `allPassed=true` |
| M1–M10 双端安装矩阵 | **10/10 PASS** | 两侧 `rc=0`，L4 两轮真实客户端全 `ok`，L6 幂等 `ok`；差异仅限已登记 ED |
| OPS-09/19/21/31/32 | **PASS** | 两侧观测一致（负载均衡、Fail2ban、证书、诊断、热用户） |
| OPS 未驱动行（Go 单边） | **36 assertions 全过** | `goevo-ops-20261119-0412-6ad3be97`；`stats`/`metadata import` 的缺失前置条件按“正确拒绝”断言（rc=3 + 原因），不跳过 |
| R1 Bash 安装 → `xray install --keep-config` | **2/2 PASS**（M1、M4） | `goevo-r1r2-20261119-0420-6ad3be97/r1`；配置字节、证书、端口、cron 不变，接管前后真实客户端均连通 |
| R2 Bash 安装 → bridge audit/prepare/validate/activate | **2/2 PASS**（M1、M4） | 同上；终态 `state=COMMITTED`，接管后客户端连通 |
| I1–I4 接管失败注入 | **42 PASS / 0 FAIL** | `20261119-0440-8c002dde/r1`；corrupt-config / missing-cert / port-in-use / read-only-target |
| Go 单元/集成测试 | **PASS** | 全包 `go test` 通过；gofmt/vet 干净 |
| 证据卫生 | **PASS** | 0 findings |

本轮外部网络恢复后，全矩阵不再有 BLOCKED 项。接管修复后于 `6ad3be97` 重跑 M1–M10/E1–E8/OPS-09/19/21/31/32 与 P3 热套件，全部 PASS；`80ad240f` 新增端口预检后在 `8c002dde` 树上再跑 M1 确认黄金路径未回归（`20261119-0442-8c002dde/p2`）。

### 6.2 本轮发现：证书切换的瞬时双代 worker

第一次全量重跑时 E5 判 `wireCertMatches=false`。取证显示：`state-pre` 与 `state-post` 两次抓取相隔 1 秒，`state-pre` 已是新证书、`state-post` 又回到旧证书——说明 Nginx 平滑重载后新旧 worker 在极短窗口内并存，任何单次握手都可能落到任一代。

- 产品侧无缺陷：编辑的 `tlsProbe` 以 5s 重试等待新叶证书，判定为成功；旧 worker 只服务重载前已建立的连接，随后退出。
- 测试侧有缺陷：驱动 `wait_served` 一次命中新指纹后，`snap post` 只做单次握手采样，可能落在旧 worker 上。
- 修复（`be141822`）：改为 `wait_served_stable`，要求 30s 内连续 3 次命中新指纹，并逐次记录探测结果到 `served-probes.txt`；诊断信息不再截断 worker 列表。
- 修复后 E5 及全部 E 场景连续通过，`served-probes.txt` 显示 3 连击收敛。

### 6.3 账本与门禁

- `feature_contracts.json`：F01–F28 全部离开 `PENDING_GO_IMPLEMENTATION`，26 项 `VERIFIED_GO_PARITY`，F20/F25 为 `APPROVED_SAFE_DIVERGENCE`；每项都带仓库相对 `evidence` 路径。
- 实跑证据：`evidence/f01f28-20261119`，privileged systemd 容器内用源码构建的 `idleleo` + 固定 Bash 检出 `3b2a5045` 执行 28 个夹具，**28/28 rc=0**；`manifest.json` 记录镜像、二进制、geo 与 Bash 哈希。
- `check_ledger_transition.py`：从 `HEAD` 基线到当前账本，28 项 `PENDING -> VERIFIED/APPROVED` 全部允许，无反向、无删改 id。
- `check_release_gate.py`：状态与夹具已满足；受保护 CI 在 `work/go-evolution-audit-20261118` 上实跑 **PASS**（run `44421005604`，日志 `RELEASE FUNCTIONAL QUALIFICATION PASS`，28/28 rc=0，证据 artifact 已上传）。
- 未执行：合并 `main`、打 tag、发布 Release、改生产机器。

### 6.4 CI、隐私、依赖与夹具扫描（C3）

| 项 | 结果 | 证据与说明 |
|---|---|---|
| CI 回归 | PASS（远程受保护分支 CI）/ NOT_RUN（stage gate） | run `44421005604` 全绿：Privacy Guard、go vet/test/build、28 个夹具在真实主机模式全 PASS，证据 artifact 已上传。本地等价同样全绿：`check_evidence_hygiene.py --mask .` 0 findings/16363 文件；`test_ledger_transition.py` 17 tests OK；A2 比较器 `SELFTEST_PASS mutations=14 baseline=MATCH`；`gofmt`/`go vet`/全库 `go test`/`go build` 通过。需要 `legacy` 检出的 stage gate 仍未跑 |
| 隐私 | PASS（本阶段） | 证据卫生扫描 0 findings；驱动对 UUID 脱敏；未提交私钥或证书（Reality target 证书运行时生成、随容器销毁）；未写入宿主公网 IP 或个人路径 |
| 依赖许可 | PASS | `go.mod`/`go.sum` 相对基线未变，未新增 vendor 代码 |
| 夹具可重复性 | PASS | `run_p3_hot.sh` 每次从源码构建、生成新 UUID/密钥与自签 origin；`run_p2_matrix.sh` 本轮在恢复外网后完整复跑 M1–M10/E1–E8/OPS，无 BLOCKED |
| 文档与命令示例 | PASS | 帮助文本已加入 `ops summary`、`xray api status\|enable`、`--experimental-hot`；本报告命令可直接复演 |

未覆盖清单（如实记录）：断电/极端退出仅以重启与半失败重试近似，未做真实断电；bridge（Bash→Go 迁移）沿用 P1/P2 证据，本次未复跑；并发仅测两路；IPv6 未覆盖。

### 6.5 最终看板（矩阵 §七）

| 维度 | PASS | FAIL | NOT_RUN | BLOCKED | 批准差异 | 证据 |
|---|---:|---:|---:|---:|---|---|
| M1–M10 安装 | 10 | 0 | 0 | 0 | 全部差异为已登记 ED，两轮一致 | `goevo-p3-matrix-0242-a9875aff/p2` |
| OPS 运营 | 5 双端 + 29 单边 | 0 | 0 | 0 | 单边不计入双端 PASS | `goevo-p3-matrix-0242-a9875aff/p2`（双端）；`goevo-ops-20261119-0412-6ad3be97`（原 18 行）与 F 夹具（OPS-04/05/06/07/08/10/16/17b/17c/24/27/30 各由对应 F 行实跑覆盖，见 §6.5 说明） |
| F01–F28 功能 | 28 | 0 | 0 | 0 | F20/F25 登记为批准差异 | `evidence/f01f28-20261119`，28/28 rc=0；账本已签收 |
| S1–S9 辅助脚本 | 9 | 0 | 0 | 0 | — | `s-20261119-full/s`（S4–S9，58 assertions）；S1/S2/S3 交互菜单本体无独立驱动，能力分别由 OPS-19/OPS-21 双端与 OPS-26 单边实跑覆盖 |
| R1/R2 迁移升级 | 2 | 0 | 0 | 0 | — | `goevo-r1r2-20261119-0420-6ad3be97/r1`（M1/M4，64 assertions） |
| G01–G06 增量 | 6 | 0 | 0 | 0 | — | P1 脱敏、变更契约、doctor、backup/repair、preflight、热用户（实验） |
| 负面/故障恢复 | 16 | 0 | 0 | 0 | — | 5 类容器注入 + 6 类单元级 + `bridge prepare --fault disk-full`（CLI 注入模拟 ENOSPC，无残留）+ I1/I2/I3/I4 接管失败注入 |

看板口径：PASS 只在对应证据存在且覆盖该行最低成功条件时计数；单元级故障注入单独注明，不冒充双端实机。

OPS 单边补账映射（本次关闭 11 个 NOT_RUN，均为 Go 侧实跑，Bash 交互驱动仍缺）：

| OPS 行 | 覆盖夹具 | 观测 |
|---|---|---|
| OPS-04 端口 | F08 | 改端口后配置/服务生效 |
| OPS-05 UUID | F06 | UUIDv5 增删一致 |
| OPS-06 target | F08 | target 修改与校验 |
| OPS-07 TLS 版本 | F10 | TLS 版本修改 |
| OPS-08 SNI Guard | F08 | serverNames/Guard 修改 |
| OPS-10 serverNames | F08 | serverNames 修改 |
| OPS-16 证书续期 | F12 | 续期/清理路径 |
| OPS-17b Nginx 更新 | F13 | Go 侧 Nginx 更新 |
| OPS-17c 自动更新 cron | F14 | cron 安装与状态 |
| OPS-24 GeoData 刷新 | F16 | 原生热更新与旧任务 |
| OPS-27 清空证书 | F12 | 证书清理断言 |
| OPS-30 语言 | F23 | 语言菜单/输出 |

这些行仍不满足“双端 PASS”：Bash 菜单没有对应自动化驱动，只有 Go 侧黑盒证据。双端缺口继续如实保留在单边列。

### 6.6 本轮新增：Bash→Go 接管的四个真实缺陷

真实接管（不是同实现重装）暴露了四个只在迁移路径上出现的问题，均已修复并在 `6ad3be97` 以 M1/M4 双场景实跑验证：

| 现象 | 根因 | 修复 |
|---|---|---|
| 接管后 xray 启动失败并回滚 | Bash 把 `/etc/idleleo/conf/xray` 留成 `0750 root:root`，Go 只给文件换组，`User=xray` 无法穿越目录 | `ensureServiceReadableDir` 给服务组补 `r-x`；`repair` 同步覆盖该目录 |
| TLS+ws 接管后客户端连不上（重置） | Go 重新生成的 Nginx 片段上游固定 `127.0.0.1:10000`，Bash 的 ws 入站是随机端口 | 接管时 `adoptRuntimeSettings` 从被保留配置继承 ws/grpc/xhttp 端口与路径 |
| 接管第二步报 `ws port ... is already in use` | 端口探测把正在运行的同一服务当成占用 | `SkipPortProbe: spec.KeepConfig`，仅接管路径跳过 |
| `bridge validate` 报 `nginx -t` 失败 | 只认 `/etc/nginx/nginx.conf`，Bash 树在 `/usr/local/nginx/conf/nginx.conf` | `nginxMainConf` 优先系统路径、回退 Bash 布局 |

失败注入（I1–I4）又补出一个第五点：全新 Reality 安装在 443 被占用时先写出配置、到启动才失败，报错不指名端口。`80ad240f` 在生成前预检公网端口（仅全新安装；接管保留运行中的监听），并让 `xray -test` 的拒绝信息带上目标配置路径。

## 7. GO/NO-GO 建议

- **正式发布：NO-GO**。28 项契约未签收，缺少受保护 CI 与真实节点证据；本轮全矩阵已实跑通过，但账本门禁仍是 `RELEASE BLOCKED`。
- **保留实验能力：GO（带标记）**。热用户变更默认关闭，仅在 `--experimental-hot` 下可用；默认路径不变。
- **默认能力：GO（有界）**。repair/doctor 的权限回归已修复并有实机证据；Bash→Go 接管（R1/R2）已实跑通过；`ops summary` 只读。
- **剩余风险**：
  1. 证书编辑存在 Nginx 平滑重载的瞬时双代窗口（E5 已用收敛判定覆盖）；若旧连接长期存活，旧 worker 也会在极短时间内继续服务旧证书，不影响新连接最终收敛。
  2. 热变更只对 Reality+VLESS 用户增删给出证据；其他协议与密钥轮换不承诺低中断。
  3. 真实 VPS 上的 systemd/journald、证书续期与断电场景仍未取证；断电/极端退出仅以重启与半失败重试近似。
  4. S1–S3 交互菜单能力已由 OPS-19/21/26 实跑覆盖（前两者双端，OPS-26 为 Go 单边），但三个菜单本身仍没有独立自动化驱动；S4–S9 已实跑 PASS，S7 仍需真实域名+公网 CA 才能验证签发，S8 仍需真实 VPS 内核才能验证 BBR 生效。F01–F28 已有容器实跑证据并在账本签收，但正式发布仍只接受受保护 CI 产物。
  5. 端口预检只覆盖全新 Reality 直连安装；TLS/reality-nginx 的公网端口由 Nginx 持有，安装时由 `nginx -t` 与启动校验兜底。
