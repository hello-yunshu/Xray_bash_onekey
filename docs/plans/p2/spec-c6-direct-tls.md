# C6 规格：direct TLS 支持（无 managed Nginx）

状态：**待审批**。本文只写方案，不含实现代码。
前置：S3 已交付 `--domain/--cert/--cert-key` 编辑与 `probeLocalTLS`，但只覆盖“Nginx 终结 TLS + Xray loopback”这一种拓扑。
审批通过后才进入实现；若结论是“不做”，本文件转为判定记录，不进 `tasks.md`。

## 0. 结论摘要

1. **拒绝的根因是拓扑不同，不是元数据缺失**。本项目的 `ModeTLS` 指“Nginx 终结 TLS、Xray 在 loopback 跑 `security:none`”，Generator 从不生成 `security:"tls"` + `tlsSettings.certificates[]` 的直连入站。放行现有路径只会把用户拓扑改掉，所以现在的拒绝是**正确**的，缺的是第二条写路径。
2. **不要教 Generator 支持直连 TLS**。建议新增一条**定点补丁**路径（clone → 只改证书/监听叶子 → 只该改的断言），与 `users.go` 同一手法；Generator 与 Nginx 模板零改动。
3. **可复用 S3 的输入侧与校验脚手架**（flags、证书对校验、备份、`--no-probe/--no-restart`、`probeLocalTLS`），**不能复用它的核心断言**（S3 断言运行时配置零 diff；直连 TLS 恰恰要写运行时配置）。
4. **续期是硬缺口**：现有 `internal/acme` 只有 HTTP-01 **webroot** 模式，依赖一个跑在 :80 的 Web 服务器——那正是 Nginx。没有 Nginx，现有续期链路直接失效。一期建议**不接管续期**，文档写明；standalone/`tls-alpn-01`/DNS-01 都各有成本（见 §5）。
5. **这是小众能力**。仓库内没有任何安装路径产出直连 TLS；价值是“接管/编辑存量配置”，不是“新增一种安装模式”，更不值得为功能齐全硬做。

## 1. 现状事实

| 事实 | 证据 |
|---|---|
| 直连 TLS 在编辑入口被显式拒绝 | `internal/xraycfg/edit.go` `editSpecFromRuntime`（L742-L745）：`direct TLS configs are not editable; reinstall with --mode tls` |
| 判定依据是运行时 `streamSettings.security == "tls"` | 同上（L724-L745） |
| `ModeTLS` 的语义是 Nginx 前端 + Xray loopback | `internal/xraycfg/share.go` 注释（L28-L32）；`TestGenerateTLSRequiresDomainAndLoopback` |
| Nginx 前端模式下 `--listen` 直接拒绝 | `applyEditRequest`（L404-L410） |
| TLS 编辑备份证书对与续期文件，`tlsTouched` 控制是否备份 | `internal/deploy/edit.go`（L274-L332） |
| 本地 TLS 握手自检已存在（SNI/链/SAN/有效期/TLS1.3） | `internal/deploy/tls.go` `probeLocalTLS`（L170-L199） |
| `Spec.CertFile/KeyFile` 与默认路径已存在 | `internal/xraycfg/xraycfg.go`（L189-L190） |
| ACME 只有 HTTP-01 webroot 一种挑战 | `internal/acme/lego.go` `webrootProvider`（L37-L65）、`SetHTTP01Provider`（L112） |
| ACME 安装后按 `ReloadCommand` 重载，失败回滚证书对 | `internal/acme/acme.go` `reloadOrRestore`（L129-L140） |
| lego v5 已 vendor（含 http01/tlsalpn01 能力），但只用到 webroot | `go.mod`、`vendor/modules.txt` |
| 非 vendor 代码里 `certificateFile/tlsSettings` 的命中只有 `share.go`（读）与 `acme`（写证书文件，不写配置） | 全仓 grep |

结论：这不是“字段少了一个”，而是**同一组 flag 背后对应两套完全不同的配置结构**。

## 2. 为什么现在拒绝（根因拆解）

| 候选根因 | 是否成立 | 说明 |
|---|---|---|
| 元数据缺失（不知道 mode） | 部分成立，但不是主因 | 即便 `EditDefaults.Mode` 声称 tls，Generator 仍会产出 loopback + `security:none` |
| 前端配置结构不同 | **主因** | 直连 TLS 的 inbound 自己持有 `tlsSettings.certificates[0].certificateFile/keyFile`，并监听公网端口；没有 Nginx conf 可写 |
| 校验层不允许 | 附加原因 | Nginx 前端模式下 `--listen` 被拒；直连模式必须允许 |
| 证书路径无处读回 | 可绕过 | 直连模式的证书路径就在运行配置里，不需要新增 metadata 字段 |

因此“补元数据”解决不了问题；补了反而更危险：一旦放行，`Generate` 会用错误拓扑覆盖用户配置，`diffRuntime` 白名单要么报错、要么被放宽到看不出问题。

## 3. 要支持它需要补什么

### 3.1 识别（只读，不改生成器）

- `editSpecFromRuntime` 在 `security == "tls"` 时不再报错，返回一个明确的拓扑标记（例如 `Spec.Topology = "tls-direct"`），并读回：
  - `inbounds[i].listen` / `port`
  - `inbounds[i].streamSettings.tlsSettings.serverName`
  - `inbounds[i].streamSettings.tlsSettings.certificates[0].certificateFile/keyFile`
- 保留拒绝：`certificates` 缺失、为空数组、或不是本地文件路径（例如只有 `certificates` 以外的字段）→ 明确报错，不猜。
- `status --json` / 报告里的 mode 建议输出 `tls-direct`，与既有 `tls`（Nginx 前端）区分，避免下游继续把两者混成一个词。该字段变更属独立小改动，需单独确认（见 §9）。

### 3.2 写路径（新增，定点补丁）

新增 `internal/xraycfg/directtls.go`：

```go
type DirectTLSRequest struct {
    Domain   string
    CertFile string
    KeyFile  string
    Listen   string
    Port     int
}

type DirectTLSResult struct {
    Domain    string
    CertFile  string
    KeyFile   string
    Listen    string
    Port      int
    Changed   []string
    Inbounds  []int
    Disconnect bool
    NoChanges  bool
    Diff       []string
}

func PatchDirectTLS(raw []byte, req DirectTLSRequest) ([]byte, DirectTLSResult, error)
```

约束：

- clone 原文档 → 只改 3 类叶子：`streamSettings.tlsSettings.certificates[0].certificateFile|keyFile`、`streamSettings.tlsSettings.serverName`、`listen`/`port`。
- 用与 `assertOnlyUsersChanged` 相同的手法做窄断言：把允许改的叶子还原后，整份文档必须 `DeepEqual`。
- 多 inbound 的证书必须一起改（默认全改），否则会有端口继续用旧证书；与 C5 §3.2 同一条规则。
- 不做结构重建：`--transport/--ws-path/--xhttp-path/--grpc-service-name/--target/--server-names/--short-id` 在该拓扑下一律拒绝，报错说明“直连 TLS 只支持证书与监听编辑”。
- 不走 `Generate`，不写 Nginx conf，不动 `outbounds/routing`。

### 3.3 握手自检（预检 + 后检，分两层）

- **写前**（不占端口）：`tls.LoadX509KeyPair` 校验文件对；解析叶子证书校验 SAN 覆盖目标域名、未过期、私钥可读且权限未放宽。失败 → rc=2、零写盘。
- **写后**（真实接线）：重启 Xray 后对 `127.0.0.1:<port>` 用 SNI=domain 做一次 TLS 握手，复用 `probeLocalTLS`；要求链、SAN、有效期、TLS1.3 全过。失败 → 回滚配置并重启，报失败点。
- 与 S3 的差异要写清楚：S3 的 `probeLocalTLS` 探的是 Nginx 的本地监听；这里探的是 Xray 自己的端口，函数可原样复用，调用点与期望值不同。
- `--no-probe` 保留（运维明确知道自己在干什么时）；默认必须探。

## 4. 与 S3 的复用程度

| 能力 | 复用 | 说明 |
|---|---|---|
| `--domain/--cert/--cert-key` flag 形状 | 是 | 用户命令不变，语义按拓扑分派 |
| 证书对校验（可加载、SAN、有效期） | 是 | 抽成共用函数，两条路径都调 |
| 备份目录与 `extras{CertFile,KeyFile}` | 是 | 备份的是“引用 + 文件路径”，不是证书内容 |
| `--no-probe/--no-restart/--dry-run/--yes` | 是 | 骨架一致 |
| `probeLocalTLS` | 是 | 拨号目标与 SNI 由调用方给 |
| 报告字段 `Domain/CertFile/KeyFile` | 是 | 统一输出 |
| `g.NginxConf` 重写 | **否** | 直连拓扑没有 Nginx |
| “运行时配置零 diff”断言 | **否** | 直连必须产生精确的运行时 diff |

即：输入侧、校验侧、备份侧、探测侧可复用（约六成工作量），**写路径是新增的**，不能靠“把 Nginx 那边改一改”糊过去。

## 5. 续期链路（没有 Nginx 时 ACME 用什么形态）

现有实现：`internal/acme` 用 lego v5，挑战方式是 `webrootProvider` 往 `/.well-known/acme-challenge/` 写文件（`lego.go` L37-L65、L112）。这要求 :80 上有一个把该目录暴露出去的 Web 服务器——托管 Nginx 正是这个角色。

直连 TLS 下 :80 通常是空的，于是可选形态与成本：

| 形态 | 可行性 | 成本/风险 |
|---|---|---|
| a. **不接管续期**，证书由用户自己的 ACME 客户端（certbot standalone、DNS-01 等）产出，再用本功能的 `--cert/--cert-key` 装载 | **推荐** | 零新增网络面；缺点是用户要自带工具 |
| b. lego standalone（HTTP-01 临时监听 :80） | 可行 | 续期窗口内需要 :80 空闲；要处理“端口被占”“续期期间短暂暴露” |
| c. `tls-alpn-01` 监听 :443 | 不可行（当前形态） | 与 Xray 抢 443；除非让 Xray 前置分流 ALPN，属重大结构改动 |
| d. DNS-01 | 技术上可行 | 需要 DNS provider 凭据，等于新增一类长期密钥，安全面变大 |

一期结论：**只做 a**。文档、`status` 告警和 `cert` 相关输出都要明确“续期不在本功能内”，避免用户以为装上就自动续。b 作为独立后续项评估，不在本规格内。

## 6. 用户规模与实际价值

事实：

- 仓库内**没有任何安装/向导路径**生成 `security:"tls"` 的入站。`certificateFile/tlsSettings` 的非 vendor 命中只有 `share.go`（读取渲染链接）与 `internal/acme`（写证书文件，不写配置）。
- 因此直连 TLS 只可能来自：手工编辑过的存量配置、外部迁移/导入的配置、以及未来“不用 Nginx”的极简部署。
- 反过来，Go 侧所有“一条命令装证书”的能力都绑定 Nginx 前端，现有 TLS 用户绝大多数走这条路径。

判断：**小众**。它的价值是“别逼这类用户重装”和“接管已有配置”，不是“补齐功能矩阵”。因此建议的交付范围是：

- 做：识别 + 证书/监听编辑 + 预检/后检 + 备份回滚。
- 不做：新增安装模式、ACME 自动续期、`--transport` 等结构重建、DNS 凭据。
- 如果连“接管”都没有真实用户在等，**建议直接判定不做**，把资源留给有真实流量的项。这一点请明确拍板，不要按“功能齐全”默认推进。

## 7. 验证方式

### 7.1 单测

1. 直连 TLS fixture（`security:"tls"` + `tlsSettings.certificates[0]` + 公网 listen）上改证书路径：只有目标叶子变化，其余 `DeepEqual`。
2. 改 `--listen/--port`：只动监听叶子，仍产生 `Disconnect=true`。
3. 负例：`certificates` 缺失、路径为空、结构不是对象 → 明确报错；`--transport` 等结构参数 → 拒绝。
4. 多 inbound：默认全改；`--inbound` 收窄时报告未改的 inbound。
5. 与既有 Nginx 前端路径的隔离：同一组 flag 在两个 fixture 上分别走到各自路径，互不串场。

### 7.2 E2E（正反对照，本地可跑）

用本地自签 CA + `local.test` 证书（OPS-21 已有同类 fixture 手法），不依赖 egress、不依赖公网 CA。

| # | 动作 | 期望 |
|---|---|---|
| 1 | 基线：客户端经直连 TLS 入站建立隧道，访问控制站 | 200 且含 `Example Domain` |
| 2 | 换成同域名的新证书（新 SAN/新序列号），`config edit --cert/--cert-key` | rc=0，重启一次，后检握手通过 |
| 3 | **不该断**：客户端继续用同域名重建隧道 | 200；UUID/其他用户/路由逐字节不变 |
| 4 | **该断**：把证书换成 SAN 不含该域名的证书 | 预检拒绝、零写盘（不重启） |
| 5 | **该断**：改端口后连旧端口 | 连接被拒（快速失败，不是超时）；新端口 200 |
| 6 | 失败注入：写入后握手探测失败 | 自动回滚配置并重启，旧证书接线恢复，第 1 步重新 200 |
| 7 | **不该断**：C2 阻断规则与用户 routing | `routing.rules` 逐条深度相等；阻断项仍被拒、控制站仍通 |

第 4、5 步必须证明“预检真的拦住了”，不能只看最终 rc：要断言配置哈希未变、`NRestarts` 未增。

### 7.3 对拍

- bash 侧是否支持直连 TLS 需在实现前补一次事实核对（本文件只确认 Go 侧生成路径不存在）。若 bash 也无此模式，则 C6 为 Go-only 增量，不产生 `expected_diffs.json` 条目，只在 `behavior-diff.md` 记录。
- 若有对拍价值，新增用例在 `matrix.json` 单侧登记，不冒充双端一致。

## 8. 安全闸

1. **显式确认**：root 下 `--yes`；`--dry-run` 打印生效端口、新证书路径、SAN、到期时间、受影响的 inbound，以及“会重启、所有会话短暂中断”。
2. **写前校验**：文件对可加载、SAN 覆盖域名、未过期、私钥权限未被放宽、`xray -test` 通过；任一失败零写盘。
3. **窄断言**：除证书/域名/监听叶子外出现任何差异 → 拒绝提交。
4. **写后探测**：真实 TLS 握手失败即回滚配置 + 重启，并保留备份供核对。
5. **不静默降级**：绝不因为证书不可用就退回 `security:none` 或关掉 TLS 校验。
6. **不扩网络面**：本期不监听 :80、不注册 ACME、不写 DNS 凭据。
7. **备份**：`/etc/idleleo/backup/direct-tls-<ts>/` 保存旧 `config.json`、旧证书路径清单、`change.json`；回滚成功后保留。
8. **续期免责**：输出与文档明确“不接管续期”；`status` 对临近过期的证书给 warning，不自动续。

## 9. 需要你拍板的点

| # | 事项 | 建议 |
|---|---|---|
| 1 | **做不做** | 只做“识别 + 编辑 + 接管”，不做新装模式；若没有真实用户等待，直接判定不做 |
| 2 | 写路径形态 | 新增定点补丁（`PatchDirectTLS`），**不教 Generator**，不改 Nginx 模板 |
| 3 | 续期 | 一期**不接管**（用户自带 ACME）；standalone / DNS-01 另立项目，不在本规格 |
| 4 | `--listen/--port` | 直连模式**允许**编辑，并标 `Disconnect=true`；Nginx 前端模式维持现在的拒绝 |
| 5 | 多 inbound 证书 | **默认全改**；`--inbound` 需显式并要求 `--yes` |
| 6 | 域名与 SAN 不匹配 | 默认**拒绝**；不提供 `--allow-san-mismatch`（避免把错误证书装上线） |
| 7 | mode 命名 | 报告里区分 `tls`（Nginx 前端）与 `tls-direct`；该字段变更单独确认，不混在 C6 里 |
| 8 | 交付门槛 | 若拍板要做，先跑通 §7.2 的第 4/5 步负例，再写正例；负例过不了不算落地 |

## 10. 实施与验收（2026-11-17）

**拍板结果**：做。按 §9 建议 2/3/4/6/7 实施，交付形态为 `识别 + 编辑 + 接管证书对`，
不新增安装模式、不改 Generator/Nginx 模板、不接管续期。

- 实现
  - `internal/xraycfg/directtls.go`：`PatchDirectTLS` 只允许 `domain/cert/cert-key/listen/port`，
    拒绝生成期字段；证书必须成对、可加载、SAN 覆盖域名；`assertDirectTLSOnlyChanged` 窄断言
    保证除允许叶子外逐字段不变；`Changed` 使用 `cert-file/cert-key-file/domain/listen/port`。
  - `internal/xraycfg/edit.go`：`ModeTLSDirect` 仅作编辑期分类，`EditRuntime` 按模式分流；
    metadata 不写入 `tls-direct`，保留安装期 TLS 标签。
  - `internal/deploy/edit.go`：`tls` 入站不再报 "not editable"；`tlsTouched` 对 direct TLS
    不排续期，改为输出“不接管续期”warning；写后对 `127.0.0.1:<port>` 做真实握手探测，
    失败整笔回滚。
  - `internal/deploy/tls.go`：无 `serverName` 时只校验证书对，不要求主机名匹配。
- 测试
  - `go test ./internal/xraycfg ./internal/deploy`：通过（新增 15 个单测：轮换对、改域名、
    listen/port、no-op、单边证书对、生成期字段拒绝、非 TLS 配置、多 inbound 端口拒绝、
    dry-run、真实探针地址、探针失败回滚、metadata 标签保持）。
  - `tests/go-parity/parity/features/C6_test.py`：29 条断言，负例优先（错域名零写盘 →
    dry-run 零写盘 → 真实轮换后握手/SNI/重启/备份/结构保持）。双跑证据
    `tests/go-parity/evidence/c6-2026-11-17/run1|run2`（29/29，rc=0）。
- 级别与缺口
  - 验收级别：**CONTAINER_VERIFIED**（root + systemd + 真实 xray，容器内；非真实 VPS）。
  - 未覆盖：`--inbound` 多入站单选（一期为全部 TLS 入站同时应用）、证书过期/权限衰减的
    独立负例、Bash 侧（本项为 Go-only 增量，无直连 TLS 模式，不产生 `expected_diffs.json`）。
