# P2 收口汇报：Go 对齐 Bash

口径：**Go 对齐 bash，除非真的做不到**。不动 `install.sh`；不静默删除安全闸；
差异只以「可改 / 不可改 / 需拍板 / 主动不对齐」四类结案，不允许用放宽断言换绿。

本文件对应 `tasks.md` 的 T8，回答四件事：差异怎么分类、每项怎么改和怎么验、
矩阵前后变化、还剩什么。

## 1. 差异清单分类

来源：`docs/plans/p2/spec.md` 的 G1–G19 与 D1–D9，逐条结论在
`docs/plans/p2/behavior-diff.md`。

| 分类 | 条目 | 结论 |
|---|---|---|
| 可改、已对齐 | G1 Reality 附加传输、G2 relay 安装落地、G3 nginx 目录（实为无差异）、G4 重复安装、G5 `--nginx-bin` 别名、G6 测试 argv、G8 relay 文件集合、G9 附加传输端口、G10 TLS 回环端口、G11 配置编辑、G16/G17 证书路径与根校验 | 改 Go，双侧实跑一致 |
| 测试侧问题 | M6/M9 argv 缺参、M10 origin 启动顺序、L4 空数组、L6 把备份目录当漂移、菜单层级 | 只改 harness，Go 未动 |
| 主动不对齐（已批准） | G12 `logrotate`、G13 `fail2ban` 不调用系统包管理器；G18 shortId 长度形态 | 单独成节说明理由与后果，不进 ED |
| 主动收紧（Go 更严） | G14 负载均衡后端增删的角色/空后端/保留端口/回滚守卫 | 不进 ED，单测固化 |
| Go 增量（bash 无对应入口） | G19 `xray user uuid`；C2 流量阻断；C4 metadata 快照；C6 direct TLS 编辑 | 登记能力增量，不反向要求 bash |
| 需拍板 | 无 | 没有必须动安全闸才能对齐的项 |

布局差异治理：113 条原始路径按类合并为 13 类（`ED-C01`…`ED-C13`，14 个唯一路径），
M8 按「新增场景必须新开 ED」单独登记 `ED-C14`（26 条），OPS-29 的 rill 输出文本差异为
`ED-005`。`ED-001`…`ED-004` 曾被判 rejected 并要求改 Go，现已分别由 S2、C1、C2、C3 消解，
从登记表移除。

护栏：`paths` 精确匹配（不做目录前缀吸收）+ `scenarios` 显式列举；新增文件或新增场景
一律重新 BLOCKER。15 条已批准 ED 共覆盖 113 条历史差异。

## 2. 每项改法与验证

| ID | 改法 | 验证 |
|---|---|---|
| G1 | `internal/xraycfg`：Reality 保留 raw 主 inbound，ws/grpc/xhttp 追加独立 inbound（端口 +1），等价 `reality_add_more` | `go test ./internal/xraycfg -run RealitySingleTransport`；M3 双侧 L2/L4 |
| G2 | `internal/nginx.EnsureRelayInclude` + `internal/deploy.InstallRelay` + `xray install --role relay` | `go test ./internal/deploy -run Relay`；M10 双侧 L1–L4，客户端经中转回源 |
| G3 | 不改 | M4 manifest 对比：两侧 `/usr/local/nginx`、`/etc/idleleo/conf/nginx` 一致 |
| G4 | `deploy` 默认保留已有配置并告警；`--keep-config`/`--rewrite-config` 显式开关 | `go test ./internal/deploy`；全部场景第 2 轮 rc=0、L6 无漂移 |
| G5 | `--mode reality --nginx-bin` 映射到 `reality-nginx` | M2 两种 CLI 形态生成等价配置 |
| G6 | 补 `--binary`；M9 显式 `--listen 0.0.0.0 --allow-non-loopback` | M5–M7/M9 双侧通过 |
| G8 | `InstallSpec.RelayOnly`；Stream 分支只给节点模式 include 占位文件 | M10 两侧文件集合一致、`nginx -t` ok |
| G9 | ws/gRPC 10000–10999、xHTTP 11000–11999 升序候选 + bind 探测 + 保留端口排除 + 显式覆盖 | M3/M7 双侧两轮；第三方占用 10000 时选 10001 并 warning |
| G10 | TLS 回环 inbound 取传输端口池，公网端口留给 Nginx | M4–M7 重启无 `EADDRINUSE`，L4 两轮 ok |
| G11 | `xray config edit`：spec 还原、patch、严格 diff 白名单、`xray -test` 前置、备份、失败回滚 | E1/E2；`go test ./internal/xraycfg ./internal/deploy` |
| G12/G13 | 缺二进制时零落盘失败，打印 deb/rhel/alpine 安装命令；卸载只删 manifest 内文件 | `TestEnableLogRotationNeedsTheBinary`、`TestFail2banInstallRequiresTheBinary`；容器内真实 logrotate/fail2ban 实测 |
| G14 | `balance add/list/remove` 角色闸、空后端/回环/保留端口/重复 host 拒绝、`nginx -t` 回滚 | `go test ./internal/deploy -run Balance`；OPS-09/OPS-31 双端 |
| G16/G17 | `config edit --domain/--cert/--cert-key`：配对、SAN 覆盖、有效期、本地握手探测；Bash 根写入前拒绝 | E5 成功、E6 回滚；单测覆盖三态 |
| G18 | 生成 8 hex，编辑接受 1–16 位偶数 hex | E7 真实客户端握手通过 |
| G19 | `xray user uuid`：email 定位、多 inbound 一次事务、失败零落盘 | `tests/e2e-diff/evidence/c5-20261115-142437`（26/26） |
| S1 | 编辑前主动回源探测：TCP；有 SNI 时校验链与 hostname | E3 拒连、E4 受信本地 CA；`evidence/s1-edit-probe-ca` |
| S2 | 负载均衡后端增删 + reality-balance | OPS-09/OPS-31/OPS-32 双端 |
| S3 | TLS 证书/域名编辑与回滚 | E5/E6；`evidence/e5e6-11150953-3f25259` |
| S4 | Reality shortIds、链路偏好、私钥轮换 | E7/E8；`evidence/s4-reality-1115c` |
| C1 | fail2ban 五套 jail、`-t` 预检、manifest 卸载、不自动放行 IP | OPS-19 改 `must-match`；`evidence/ops19-verify-0415` |
| C2 | Xray 路由层流量阻断 | F21 执行器 |
| C3 | `logs clean` + `logs rotate enable/disable` | OPS-22 改 `must-match`；容器内真实 logrotate |
| C4 | metadata 快照引擎版本/端口/target/serverNames | `evidence/c4-metadata-snapshot-full` 全量矩阵 |
| C5 | 单用户 UUID 轮换 | `evidence/c5-20261115-142437` |
| C6 | direct TLS inbound 证书原地编辑，窄断言只允许 5 个字段变化 | `tests/go-parity/evidence/c6-2026-11-17/run1|run2`：29/29，`CONTAINER_VERIFIED` |

提交分组（T8 要求）：差异清单与规格 `4983551e`；Go 生成逻辑 `8ecc69e3`、`16f38bbc`；
relay 安装 `467c1934`、`e209f49d`；重复安装/别名 `196d7378`、`916ac951`、`59b8ac33`；
矩阵/驱动/runner `f8fad8dc`、`2a7c6c85`、`57781355`；
证书对齐轮 `7022c09c`/`69dba27f`/`2ea4c8ae`；
本轮 G-4/G-5/G-6 的提交见 `git log`（`35831a67`、`85cdc392`、`03405437`、`7bf4841c`、
`75aea7a0`、`b073a004`）。

## 3. 矩阵前后对比

| 阶段 | 证据 | 结果 |
|---|---|---|
| P2 起点 | `evidence/step1-m10-relayonly/p2/install-matrix.md` | 仅 M10 局部跑，Go `relay:fail`、rc=1 |
| ED 审批前全量 | `evidence/final-full-d6a6d3d/p2/install-matrix.md` | M1–M7/M9/M10 全为 **BLOCKER**（ED pending），M6 bash 幂等失败，M8 HARNESS-BLOCKED |
| ED 按类审批后全量 | `evidence/final-full2-8863b10/p2/install-matrix.md` | M1–M7/M9/M10 判定为 `ED-C01…ED-C13`，**未抑制路径 0**；M8 仍 HARNESS-BLOCKED |
| C1–C4 后复跑 | `evidence/c4-metadata-snapshot-full/p2/install-matrix.md` | 同上，且 OPS-19/OPS-22 转 `must-match` |
| M8 解阻 | `evidence/g4-m8-run7-20261117`、`g4-m8-run9-20261117` | M8 双侧 round1/2 rc=0、L4 ws 两轮 ok、L6 ok、判定 `ED-C14`；no unsuppressed |
| 编辑场景 | `evidence/s1-edit-probe-ca`、`e5e6-11150953-3f25259`、`s4-reality-1115c` | E1–E8 全部 PASS |

结论：安装矩阵的阻塞项从「9 个 BLOCKER + 1 个 HARNESS-BLOCKED」收敛为
「10 个场景全部有结论、0 未抑制差异」；编辑矩阵 E1–E8 全绿。

## 4. 仍保留的能力缺口与外部阻塞

1. **G12/G13 不调用系统包管理器**：全新系统上 `logs rotate enable` 与 `fail2ban install`
   需先手动装一次依赖；报错已给出三条安装命令。这是批准过的主动选择，重新评估条件写在
   `behavior-diff.md`。
2. **G14 主动收紧**：Go 拒绝 bash 允许的若干危险操作（删空后端、保留端口、跨角色增删）。
   属于更安全的行为，不是缺口。
3. **G18 shortId 形态**：bash 16 hex、Go 8 hex，双方都能接受对方的 id，不是兼容问题。
4. **无交互菜单等价**：D3 只对齐「重复安装默认保留配置」的结果，不复制 bash 的菜单体验；
   若要求交互等价需另立需求。
5. **Bash 侧重复安装在运行中会被自身 `port_exist_check` 误判**：已观测、未修，
   需 bash 侧单独立项；P2 第 2 轮通过先停服务规避，并把该问题排除在通过结论之外。
6. **真实公网 CA 终验未做**：环境缺公网入口，M8 只证明本地 Pebble 的真实 ACME 协议链路；
   staging/公网签发仍需外部环境。
7. **发布账本未签收**：`tests/go-parity/parity/cases/feature_contracts.json` 28 项仍为
   `PENDING_GO_IMPLEMENTATION`，`check_release_gate.py` 因此在任何环境都返回 rc=2；
   6 项夹具（F01/F05/F11/F26/F27/F28）只有 preview 输出、无归档证据目录。这是 G-6 的
   唯一剩余阻塞，必须由真实 VPS/VM 签收，不能用本地证据替换。

## 5. 结论

T0–T7、T9–T14 全部完成；T8 的提交分组与汇报以本文件收口。
P2 的差分开齐目标已达成：可改项全部改完并有双侧证据，不可改/主动不对齐/主动收紧项
均有书面理由与后果说明，矩阵无未抑制差异。
发布验收（P2-G 的 G-6）不属于差分计划本身，其剩余项是外部签收与受保护 CI 实跑，
状态见 `tasks.md` 与 `tests/go-parity/evidence/g6-2026-11-17/ci-closeout.md`。
