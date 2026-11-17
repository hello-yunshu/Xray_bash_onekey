# P2 install matrix — p2

Generated 2026-11-15 03:25:56. Round 1 is primary; round 2 is the idempotency round.

| 场景 | bash rc / L4r1 / L4r2 / rc2 / L6 | go rc / L4r1 / L4r2 / rc2 / L6 | 判定 | 说明 |
|---|---|---|---|---|
| M1 reality-standard | 0 / reality:ok / reality:ok / 0 / ok | 0 / reality:ok / reality:ok / 0 / ok | **ED-C01,ED-C02,ED-C03,ED-C04,ED-C05,ED-C06,ED-C07,ED-C08,ED-C09,ED-C10,ED-C11,ED-C12,ED-C13** | 27 L1 paths suppressed by registered ED |
| M2 reality-nginx | 0 / reality:ok / reality:ok / 0 / ok | 0 / reality:ok / reality:ok / 0 / ok | **ED-C01,ED-C02,ED-C03,ED-C04,ED-C05,ED-C06,ED-C07,ED-C08,ED-C09,ED-C10,ED-C11,ED-C12,ED-C13** | 27 L1 paths suppressed by registered ED |
| M3 reality-transport | 0 / reality:ok,ws:ok / reality:ok,ws:ok / 0 / ok | 0 / reality:ok,ws:ok / reality:ok,ws:ok / 0 / ok | **ED-C01,ED-C02,ED-C03,ED-C04,ED-C05,ED-C06,ED-C07,ED-C08,ED-C09,ED-C10,ED-C11,ED-C12,ED-C13** | 27 L1 paths suppressed by registered ED |
| M4 tls-ws | 0 / ws:ok / ws:ok / 0 / ok | 0 / ws:ok / ws:ok / 0 / ok | **ED-C01,ED-C02,ED-C03,ED-C04,ED-C05,ED-C06,ED-C08,ED-C09,ED-C10,ED-C11,ED-C12,ED-C13** | 26 L1 paths suppressed by registered ED |
| M5 tls-grpc | 0 / grpc:ok / grpc:ok / 0 / ok | 0 / grpc:ok / grpc:ok / 0 / ok | **ED-C01,ED-C02,ED-C03,ED-C04,ED-C05,ED-C06,ED-C08,ED-C09,ED-C10,ED-C11,ED-C12,ED-C13** | 26 L1 paths suppressed by registered ED |
| M6 tls-xhttp | 0 / xhttp:ok / xhttp:ok / 0 / ok | 0 / xhttp:ok / xhttp:ok / 0 / ok | **ED-C01,ED-C02,ED-C03,ED-C04,ED-C05,ED-C06,ED-C08,ED-C09,ED-C10,ED-C11,ED-C12,ED-C13** | 26 L1 paths suppressed by registered ED |
| M7 tls-ws-grpc-xhttp | 0 / grpc:ok,ws:ok,xhttp:ok / grpc:ok,ws:ok,xhttp:ok / 0 / ok | 0 / grpc:ok,ws:ok,xhttp:ok / grpc:ok,ws:ok,xhttp:ok / 0 / ok | **ED-C01,ED-C02,ED-C03,ED-C04,ED-C05,ED-C06,ED-C08,ED-C09,ED-C10,ED-C11,ED-C12,ED-C13** | 26 L1 paths suppressed by registered ED |
| M8 tls-acme | - / - / - / - / - | - / - / - / - / - | **HARNESS-BLOCKED** | scenario ineligible: 前置：Pebble 的 HTTP-01/TLS-ALPN 在本容器网络的解析方案；方案未定前不判过，标 HARNESS-BLOCKED |
| M9 none-ws | 0 / ws:ok / ws:ok / 0 / ok | 0 / ws:ok / ws:ok / 0 / ok | **ED-C01,ED-C02,ED-C03,ED-C04,ED-C05,ED-C06,ED-C07,ED-C08,ED-C09,ED-C10,ED-C11,ED-C12,ED-C13** | 26 L1 paths suppressed by registered ED |
| M10 relay-stream | 0 / relay:ok / relay:ok / 0 / ok | 0 / relay:ok / relay:ok / 0 / ok | **ED-C01,ED-C02,ED-C03,ED-C04,ED-C05,ED-C08,ED-C09,ED-C10,ED-C11,ED-C12,ED-C13** | 23 L1 paths suppressed by registered ED |

本轮 M1–M7、M9、M10 两侧的 rc、L4（两轮）、rc2、L6 全部通过；M8 仍为 HARNESS-BLOCKED；布局差异按类 ED 登记后不再计 BLOCKER，剩余 BLOCKER 只来自未批准 ED（Go 能力缺口）。

## 未验 / 阻塞项

- **M8 tls-acme** — HARNESS-BLOCKED：scenario ineligible: 前置：Pebble 的 HTTP-01/TLS-ALPN 在本容器网络的解析方案；方案未定前不判过，标 HARNESS-BLOCKED

## L1 布局差异（未抑制）

无。

## EXPECTED-DIFF 登记表（按类审批）

匹配口径：`paths` 精确匹配 + `scenarios` 显式列举。新增文件或新增场景不会被已批准类别吸收，一律重新 BLOCKER。

| ED | 类别 | 场景数 | 层 | 路径数 | owner | approved_by | expires | supersedes | 状态 |
|---|---|---|---|---|---|---|---|---|---|
| ED-C01 | 辅助脚本目录 | 9 | L1 | 8 | hello-yunshu | release-gate | 2027-03-31 | 9 | ED |
| ED-C02 | 分享信息缓存 | 9 | L1 | 3 | hello-yunshu | release-gate | 2027-03-31 | 9 | ED |
| ED-C03 | gettext 语言包 | 9 | L1 | 1 | hello-yunshu | release-gate | 2027-03-31 | 9 | ED |
| ED-C04 | 安装日志目录 | 9 | L1 | 2 | hello-yunshu | release-gate | 2027-03-31 | 9 | ED |
| ED-C05 | 安装临时目录 | 9 | L1 | 2 | hello-yunshu | release-gate | 2027-03-31 | 9 | ED |
| ED-C06 | 统计/地理数据目录 | 9 | L1 | 2 | hello-yunshu | release-gate | 2027-03-31 | 8 | ED |
| ED-C07 | 证书目录 | 9 | L1 | 1 | hello-yunshu | release-gate | 2027-03-31 | 4 | ED |
| ED-C08 | conf 布局 | 9 | L1 | 2 | hello-yunshu | release-gate | 2027-03-31 | 11 | ED |
| ED-C09 | 自安装副本 | 9 | L1 | 1 | hello-yunshu | release-gate | 2027-03-31 | 9 | ED |
| ED-C10 | 组件版本清单 | 9 | L1 | 1 | hello-yunshu | release-gate | 2027-03-31 | 9 | ED |
| ED-C11 | 托管版本标记 | 9 | L1 | 1 | hello-yunshu | release-gate | 2027-03-31 | 9 | ED |
| ED-C12 | root crontab | 9 | L1 | 1 | hello-yunshu | release-gate | 2027-03-31 | 9 | ED |
| ED-C13 | Go 元数据目录 | 9 | L1 | 3 | hello-yunshu | release-gate | 2027-03-31 | 9 | ED |
| ED-001 | Nginx 负载均衡 upstream 块 | 1 | L2 | 1 | hello-yunshu | release-gate | 2027-03-31 | 0 | BLOCKER(rejected) |
| ED-002 | fail2ban jail.local + filter.d | 1 | L1 | 1 | hello-yunshu | release-gate | 2027-03-31 | 0 | BLOCKER(rejected) |
| ED-003 | 流量阻断规则 | 1 | L3 | 1 | hello-yunshu | release-gate | 2027-03-31 | 0 | BLOCKER(rejected) |
| ED-004 | 日志清理/轮转结果 | 1 | L1 | 1 | hello-yunshu | release-gate | 2027-03-31 | 0 | BLOCKER(rejected) |
| ED-005 | rill agent 输出文本 | 1 | L5 | 1 | hello-yunshu | release-gate | 2027-03-31 | 0 | ED |

### 不予批准（转 Go 待办）

| ED | 待办 | 理由 |
|---|---|---|
| ED-001 | S2 | Go 没有负载均衡配置入口，且 reality-balance 编辑直接拒绝；这是功能空白，不是布局差异。 |
| ED-002 | C1 | Go 完全没有 fail2ban 接入，登记等于默认接受安全能力缺失。 |
| ED-003 | C2 | Go 无任何等价入口，用户迁移后等于丢功能。 |
| ED-004 | C3 | 磁盘打满是运维事故，Go 无 logrotate/清理，工作量小。 |

批准性质：`approved_by=release-gate` 为流程批准，当前无第二维护者账号，**不是双人批准**；`expires=2027-03-31` 到期自动回落 BLOCKER，发布前须完成到期复核。

## 配置编辑场景（xray config edit，Go）

| 场景 | 编辑 rc | SHA 改前 → 改后 | 检查项 | L4 改前/改后 | 判定 | 说明 |
|---|---|---|---|---|---|---|
| E1 config-edit-before-after | 0 | 3c209d1c364d → 0b328b3f54d1 | editRcZero:ok, configChanged:ok, uuidApplied:ok, shareUriUpdated:ok, serviceActive:ok, backupExists:ok | ok / ok | **PASS** | Go 独有能力，bash 侧无 UUID 非交互入口；判定只看 Go 改前/改后与 L4。 |
| E2 config-edit-restart-rollback | 1 | 167c6359940f → 167c6359940f | editRcNonZero:ok, rollbackReported:ok, configRestored:ok, serviceActive:ok | ok / ok | **PASS** | 回滚后 SHA 还原 |
| E3 config-edit-target-probe-refused | 2 | ad45e14bd28b → ad45e14bd28b | probeRefused:ok, configRestored:ok, serviceActive:ok, noBackup:ok | ok / ok | **PASS** | 回源不可达被拒绝，零落盘 |
| E4 config-edit-target-probe-ok | 0 | a5882164ec22 → 9739b77ae7c2 | editRcZero:ok, configChanged:ok, targetApplied:ok, probeReported:ok, serviceActive:ok | ok / ok | **PASS** | 回源探测通过后落盘 |

- E1 SHA：改前 `3c209d1c364d88f6a131a0967c858a21cdf40d245e0173fa097d72c3fe7ca300` → 改后 `0b328b3f54d1d71f51a19f1ef2650399552cdedb02dcd953e88c5be17d6bbd47`（已变更）
- E2 SHA：改前 `167c6359940fed7f6d176fabe149bdc371c8bf46ba8715a7629e3f4c5cedc916` → 改后 `167c6359940fed7f6d176fabe149bdc371c8bf46ba8715a7629e3f4c5cedc916`（已还原）
- E3 SHA：改前 `ad45e14bd28b4fa61b77b6e01306aaac32b58f451bc1b29e09a5a4ec2e4a7c01` → 改后 `ad45e14bd28b4fa61b77b6e01306aaac32b58f451bc1b29e09a5a4ec2e4a7c01`（已还原）
- E4 SHA：改前 `a5882164ec22258cea438aacc86691c3a2f50b6f7b8ca77d66f281eb6f95498f` → 改后 `9739b77ae7c2534a6b6adbcae8f3345e25b455ea3f3a1aad84a0c0471cec6e69`（已变更）

## 与基线对比（p2）

| 场景 | 基线（bash ‖ go ‖ 判定；每侧 rc/L4r1/L4r2/rc2/L6） | 本轮（bash ‖ go ‖ 判定；每侧 rc/L4r1/L4r2/rc2/L6） | 变化格子 |
|---|---|---|---|
| M1 | 0 / reality:ok / reality:fail / 0 / ok / 0 / reality:ok / reality:ok / 0 / ok / BLOCKER | 0 / reality:ok / reality:ok / 0 / ok / 0 / reality:ok / reality:ok / 0 / ok / ED-C01,ED-C02,ED-C03,ED-C04,ED-C05,ED-C06,ED-C07,ED-C08,ED-C09,ED-C10,ED-C11,ED-C12,ED-C13 | bash.l4r2 变化; 判定 BLOCKER→ED-C01,ED-C02,ED-C03,ED-C04,ED-C05,ED-C06,ED-C07,ED-C08,ED-C09,ED-C10,ED-C11,ED-C12,ED-C13 |
| M2 | 0 / reality:ok / reality:fail / 0 / ok / 0 / reality:ok / reality:fail / 0 / ok / BLOCKER | 0 / reality:ok / reality:ok / 0 / ok / 0 / reality:ok / reality:ok / 0 / ok / ED-C01,ED-C02,ED-C03,ED-C04,ED-C05,ED-C06,ED-C07,ED-C08,ED-C09,ED-C10,ED-C11,ED-C12,ED-C13 | bash.l4r2 变化; go.l4r2 变化; 判定 BLOCKER→ED-C01,ED-C02,ED-C03,ED-C04,ED-C05,ED-C06,ED-C07,ED-C08,ED-C09,ED-C10,ED-C11,ED-C12,ED-C13 |
| M3 | 0 / reality:ok,ws:ok / reality:fail,ws:fail / 0 / ok / 0 / reality:ok,ws:ok / reality:ok,ws:ok / 0 / ok / BLOCKER | 0 / reality:ok,ws:ok / reality:ok,ws:ok / 0 / ok / 0 / reality:ok,ws:ok / reality:ok,ws:ok / 0 / ok / ED-C01,ED-C02,ED-C03,ED-C04,ED-C05,ED-C06,ED-C07,ED-C08,ED-C09,ED-C10,ED-C11,ED-C12,ED-C13 | bash.l4r2 变化; 判定 BLOCKER→ED-C01,ED-C02,ED-C03,ED-C04,ED-C05,ED-C06,ED-C07,ED-C08,ED-C09,ED-C10,ED-C11,ED-C12,ED-C13 |
| M4 | 0 / ws:ok / ws:fail / 0 / ok / 0 / ws:ok / ws:fail / 0 / ok / BLOCKER | 0 / ws:ok / ws:ok / 0 / ok / 0 / ws:ok / ws:ok / 0 / ok / ED-C01,ED-C02,ED-C03,ED-C04,ED-C05,ED-C06,ED-C08,ED-C09,ED-C10,ED-C11,ED-C12,ED-C13 | bash.l4r2 变化; go.l4r2 变化; 判定 BLOCKER→ED-C01,ED-C02,ED-C03,ED-C04,ED-C05,ED-C06,ED-C08,ED-C09,ED-C10,ED-C11,ED-C12,ED-C13 |
| M5 | 0 / grpc:ok / grpc:fail / 0 / ok / 0 / grpc:ok / grpc:fail / 0 / ok / BLOCKER | 0 / grpc:ok / grpc:ok / 0 / ok / 0 / grpc:ok / grpc:ok / 0 / ok / ED-C01,ED-C02,ED-C03,ED-C04,ED-C05,ED-C06,ED-C08,ED-C09,ED-C10,ED-C11,ED-C12,ED-C13 | bash.l4r2 变化; go.l4r2 变化; 判定 BLOCKER→ED-C01,ED-C02,ED-C03,ED-C04,ED-C05,ED-C06,ED-C08,ED-C09,ED-C10,ED-C11,ED-C12,ED-C13 |
| M6 | 0 / xhttp:ok / xhttp:fail / 0 / ok / 0 / xhttp:ok / xhttp:fail / 0 / ok / BLOCKER | 0 / xhttp:ok / xhttp:ok / 0 / ok / 0 / xhttp:ok / xhttp:ok / 0 / ok / ED-C01,ED-C02,ED-C03,ED-C04,ED-C05,ED-C06,ED-C08,ED-C09,ED-C10,ED-C11,ED-C12,ED-C13 | bash.l4r2 变化; go.l4r2 变化; 判定 BLOCKER→ED-C01,ED-C02,ED-C03,ED-C04,ED-C05,ED-C06,ED-C08,ED-C09,ED-C10,ED-C11,ED-C12,ED-C13 |
| M7 | 0 / grpc:ok,ws:ok,xhttp:ok / grpc:fail,ws:fail,xhttp:fail / 0 / ok / 0 / grpc:ok,ws:ok,xhttp:ok / grpc:fail,ws:fail,xhttp:fail / 0 / ok / BLOCKER | 0 / grpc:ok,ws:ok,xhttp:ok / grpc:ok,ws:ok,xhttp:ok / 0 / ok / 0 / grpc:ok,ws:ok,xhttp:ok / grpc:ok,ws:ok,xhttp:ok / 0 / ok / ED-C01,ED-C02,ED-C03,ED-C04,ED-C05,ED-C06,ED-C08,ED-C09,ED-C10,ED-C11,ED-C12,ED-C13 | bash.l4r2 变化; go.l4r2 变化; 判定 BLOCKER→ED-C01,ED-C02,ED-C03,ED-C04,ED-C05,ED-C06,ED-C08,ED-C09,ED-C10,ED-C11,ED-C12,ED-C13 |
| M8 | - / - / - / - / - / - / - / - / - / - / HARNESS-BLOCKED | - / - / - / - / - / - / - / - / - / - / HARNESS-BLOCKED | — |
| M9 | 0 / ws:ok / ws:fail / 0 / ok / 0 / ws:ok / ws:ok / 0 / ok / BLOCKER | 0 / ws:ok / ws:ok / 0 / ok / 0 / ws:ok / ws:ok / 0 / ok / ED-C01,ED-C02,ED-C03,ED-C04,ED-C05,ED-C06,ED-C07,ED-C08,ED-C09,ED-C10,ED-C11,ED-C12,ED-C13 | bash.l4r2 变化; 判定 BLOCKER→ED-C01,ED-C02,ED-C03,ED-C04,ED-C05,ED-C06,ED-C07,ED-C08,ED-C09,ED-C10,ED-C11,ED-C12,ED-C13 |
| M10 | 0 / relay:ok / relay:ok / 0 / ok / 0 / relay:ok / relay:ok / 0 / ok / BLOCKER | 0 / relay:ok / relay:ok / 0 / ok / 0 / relay:ok / relay:ok / 0 / ok / ED-C01,ED-C02,ED-C03,ED-C04,ED-C05,ED-C08,ED-C09,ED-C10,ED-C11,ED-C12,ED-C13 | 判定 BLOCKER→ED-C01,ED-C02,ED-C03,ED-C04,ED-C05,ED-C08,ED-C09,ED-C10,ED-C11,ED-C12,ED-C13 |
| E1,E2,E3,E4 | 无 | 已执行 | E1 新增; E2 新增; E3 新增; E4 新增 |

本轮预期变化：G8 → M10 文件集合；G9 → M3/M7 端口；G10 → M4/M7 重启；G11 → E1/E2 新增。

## 三步改动落地证据

| 主题 | 基线 go | 本轮 go | 本轮 bash | 关联 |
|---|---|---|---|---|
| M10 relay nginx 文件 | 00-xray.conf, 03-isolate.conf, nginx.default, relay-stream.conf | nginx.default, relay-stream.conf | nginx.default, relay-stream.conf | G8 |
| M3 附加传输端口 | 444 | 10000 | 10517 | G9 |
| M7 附加传输端口 | 10086, 10087, 10088 | 10000, 10001, 11000 | 10743, 10875, 11315 | G9 |
| M4 TLS 回环端口 | 9000 | 10000（公网 443） | 10522 | G10 |
| E1/E2 配置编辑 | 无 | 2 场景 PASS（见上表） | — | G11 |

## 未覆盖/未验证

- M8（ACME）：`eligible:false`，按计划记 HARNESS-BLOCKED。
- L2 仅记录 sanitized config 摘要，未做全字段语义 diff；L3/L5 以采集件为准。
