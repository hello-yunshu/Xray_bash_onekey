# P2 install matrix — p2

Generated 2026-11-15 10:46:20. Round 1 is primary; round 2 is the idempotency round.

| 场景 | bash rc / L4r1 / L4r2 / rc2 / L6 | go rc / L4r1 / L4r2 / rc2 / L6 | 判定 | 说明 |
|---|---|---|---|---|
| M1 reality-standard | - / - / - / - / - | - / - / - / - / - | **NOT-RUN** | scenario not executed in this run |
| M2 reality-nginx | - / - / - / - / - | - / - / - / - / - | **NOT-RUN** | scenario not executed in this run |
| M3 reality-transport | - / - / - / - / - | - / - / - / - / - | **NOT-RUN** | scenario not executed in this run |
| M4 tls-ws | - / - / - / - / - | - / - / - / - / - | **NOT-RUN** | scenario not executed in this run |
| M5 tls-grpc | - / - / - / - / - | - / - / - / - / - | **NOT-RUN** | scenario not executed in this run |
| M6 tls-xhttp | - / - / - / - / - | - / - / - / - / - | **NOT-RUN** | scenario not executed in this run |
| M7 tls-ws-grpc-xhttp | - / - / - / - / - | - / - / - / - / - | **NOT-RUN** | scenario not executed in this run |
| M8 tls-acme | - / - / - / - / - | - / - / - / - / - | **HARNESS-BLOCKED** | scenario ineligible: 前置：Pebble 的 HTTP-01/TLS-ALPN 在本容器网络的解析方案；方案未定前不判过，标 HARNESS-BLOCKED |
| M9 none-ws | - / - / - / - / - | - / - / - / - / - | **NOT-RUN** | scenario not executed in this run |
| M10 relay-stream | - / - / - / - / - | - / - / - / - / - | **NOT-RUN** | scenario not executed in this run |

本轮判定：HARNESS-BLOCKED=1，NOT-RUN=9。NOT-RUN 表示该场景未在本轮执行，不得视为通过。

## OPS 运营场景（实跑证据）

只有两侧观测一致才渲染 PASS；声明 `must-match` 却没有 `ops.json` 的 OPS 一律渲染为 NOT-RUN（未执行，不得视为通过）。

| 场景 | 两侧 install rc | 两侧后端 / jail | 文件（创建 / 删除后）或封禁前 / 解封后 | 判定 | 说明 |
|---|---|---|---|---|---|
| OPS-01 查看用户 | - | - | - | **NOT-RUN** | 未执行，不得视为通过 |
| OPS-02 添加用户 | - | - | - | **NOT-RUN** | 未执行，不得视为通过 |
| OPS-03 删除用户 | - | - | - | **NOT-RUN** | 未执行，不得视为通过 |
| OPS-04 变更端口 | - | - | - | **NOT-RUN** | 未执行，不得视为通过 |
| OPS-09 Nginx负载均衡 | - | - | - | **NOT-RUN** | 未执行，不得视为通过 |
| OPS-11 查看配置信息 | - | - | - | **NOT-RUN** | 未执行，不得视为通过 |
| OPS-12 实时访问日志 | - | - | - | **NOT-RUN** | 未执行，不得视为通过 |
| OPS-13 实时错误日志 | - | - | - | **NOT-RUN** | 未执行，不得视为通过 |
| OPS-14 端口实时流量 | - | - | - | **NOT-RUN** | 未执行，不得视为通过 |
| OPS-15 服务重启/启动/停止/状态 | - | - | - | **NOT-RUN** | 未执行，不得视为通过 |
| OPS-16 证书状态/有效期/自动更新 | - | - | - | **NOT-RUN** | 未执行，不得视为通过 |
| OPS-17a 更新脚本 | - | - | - | **NOT-RUN** | 未执行，不得视为通过 |
| OPS-17c 配置自动更新 | - | - | - | **NOT-RUN** | 未执行，不得视为通过 |
| OPS-18 TCP加速 | - | - | - | **NOT-RUN** | 未执行，不得视为通过 |
| OPS-19 Fail2ban | - | - | - | **NOT-RUN** | 未执行，不得视为通过 |
| OPS-20 流量统计 | - | - | - | **NOT-RUN** | 未执行，不得视为通过 |
| OPS-22 清除日志 | - | - | - | **NOT-RUN** | 未执行，不得视为通过 |
| OPS-25 备份管理文件 | - | - | - | **NOT-RUN** | 未执行，不得视为通过 |
| OPS-26 恢复管理文件 | - | - | - | **NOT-RUN** | 未执行，不得视为通过 |
| OPS-28 卸载 | - | - | - | **NOT-RUN** | 未执行，不得视为通过 |
| OPS-31 Reality负载均衡 | - | - | - | **NOT-RUN** | 未执行，不得视为通过 |
| OPS-32 后端故障摘除（ws + reality 上游） | - | - | - | **NOT-RUN** | 未执行，不得视为通过 |

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
| ED-003 | 流量阻断规则 | 1 | L3 | 1 | hello-yunshu | release-gate | 2027-03-31 | 0 | BLOCKER(rejected) |
| ED-005 | rill agent 输出文本 | 1 | L5 | 1 | hello-yunshu | release-gate | 2027-03-31 | 0 | ED |

### 不予批准（转 Go 待办）

| ED | 待办 | 理由 |
|---|---|---|
| ED-003 | C2 | Go 无任何等价入口，用户迁移后等于丢功能。 |

批准性质：`approved_by=release-gate` 为流程批准，当前无第二维护者账号，**不是双人批准**；`expires=2027-03-31` 到期自动回落 BLOCKER，发布前须完成到期复核。

## 配置编辑场景（xray config edit，Go）

| 场景 | 编辑 rc | SHA 改前 → 改后 | 检查项 | L4 改前/改后 | 判定 | 说明 |
|---|---|---|---|---|---|---|
| E1 config-edit-before-after | - | - → - | editRcZero:-, configChanged:-, uuidApplied:-, shareUriUpdated:-, serviceActive:-, backupExists:- | - / - | **BLOCKER** | 缺 checks.json; 改前 L4 未通过; 改后/回滚后 L4 未通过 |
| E2 config-edit-restart-rollback | - | - → - | editRcNonZero:-, rollbackReported:-, configRestored:-, serviceActive:- | - / - | **BLOCKER** | 缺 checks.json; 改前 L4 未通过; 改后/回滚后 L4 未通过 |
| E3 config-edit-target-probe-refused | - | - → - | probeRefused:-, configRestored:-, serviceActive:-, noBackup:- | - / - | **BLOCKER** | 缺 checks.json; 改前 L4 未通过; 改后/回滚后 L4 未通过 |
| E4 config-edit-target-probe-ok | - | - → - | editRcZero:-, configChanged:-, targetApplied:-, probeReported:-, serviceActive:- | - / - | **BLOCKER** | 缺 checks.json; 改前 L4 未通过; 改后/回滚后 L4 未通过 |
| E5 config-edit-tls-cert-success | - | - → - | editRcZero:-, probeOk:-, tlsVersion13:-, wireCertMatches:-, fragmentUpdated:-, backupHasOldCert:-, backupHasOldKey:-, scheduleUpdated:-, runtimeUnchanged:-, xrayNotRestarted:-, servicesActive:- | - / - | **BLOCKER** | 缺 checks.json; 改前 L4 未通过; 改后/回滚后 L4 未通过 |
| E6 config-edit-tls-rollback | - | - → - | guardRejected:-, guardZeroWrites:-, rollbackRcNonZero:-, probeFailureRecorded:-, configRestored:-, nginxRestored:-, scheduleRestored:-, servedCertRestored:-, backupHasOldPair:-, servicesActive:- | - / - | **BLOCKER** | 缺 checks.json; 改前 L4 未通过; 改后/回滚后 L4 未通过 |
| E7 config-edit-shortid-transition | 0 | f83cdb3ee4ae → 2af50b619704 | baselineLinkWorks:ok, appendRcZero:ok, appendKeepsOldSid:ok, newLinkUsesNewSid:ok, appendRestartedService:ok, oldLinkWorksAfterAppend:ok, newLinkWorksAfterAppend:ok, removeRcZero:ok, oldSidGone:ok, removeRestartedService:ok, oldLinkFailsAfterRemove:ok, newLinkStillWorks:ok, serviceActive:ok | ok / ok | **PASS** | 推荐流程：追加新 id -> 客户端切换 -> 删除旧 id。追加与删除都会重启 Xray（秒级重连），但旧链接在旧 sid 仍被接受期间必须一直可用；探针用真实 xray 客户端 + 隧道内 TLS 握手 + 认证后的 HTTP 请求，避免 Reality 回退造成握手假通过。 |
| E8 config-edit-privatekey-rotate-rollback | 0 | 129c4e7a4473 → 2433ace95251 | baselineLinkWorks:ok, rotateRcZero:ok, rotationReported:ok, oldLinkCaptured:ok, backupHasOldShareUri:ok, newLinkWorksAfterRotate:ok, oldLinkFailsAfterRotate:ok, faultEditFails:ok, failurePointRecorded:ok, rollbackProbeOk:ok, configRestored:ok, oldLinkWorksAfterRollback:ok, serviceActiveAfterCleanup:ok, serviceActive:ok | ok / ok | **PASS** | 轮换的断线窗口不可避免，输出必须提前打印旧链接。故障注入让重启加载旧配置副本：服务 active 但新 key/sid 未生效，只有真实客户端能发现；回滚后必须用旧链接再探通，这条是断言而不是日志。 |

- E7 SHA：改前 `f83cdb3ee4aed0289fc74f4c5f522181d0312498d72d42fa4cd7f9ce12077bf5` → 改后 `2af50b61970486f4c69412cfdeb7692cec4a93c1661c77566c4d426a1e43407e`（已变更）
- E8 SHA：改前 `129c4e7a44735ff26f6c9999d803163e2af6861ad9392af0313928e556157f2f` → 改后 `2433ace95251a2b528b4015ed4428e438b1f35f9f744e0cdfa2c11b8f155b384`（已变更）

## 未覆盖/未验证

- M8（ACME）：`eligible:false`，按计划记 HARNESS-BLOCKED。
- L2 仅记录 sanitized config 摘要，未做全字段语义 diff；L3/L5 以采集件为准。
