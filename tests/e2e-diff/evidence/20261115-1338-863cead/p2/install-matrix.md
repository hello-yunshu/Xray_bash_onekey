# P2 install matrix — p2

Generated 2026-11-15 13:40:10. Round 1 is primary; round 2 is the idempotency round.

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
| OPS-21 流量阻断 | bash=- / go=- | bash: - ‖ go: - | - / - | **HARNESS-ERROR** | bash: container network has no egress; the bash installer cannot resolve its public IP or fetch geoip.dat/geosite.dat; go never reached the control origin before blocking; go failed: applyRcZero, controlAfterApply, controlAfterEdit, controlAfterOff, editOwnedRulesKept, editRoutingIdentical, offRcZero, offRestored, rulesAdded |
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
| ED-003 | 流量阻断（Xray 路由层） | 1 | L2 | 4 | hello-yunshu | release-gate | 2027-03-31 | 0 | BLOCKER(rejected) |
| ED-005 | rill agent 输出文本 | 1 | L5 | 1 | hello-yunshu | release-gate | 2027-03-31 | 0 | ED |

### 不予批准（转 Go 待办）

| ED | 待办 | 理由 |
|---|---|---|
| ED-003 | C2 | Go 无任何等价入口，用户迁移后等于丢功能。bash 的阻断写在 Xray 路由层（routing.rules + blocked 出站 + geosite/geoip/bittorrent），不是 nftables/iptables；内核层封 IP 由 C1 fail2ban 负责。 |

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
| E7 config-edit-shortid-transition | - | - → - | baselineLinkWorks:-, appendRcZero:-, appendKeepsOldSid:-, newLinkUsesNewSid:-, appendRestartedService:-, oldLinkWorksAfterAppend:-, newLinkWorksAfterAppend:-, removeRcZero:-, oldSidGone:-, removeRestartedService:-, oldLinkFailsAfterRemove:-, newLinkStillWorks:-, serviceActive:- | - / - | **BLOCKER** | 缺 checks.json; 改前 L4 未通过; 改后/回滚后 L4 未通过 |
| E8 config-edit-privatekey-rotate-rollback | - | - → - | baselineLinkWorks:-, rotateRcZero:-, rotationReported:-, oldLinkCaptured:-, backupHasOldShareUri:-, newLinkWorksAfterRotate:-, oldLinkFailsAfterRotate:-, faultEditFails:-, failurePointRecorded:-, rollbackProbeOk:-, configRestored:-, oldLinkWorksAfterRollback:-, serviceActiveAfterCleanup:-, serviceActive:- | - / - | **BLOCKER** | 缺 checks.json; 改前 L4 未通过; 改后/回滚后 L4 未通过 |


## 与基线对比（p2）

| 场景 | 基线（bash ‖ go ‖ 判定；每侧 rc/L4r1/L4r2/rc2/L6） | 本轮（bash ‖ go ‖ 判定；每侧 rc/L4r1/L4r2/rc2/L6） | 变化格子 |
|---|---|---|---|
| M1 | 0 / reality:ok / reality:fail / 0 / ok / 0 / reality:ok / reality:ok / 0 / ok / BLOCKER | - / - / - / - / - / - / - / - / - / - / NOT-RUN | bash.rc 0→-; bash.l4 变化; bash.l4r2 变化; bash.rc2 0→-; bash.l6 True→-; go.rc 0→-; go.l4 变化; go.l4r2 变化; go.rc2 0→-; go.l6 True→-; 判定 BLOCKER→NOT-RUN |
| M2 | 0 / reality:ok / reality:fail / 0 / ok / 0 / reality:ok / reality:fail / 0 / ok / BLOCKER | - / - / - / - / - / - / - / - / - / - / NOT-RUN | bash.rc 0→-; bash.l4 变化; bash.l4r2 变化; bash.rc2 0→-; bash.l6 True→-; go.rc 0→-; go.l4 变化; go.l4r2 变化; go.rc2 0→-; go.l6 True→-; 判定 BLOCKER→NOT-RUN |
| M3 | 0 / reality:ok,ws:ok / reality:fail,ws:fail / 0 / ok / 0 / reality:ok,ws:ok / reality:ok,ws:ok / 0 / ok / BLOCKER | - / - / - / - / - / - / - / - / - / - / NOT-RUN | bash.rc 0→-; bash.l4 变化; bash.l4r2 变化; bash.rc2 0→-; bash.l6 True→-; go.rc 0→-; go.l4 变化; go.l4r2 变化; go.rc2 0→-; go.l6 True→-; 判定 BLOCKER→NOT-RUN |
| M4 | 0 / ws:ok / ws:fail / 0 / ok / 0 / ws:ok / ws:fail / 0 / ok / BLOCKER | - / - / - / - / - / - / - / - / - / - / NOT-RUN | bash.rc 0→-; bash.l4 变化; bash.l4r2 变化; bash.rc2 0→-; bash.l6 True→-; go.rc 0→-; go.l4 变化; go.l4r2 变化; go.rc2 0→-; go.l6 True→-; 判定 BLOCKER→NOT-RUN |
| M5 | 0 / grpc:ok / grpc:fail / 0 / ok / 0 / grpc:ok / grpc:fail / 0 / ok / BLOCKER | - / - / - / - / - / - / - / - / - / - / NOT-RUN | bash.rc 0→-; bash.l4 变化; bash.l4r2 变化; bash.rc2 0→-; bash.l6 True→-; go.rc 0→-; go.l4 变化; go.l4r2 变化; go.rc2 0→-; go.l6 True→-; 判定 BLOCKER→NOT-RUN |
| M6 | 0 / xhttp:ok / xhttp:fail / 0 / ok / 0 / xhttp:ok / xhttp:fail / 0 / ok / BLOCKER | - / - / - / - / - / - / - / - / - / - / NOT-RUN | bash.rc 0→-; bash.l4 变化; bash.l4r2 变化; bash.rc2 0→-; bash.l6 True→-; go.rc 0→-; go.l4 变化; go.l4r2 变化; go.rc2 0→-; go.l6 True→-; 判定 BLOCKER→NOT-RUN |
| M7 | 0 / grpc:ok,ws:ok,xhttp:ok / grpc:fail,ws:fail,xhttp:fail / 0 / ok / 0 / grpc:ok,ws:ok,xhttp:ok / grpc:fail,ws:fail,xhttp:fail / 0 / ok / BLOCKER | - / - / - / - / - / - / - / - / - / - / NOT-RUN | bash.rc 0→-; bash.l4 变化; bash.l4r2 变化; bash.rc2 0→-; bash.l6 True→-; go.rc 0→-; go.l4 变化; go.l4r2 变化; go.rc2 0→-; go.l6 True→-; 判定 BLOCKER→NOT-RUN |
| M8 | - / - / - / - / - / - / - / - / - / - / HARNESS-BLOCKED | - / - / - / - / - / - / - / - / - / - / HARNESS-BLOCKED | — |
| M9 | 0 / ws:ok / ws:fail / 0 / ok / 0 / ws:ok / ws:ok / 0 / ok / BLOCKER | - / - / - / - / - / - / - / - / - / - / NOT-RUN | bash.rc 0→-; bash.l4 变化; bash.l4r2 变化; bash.rc2 0→-; bash.l6 True→-; go.rc 0→-; go.l4 变化; go.l4r2 变化; go.rc2 0→-; go.l6 True→-; 判定 BLOCKER→NOT-RUN |
| M10 | 0 / relay:ok / relay:ok / 0 / ok / 0 / relay:ok / relay:ok / 0 / ok / BLOCKER | - / - / - / - / - / - / - / - / - / - / NOT-RUN | bash.rc 0→-; bash.l4 变化; bash.l4r2 变化; bash.rc2 0→-; bash.l6 True→-; go.rc 0→-; go.l4 变化; go.l4r2 变化; go.rc2 0→-; go.l6 True→-; 判定 BLOCKER→NOT-RUN |

本轮预期变化：G8 → M10 文件集合；G9 → M3/M7 端口；G10 → M4/M7 重启；G11 → E1/E2 新增。

## 三步改动落地证据

| 主题 | 基线 go | 本轮 go | 本轮 bash | 关联 |
|---|---|---|---|---|
| M10 relay nginx 文件 | 00-xray.conf, 03-isolate.conf, nginx.default, relay-stream.conf | - | - | G8 |
| M3 附加传输端口 | 444 | - | - | G9 |
| M7 附加传输端口 | 10086, 10087, 10088 | - | - | G9 |
| M4 TLS 回环端口 | 9000 | -（公网 443） | - | G10 |
| E1/E2 配置编辑 | 无 | 2 场景 PASS（见上表） | — | G11 |

## 未覆盖/未验证

- M8（ACME）：`eligible:false`，按计划记 HARNESS-BLOCKED。
- L2 仅记录 sanitized config 摘要，未做全字段语义 diff；L3/L5 以采集件为准。
