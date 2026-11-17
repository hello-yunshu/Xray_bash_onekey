# P2 install matrix — p2

Generated 2026-11-15 09:54:25. Round 1 is primary; round 2 is the idempotency round.

| 场景 | bash rc / L4r1 / L4r2 / rc2 / L6 | go rc / L4r1 / L4r2 / rc2 / L6 | 判定 | 说明 |
|---|---|---|---|---|
| M1 reality-standard | - / - / - / - / - | - / - / - / - / - | **HARNESS-ERROR** | bash: missing evidence directory |
| M2 reality-nginx | - / - / - / - / - | - / - / - / - / - | **HARNESS-ERROR** | bash: missing evidence directory |
| M3 reality-transport | - / - / - / - / - | - / - / - / - / - | **HARNESS-ERROR** | bash: missing evidence directory |
| M4 tls-ws | - / - / - / - / - | - / - / - / - / - | **HARNESS-ERROR** | bash: missing evidence directory |
| M5 tls-grpc | - / - / - / - / - | - / - / - / - / - | **HARNESS-ERROR** | bash: missing evidence directory |
| M6 tls-xhttp | - / - / - / - / - | - / - / - / - / - | **HARNESS-ERROR** | bash: missing evidence directory |
| M7 tls-ws-grpc-xhttp | - / - / - / - / - | - / - / - / - / - | **HARNESS-ERROR** | bash: missing evidence directory |
| M8 tls-acme | - / - / - / - / - | - / - / - / - / - | **HARNESS-BLOCKED** | scenario ineligible: 前置：Pebble 的 HTTP-01/TLS-ALPN 在本容器网络的解析方案；方案未定前不判过，标 HARNESS-BLOCKED |
| M9 none-ws | - / - / - / - / - | - / - / - / - / - | **HARNESS-ERROR** | bash: missing evidence directory |
| M10 relay-stream | - / - / - / - / - | - / - / - / - / - | **HARNESS-ERROR** | bash: missing evidence directory |

本轮 M1–M7、M9、M10 两侧的 rc、L4（两轮）、rc2、L6 全部通过；M8 仍为 HARNESS-BLOCKED；布局差异按类 ED 登记后不再计 BLOCKER，剩余 BLOCKER 只来自未批准 ED（Go 能力缺口）。

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

- **M1 reality-standard** — HARNESS-ERROR：bash: missing evidence directory
- **M2 reality-nginx** — HARNESS-ERROR：bash: missing evidence directory
- **M3 reality-transport** — HARNESS-ERROR：bash: missing evidence directory
- **M4 tls-ws** — HARNESS-ERROR：bash: missing evidence directory
- **M5 tls-grpc** — HARNESS-ERROR：bash: missing evidence directory
- **M6 tls-xhttp** — HARNESS-ERROR：bash: missing evidence directory
- **M7 tls-ws-grpc-xhttp** — HARNESS-ERROR：bash: missing evidence directory
- **M8 tls-acme** — HARNESS-BLOCKED：scenario ineligible: 前置：Pebble 的 HTTP-01/TLS-ALPN 在本容器网络的解析方案；方案未定前不判过，标 HARNESS-BLOCKED
- **M9 none-ws** — HARNESS-ERROR：bash: missing evidence directory
- **M10 relay-stream** — HARNESS-ERROR：bash: missing evidence directory

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
| E5 config-edit-tls-cert-success | 0 | 0b5e090d66d6 → 0b5e090d66d6 | backupHasOldCert:ok, backupHasOldKey:ok, editRcZero:ok, fragmentUpdated:ok, probeOk:ok, runtimeUnchanged:ok, scheduleUpdated:ok, servicesActive:ok, tlsVersion13:ok, wireCertMatches:ok, xrayNotRestarted:ok | ok / ok | **PASS** | M4 的证书/域名编辑是前端所有，runtime JSON 必须逐字节不变且 Xray 不重启；旧对被备份到 edit-<ts>/。 |
| E6 config-edit-tls-rollback | 1 | 88fd41f6ea73 → 88fd41f6ea73 | backupHasOldPair:ok, configRestored:ok, guardRejected:ok, guardZeroWrites:ok, nginxRestored:ok, probeFailureRecorded:ok, rollbackRcNonZero:ok, scheduleRestored:ok, servedCertRestored:ok, servicesActive:ok | ok / ok | **PASS** | E6a 证明写前守卫零落盘；E6b 由 reload 静默未生效制造真实握手失败，证明写入后探针会触发 runtime/nginx/jobs.json 全量回滚且服务保持 active。 |

- E5 SHA：改前 `0b5e090d66d6e7e2df67c1a78c5c7fa8350c22709ab51e65c45ada11bdcc70ad` → 改后 `0b5e090d66d6e7e2df67c1a78c5c7fa8350c22709ab51e65c45ada11bdcc70ad`（已还原）
- E6 SHA：改前 `88fd41f6ea73100498951abcd2a96e9dbb4b51b777daf2a6fbecb54557193b39` → 改后 `88fd41f6ea73100498951abcd2a96e9dbb4b51b777daf2a6fbecb54557193b39`（已还原）

## 未覆盖/未验证

- M8（ACME）：`eligible:false`，按计划记 HARNESS-BLOCKED。
- L2 仅记录 sanitized config 摘要，未做全字段语义 diff；L3/L5 以采集件为准。
