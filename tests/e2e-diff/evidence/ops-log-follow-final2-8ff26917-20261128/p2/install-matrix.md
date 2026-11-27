# P2 install matrix — p2

Generated 2026-11-28 00:11:52. Round 1 is primary; round 2 is the idempotency round.

> 局部跑（scope.json）：本轮只执行 OPS OPS-OBSERVE；未跑场景记 NOT-RUN，不计入阻塞，也不得作为全量通过的证据。

| 场景 | bash rc / L4r1 / L4r2 / rc2 / L6 | go rc / L4r1 / L4r2 / rc2 / L6 | 判定 | 说明 |
|---|---|---|---|---|
| M1 reality-standard | — | — | **NOT-RUN** | 未在本轮 scope 内（E2E_ONLY 局部跑） |
| M2 reality-nginx | — | — | **NOT-RUN** | 未在本轮 scope 内（E2E_ONLY 局部跑） |
| M3 reality-transport | — | — | **NOT-RUN** | 未在本轮 scope 内（E2E_ONLY 局部跑） |
| M4 tls-ws | — | — | **NOT-RUN** | 未在本轮 scope 内（E2E_ONLY 局部跑） |
| M5 tls-grpc | — | — | **NOT-RUN** | 未在本轮 scope 内（E2E_ONLY 局部跑） |
| M6 tls-xhttp | — | — | **NOT-RUN** | 未在本轮 scope 内（E2E_ONLY 局部跑） |
| M7 tls-ws-grpc-xhttp | — | — | **NOT-RUN** | 未在本轮 scope 内（E2E_ONLY 局部跑） |
| M8 tls-acme | — | — | **NOT-RUN** | 未在本轮 scope 内（E2E_ONLY 局部跑） |
| M9 none-ws | — | — | **NOT-RUN** | 未在本轮 scope 内（E2E_ONLY 局部跑） |
| M10 relay-stream | — | — | **NOT-RUN** | 未在本轮 scope 内（E2E_ONLY 局部跑） |

本轮判定：NOT-RUN=10。NOT-RUN 表示该场景未在本轮执行，不得视为通过。

## OPS 运营场景（实跑证据）

只有两侧观测一致才渲染 PASS；声明 `must-match` 却没有 `ops.json` 的 OPS 一律渲染为 NOT-RUN（未执行，不得视为通过）。

| 场景 | 两侧 install rc | 两侧后端 / jail | 文件（创建 / 删除后）或封禁前 / 解封后 | 判定 | 说明 |
|---|---|---|---|---|---|
| OPS-01 查看用户 | - | - | - | **NOT-RUN** | 未执行，不得视为通过 |
| OPS-02 添加用户 | - | - | - | **NOT-RUN** | 未执行，不得视为通过 |
| OPS-03 删除用户 | - | - | - | **NOT-RUN** | 未执行，不得视为通过 |
| OPS-07 变更TLS版本 | - | - | - | **NOT-RUN** | 未执行，不得视为通过 |
| OPS-08 SNI Guard | - | - | - | **NOT-RUN** | 未执行，不得视为通过 |
| OPS-09 Nginx负载均衡 | - | - | - | **NOT-RUN** | 未执行，不得视为通过 |
| OPS-10 serverNames | - | - | - | **NOT-RUN** | 未执行，不得视为通过 |
| OPS-11 查看配置信息 | - | - | - | **NOT-RUN** | 未执行，不得视为通过 |
| OPS-12 实时访问日志 | bash=- / go=- | bash: - ‖ go: - | - / - | **PASS** | - |
| OPS-13 实时错误日志 | bash=- / go=- | bash: - ‖ go: - | - / - | **PASS** | - |
| OPS-14 端口实时流量 | - | - | - | **NOT-RUN** | 未执行，不得视为通过 |
| OPS-15 服务重启/启动/停止/状态 | - | - | - | **NOT-RUN** | 未执行，不得视为通过 |
| OPS-16 证书状态/有效期/自动更新 | - | - | - | **NOT-RUN** | 未执行，不得视为通过 |
| OPS-17a 更新脚本 | - | - | - | **NOT-RUN** | 未执行，不得视为通过 |
| OPS-17b 更新Nginx | - | - | - | **NOT-RUN** | 未执行，不得视为通过 |
| OPS-17c 配置自动更新 | - | - | - | **NOT-RUN** | 未执行，不得视为通过 |
| OPS-18 TCP加速 | - | - | - | **NOT-RUN** | 未执行，不得视为通过 |
| OPS-19 Fail2ban | - | - | - | **NOT-RUN** | 未执行，不得视为通过 |
| OPS-20 流量统计 | - | - | - | **NOT-RUN** | 未执行，不得视为通过 |
| OPS-21 流量阻断 | - | - | - | **NOT-RUN** | 未执行，不得视为通过 |
| OPS-22 清除日志 | - | - | - | **NOT-RUN** | 未执行，不得视为通过 |
| OPS-25 备份管理文件 | - | - | - | **NOT-RUN** | 未执行，不得视为通过 |
| OPS-26 恢复管理文件 | - | - | - | **NOT-RUN** | 未执行，不得视为通过 |
| OPS-27 清空证书文件 | - | - | - | **NOT-RUN** | 未执行，不得视为通过 |
| OPS-28 卸载 | - | - | - | **NOT-RUN** | 未执行，不得视为通过 |
| OPS-31 Reality负载均衡 | - | - | - | **NOT-RUN** | 未执行，不得视为通过 |
| OPS-32 后端故障摘除（ws + reality 上游） | - | - | - | **NOT-RUN** | 未执行，不得视为通过 |

## 未验 / 阻塞项


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
| ED-C14 | M8 ACME 场景布局差异（13 类并集） | 1 | L1 | 26 | hello-yunshu | release-gate | 2027-03-31 | 0 | ED |
| ED-C15 | TLS 场景 bash 自备证书标记 .user-managed | 4 | L1 | 1 | hello-yunshu | release-gate | 2027-03-31 | 0 | ED |
| ED-005 | rill agent 输出文本 | 1 | L5 | 1 | hello-yunshu | release-gate | 2027-03-31 | 0 | ED |

批准性质：`approved_by=release-gate` 为流程批准，当前无第二维护者账号，**不是双人批准**；`expires=2027-03-31` 到期自动回落 BLOCKER，发布前须完成到期复核。

## 配置编辑场景（xray config edit，Go）

| 场景 | 编辑 rc | SHA 改前 → 改后 | 检查项 | L4 改前/改后 | 判定 | 说明 |
|---|---|---|---|---|---|---|
| E1 config-edit-before-after | — | — | — | — / — | **NOT-RUN** | 未在本轮 scope 内 |
| E2 config-edit-restart-rollback | — | — | — | — / — | **NOT-RUN** | 未在本轮 scope 内 |
| E3 config-edit-target-probe-refused | — | — | — | — / — | **NOT-RUN** | 未在本轮 scope 内 |
| E4 config-edit-target-probe-ok | — | — | — | — / — | **NOT-RUN** | 未在本轮 scope 内 |
| E5 config-edit-tls-cert-success | — | — | — | — / — | **NOT-RUN** | 未在本轮 scope 内 |
| E6 config-edit-tls-rollback | — | — | — | — / — | **NOT-RUN** | 未在本轮 scope 内 |
| E7 config-edit-shortid-transition | — | — | — | — / — | **NOT-RUN** | 未在本轮 scope 内 |
| E8 config-edit-privatekey-rotate-rollback | — | — | — | — / — | **NOT-RUN** | 未在本轮 scope 内 |


## 与基线对比

本轮为局部跑，跳过基线与三步改动对比，避免把未跑场景渲染成变化。

## 未覆盖/未验证

- 全部安装场景 eligible；M8 走真实本地 Pebble ACME，ACME 专属产物（cert/、.well-known、schedule/）两侧已对齐。
- L2 仅记录 sanitized config 摘要，未做全字段语义 diff；L3/L5 以采集件为准。
