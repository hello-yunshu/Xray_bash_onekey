# P2 install matrix — p2

Generated 2026-11-19 03:00:18. Round 1 is primary; round 2 is the idempotency round.

| 场景 | bash rc / L4r1 / L4r2 / rc2 / L6 | go rc / L4r1 / L4r2 / rc2 / L6 | 判定 | 说明 |
|---|---|---|---|---|
| M1 reality-standard | 0 / reality:ok / reality:ok / 0 / ok | 0 / reality:ok / reality:ok / 0 / ok | **ED-C01,ED-C02,ED-C03,ED-C04,ED-C05,ED-C06,ED-C07,ED-C08,ED-C09,ED-C10,ED-C11,ED-C12,ED-C13** | 27 L1 paths suppressed by registered ED |
| M2 reality-nginx | 0 / reality:ok / reality:ok / 0 / ok | 0 / reality:ok / reality:ok / 0 / ok | **ED-C01,ED-C02,ED-C03,ED-C04,ED-C05,ED-C06,ED-C07,ED-C08,ED-C09,ED-C10,ED-C11,ED-C12,ED-C13** | 27 L1 paths suppressed by registered ED |
| M3 reality-transport | 0 / reality:ok,ws:ok / reality:ok,ws:ok / 0 / ok | 0 / reality:ok,ws:ok / reality:ok,ws:ok / 0 / ok | **ED-C01,ED-C02,ED-C03,ED-C04,ED-C05,ED-C06,ED-C07,ED-C08,ED-C09,ED-C10,ED-C11,ED-C12,ED-C13** | 27 L1 paths suppressed by registered ED |
| M4 tls-ws | 0 / ws:ok / ws:ok / 0 / ok | 0 / ws:ok / ws:ok / 0 / ok | **ED-C01,ED-C02,ED-C03,ED-C04,ED-C05,ED-C06,ED-C08,ED-C09,ED-C10,ED-C11,ED-C12,ED-C13,ED-C15** | 27 L1 paths suppressed by registered ED |
| M5 tls-grpc | 0 / grpc:ok / grpc:ok / 0 / ok | 0 / grpc:ok / grpc:ok / 0 / ok | **ED-C01,ED-C02,ED-C03,ED-C04,ED-C05,ED-C06,ED-C08,ED-C09,ED-C10,ED-C11,ED-C12,ED-C13,ED-C15** | 27 L1 paths suppressed by registered ED |
| M6 tls-xhttp | 0 / xhttp:ok / xhttp:ok / 0 / ok | 0 / xhttp:ok / xhttp:ok / 0 / ok | **ED-C01,ED-C02,ED-C03,ED-C04,ED-C05,ED-C06,ED-C08,ED-C09,ED-C10,ED-C11,ED-C12,ED-C13,ED-C15** | 27 L1 paths suppressed by registered ED |
| M7 tls-ws-grpc-xhttp | 0 / grpc:ok,ws:ok,xhttp:ok / grpc:ok,ws:ok,xhttp:ok / 0 / ok | 0 / grpc:ok,ws:ok,xhttp:ok / grpc:ok,ws:ok,xhttp:ok / 0 / ok | **ED-C01,ED-C02,ED-C03,ED-C04,ED-C05,ED-C06,ED-C08,ED-C09,ED-C10,ED-C11,ED-C12,ED-C13,ED-C15** | 27 L1 paths suppressed by registered ED |
| M8 tls-acme | 0 / ws:ok / ws:ok / 0 / ok | 0 / ws:ok / ws:ok / 0 / ok | **ED-C14** | 26 L1 paths suppressed by registered ED |
| M9 none-ws | 0 / ws:ok / ws:ok / 0 / ok | 0 / ws:ok / ws:ok / 0 / ok | **ED-C01,ED-C02,ED-C03,ED-C04,ED-C05,ED-C06,ED-C07,ED-C08,ED-C09,ED-C10,ED-C11,ED-C12,ED-C13** | 26 L1 paths suppressed by registered ED |
| M10 relay-stream | 0 / relay:ok / relay:ok / 0 / ok | 0 / relay:ok / relay:ok / 0 / ok | **ED-C01,ED-C02,ED-C03,ED-C04,ED-C05,ED-C08,ED-C09,ED-C10,ED-C11,ED-C12,ED-C13** | 23 L1 paths suppressed by registered ED |

本轮判定：ED-C01,ED-C02,ED-C03,ED-C04,ED-C05,ED-C06,ED-C07,ED-C08,ED-C09,ED-C10,ED-C11,ED-C12,ED-C13=4，ED-C01,ED-C02,ED-C03,ED-C04,ED-C05,ED-C06,ED-C08,ED-C09,ED-C10,ED-C11,ED-C12,ED-C13,ED-C15=4，ED-C01,ED-C02,ED-C03,ED-C04,ED-C05,ED-C08,ED-C09,ED-C10,ED-C11,ED-C12,ED-C13=1，ED-C14=1。NOT-RUN 表示该场景未在本轮执行，不得视为通过。

## OPS 运营场景（实跑证据）

只有两侧观测一致才渲染 PASS；声明 `must-match` 却没有 `ops.json` 的 OPS 一律渲染为 NOT-RUN（未执行，不得视为通过）。

| 场景 | 两侧 install rc | 两侧后端 / jail | 文件（创建 / 删除后）或封禁前 / 解封后 | 判定 | 说明 |
|---|---|---|---|---|---|
| OPS-01 查看用户 | - | - | - | **NOT-RUN** | 未执行，不得视为通过 |
| OPS-02 添加用户 | - | - | - | **NOT-RUN** | 未执行，不得视为通过 |
| OPS-03 删除用户 | - | - | - | **NOT-RUN** | 未执行，不得视为通过 |
| OPS-04 变更端口 | - | - | - | **NOT-RUN** | 未执行，不得视为通过 |
| OPS-09 Nginx负载均衡 | bash=0 / go=0 | bash: 10.99.0.7:9447 weight=60,127.0.0.1:10017 weight=50 ‖ go: 10.99.0.7:9447 weight=60,127.0.0.1:10000 weight=50 | bash: 创建 10.99.0.7.wsServers,127.0.0.1.wsServers / 删除后 127.0.0.1.wsServers ‖ go: 创建 10.99.0.7.wsServers,127.0.0.1.wsServers / 删除后 127.0.0.1.wsServers | **PASS** | - |
| OPS-11 查看配置信息 | - | - | - | **NOT-RUN** | 未执行，不得视为通过 |
| OPS-12 实时访问日志 | - | - | - | **NOT-RUN** | 未执行，不得视为通过 |
| OPS-13 实时错误日志 | - | - | - | **NOT-RUN** | 未执行，不得视为通过 |
| OPS-14 端口实时流量 | - | - | - | **NOT-RUN** | 未执行，不得视为通过 |
| OPS-15 服务重启/启动/停止/状态 | - | - | - | **NOT-RUN** | 未执行，不得视为通过 |
| OPS-16 证书状态/有效期/自动更新 | - | - | - | **NOT-RUN** | 未执行，不得视为通过 |
| OPS-17a 更新脚本 | - | - | - | **NOT-RUN** | 未执行，不得视为通过 |
| OPS-17c 配置自动更新 | - | - | - | **NOT-RUN** | 未执行，不得视为通过 |
| OPS-18 TCP加速 | - | - | - | **NOT-RUN** | 未执行，不得视为通过 |
| OPS-19 Fail2ban | bash=0 / go=0 | bash: nginx-badbots,nginx-botsearch,nginx-no-host,nginx-tls-error ‖ go: nginx-badbots,nginx-botsearch,nginx-no-host,nginx-tls-error | true / false | **PASS** | - |
| OPS-20 流量统计 | - | - | - | **NOT-RUN** | 未执行，不得视为通过 |
| OPS-21 流量阻断 | bash=- / go=- | bash: - ‖ go: - | - / - | **PASS** | - |
| OPS-22 清除日志 | - | - | - | **NOT-RUN** | 未执行，不得视为通过 |
| OPS-25 备份管理文件 | - | - | - | **NOT-RUN** | 未执行，不得视为通过 |
| OPS-26 恢复管理文件 | - | - | - | **NOT-RUN** | 未执行，不得视为通过 |
| OPS-28 卸载 | - | - | - | **NOT-RUN** | 未执行，不得视为通过 |
| OPS-31 Reality负载均衡 | bash=0 / go=0 | bash: 10.99.0.7:9447 weight=60,127.0.0.1:9443 weight=50 ‖ go: 10.99.0.7:9447 weight=60,127.0.0.1:9443 weight=50 | bash: 创建 10.99.0.7.realityServers,127.0.0.1.realityServers / 删除后 127.0.0.1.realityServers ‖ go: 创建 10.99.0.7.realityServers,127.0.0.1.realityServers / 删除后 127.0.0.1.realityServers | **PASS** | - |
| OPS-32 后端故障摘除（ws + reality 上游） | bash=reality=0, ws=0 / go=reality=0, ws=0 | bash: reality: backend-a.realityServers: server backend-a:9001 weight=50 max_fails=2 fail_timeout=10;,backend-b.realityServers: server backend-b:9002 weight=50 max_fails=2 fail_timeout=10; ‖ ws: backend-a.wsServers: server backend-a:9001 weight=50 max_fails=2 fail_timeout=10;,backend-b.wsServers: server backend-b:9002 weight=50 max_fails=2 fail_timeout=10; ‖ go: reality: backend-a.realityServers: server backend-a:9001 weight=50 max_fails=2 fail_timeout=10;,backend-b.realityServers: server backend-b:9002 weight=50 max_fails=2 fail_timeout=10; ‖ ws: backend-a.wsServers: server backend-a:9001 weight=50 max_fails=2 fail_timeout=10;,backend-b.wsServers: server backend-b:9002 weight=50 max_fails=2 fail_timeout=10; | reality PASS / ws PASS | **PASS** | - |

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
| E1 config-edit-before-after | 0 | b92ab321f87d → b29765d704e7 | editRcZero:ok, configChanged:ok, uuidApplied:ok, shareUriUpdated:ok, serviceActive:ok, backupExists:ok | ok / ok | **PASS** | Go 独有能力，bash 侧无 UUID 非交互入口；判定只看 Go 改前/改后与 L4。 |
| E2 config-edit-restart-rollback | 1 | a3c24750e1d6 → a3c24750e1d6 | editRcNonZero:ok, rollbackReported:ok, configRestored:ok, serviceActive:ok | ok / ok | **PASS** | 回滚后 SHA 还原 |
| E3 config-edit-target-probe-refused | 2 | 38e963b8f310 → 38e963b8f310 | probeRefused:ok, configRestored:ok, serviceActive:ok, noBackup:ok | ok / ok | **PASS** | 回源不可达被拒绝，零落盘 |
| E4 config-edit-target-probe-ok | 0 | 6b0dc389d518 → 6dbfb83e50a4 | editRcZero:ok, configChanged:ok, targetApplied:ok, probeReported:ok, serviceActive:ok | ok / ok | **PASS** | 回源探测通过后落盘 |
| E5 config-edit-tls-cert-success | 0 | f0360355791d → f0360355791d | backupHasOldCert:ok, backupHasOldKey:ok, editRcZero:ok, fragmentUpdated:ok, probeOk:ok, runtimeUnchanged:ok, scheduleUpdated:ok, servicesActive:ok, tlsVersion13:ok, wireCertMatches:ok, xrayNotRestarted:ok | ok / ok | **PASS** | M4 的证书/域名编辑是前端所有，runtime JSON 必须逐字节不变且 Xray 不重启；旧对被备份到 edit-<ts>/。 |
| E6 config-edit-tls-rollback | 1 | 0d09409e776f → 0d09409e776f | backupHasOldPair:ok, configRestored:ok, guardRejected:ok, guardZeroWrites:ok, nginxRestored:ok, probeFailureRecorded:ok, rollbackRcNonZero:ok, scheduleRestored:ok, servedCertRestored:ok, servicesActive:ok | ok / ok | **PASS** | E6a 证明写前守卫零落盘；E6b 由 reload 静默未生效制造真实握手失败，证明写入后探针会触发 runtime/nginx/jobs.json 全量回滚且服务保持 active。 |
| E7 config-edit-shortid-transition | 0 | 8d6733c85803 → f27709e5b5ab | baselineLinkWorks:ok, appendRcZero:ok, appendKeepsOldSid:ok, newLinkUsesNewSid:ok, appendRestartedService:ok, oldLinkWorksAfterAppend:ok, newLinkWorksAfterAppend:ok, removeRcZero:ok, oldSidGone:ok, removeRestartedService:ok, oldLinkFailsAfterRemove:ok, newLinkStillWorks:ok, serviceActive:ok | ok / ok | **PASS** | 推荐流程：追加新 id -> 客户端切换 -> 删除旧 id。追加与删除都会重启 Xray（秒级重连），但旧链接在旧 sid 仍被接受期间必须一直可用；探针用真实 xray 客户端 + 隧道内 TLS 握手 + 认证后的 HTTP 请求，避免 Reality 回退造成握手假通过。 |
| E8 config-edit-privatekey-rotate-rollback | 0 | 023fdb921f2d → 1da343e565ee | baselineLinkWorks:ok, rotateRcZero:ok, rotationReported:ok, oldLinkCaptured:ok, backupHasOldShareUri:ok, newLinkWorksAfterRotate:ok, oldLinkFailsAfterRotate:ok, faultEditFails:ok, failurePointRecorded:ok, rollbackProbeOk:ok, configRestored:ok, oldLinkWorksAfterRollback:ok, serviceActiveAfterCleanup:ok, serviceActive:ok | ok / ok | **PASS** | 轮换的断线窗口不可避免，输出必须提前打印旧链接。故障注入让重启加载旧配置副本：服务 active 但新 key/sid 未生效，只有真实客户端能发现；回滚后必须用旧链接再探通，这条是断言而不是日志。 |

- E1 SHA：改前 `b92ab321f87d1882b8924fc871fb9485bac3e528dcbc8f5236dcbac955cd64b4` → 改后 `b29765d704e7be5a20edd62c7ab45f6a5c759072d269d2ade8ff09ba5abbecc2`（已变更）
- E2 SHA：改前 `a3c24750e1d6f2fedf674e88dc0c917dcf83927862981849c687e826b1f03f73` → 改后 `a3c24750e1d6f2fedf674e88dc0c917dcf83927862981849c687e826b1f03f73`（已还原）
- E3 SHA：改前 `38e963b8f310ba459dc99e353e41508b25021ebc7c64c4bb56ea377775726d10` → 改后 `38e963b8f310ba459dc99e353e41508b25021ebc7c64c4bb56ea377775726d10`（已还原）
- E4 SHA：改前 `6b0dc389d518ed6bc1c90138324e60ebd8263409ef6dec8b176071b67e3ff70e` → 改后 `6dbfb83e50a47a756a8ee79435d7c189a0ab8c592caa5d1d400099638c826922`（已变更）
- E5 SHA：改前 `f0360355791de1477745f0fb16de8f47247d62b12af07e1b9e627bbced14a2f5` → 改后 `f0360355791de1477745f0fb16de8f47247d62b12af07e1b9e627bbced14a2f5`（已还原）
- E6 SHA：改前 `0d09409e776f051f773968a3b8489024f60450486f3ca95622c2d1c2c153fed6` → 改后 `0d09409e776f051f773968a3b8489024f60450486f3ca95622c2d1c2c153fed6`（已还原）
- E7 SHA：改前 `8d6733c85803e1ec4665d8ea19c76c4960b33f6e40127f454e4f1dd697305b47` → 改后 `f27709e5b5abc8324ce485b6de9b0210a4cd7f361b8b1d55d6a16320c152dea1`（已变更）
- E8 SHA：改前 `023fdb921f2dd6ab6f9bbbd43834c144e7bd17a3e4f6c40e536f233122594186` → 改后 `1da343e565ee10a6d24ee4db7299c6f4b64dd6263303e8a0047eccd1d5fe6d03`（已变更）

## 与基线对比（p2）

| 场景 | 基线（bash ‖ go ‖ 判定；每侧 rc/L4r1/L4r2/rc2/L6） | 本轮（bash ‖ go ‖ 判定；每侧 rc/L4r1/L4r2/rc2/L6） | 变化格子 |
|---|---|---|---|
| M1 | 0 / reality:ok / reality:fail / 0 / ok / 0 / reality:ok / reality:ok / 0 / ok / BLOCKER | 0 / reality:ok / reality:ok / 0 / ok / 0 / reality:ok / reality:ok / 0 / ok / ED-C01,ED-C02,ED-C03,ED-C04,ED-C05,ED-C06,ED-C07,ED-C08,ED-C09,ED-C10,ED-C11,ED-C12,ED-C13 | bash.l4r2 变化; 判定 BLOCKER→ED-C01,ED-C02,ED-C03,ED-C04,ED-C05,ED-C06,ED-C07,ED-C08,ED-C09,ED-C10,ED-C11,ED-C12,ED-C13 |
| M2 | 0 / reality:ok / reality:fail / 0 / ok / 0 / reality:ok / reality:fail / 0 / ok / BLOCKER | 0 / reality:ok / reality:ok / 0 / ok / 0 / reality:ok / reality:ok / 0 / ok / ED-C01,ED-C02,ED-C03,ED-C04,ED-C05,ED-C06,ED-C07,ED-C08,ED-C09,ED-C10,ED-C11,ED-C12,ED-C13 | bash.l4r2 变化; go.l4r2 变化; 判定 BLOCKER→ED-C01,ED-C02,ED-C03,ED-C04,ED-C05,ED-C06,ED-C07,ED-C08,ED-C09,ED-C10,ED-C11,ED-C12,ED-C13 |
| M3 | 0 / reality:ok,ws:ok / reality:fail,ws:fail / 0 / ok / 0 / reality:ok,ws:ok / reality:ok,ws:ok / 0 / ok / BLOCKER | 0 / reality:ok,ws:ok / reality:ok,ws:ok / 0 / ok / 0 / reality:ok,ws:ok / reality:ok,ws:ok / 0 / ok / ED-C01,ED-C02,ED-C03,ED-C04,ED-C05,ED-C06,ED-C07,ED-C08,ED-C09,ED-C10,ED-C11,ED-C12,ED-C13 | bash.l4r2 变化; 判定 BLOCKER→ED-C01,ED-C02,ED-C03,ED-C04,ED-C05,ED-C06,ED-C07,ED-C08,ED-C09,ED-C10,ED-C11,ED-C12,ED-C13 |
| M4 | 0 / ws:ok / ws:fail / 0 / ok / 0 / ws:ok / ws:fail / 0 / ok / BLOCKER | 0 / ws:ok / ws:ok / 0 / ok / 0 / ws:ok / ws:ok / 0 / ok / ED-C01,ED-C02,ED-C03,ED-C04,ED-C05,ED-C06,ED-C08,ED-C09,ED-C10,ED-C11,ED-C12,ED-C13,ED-C15 | bash.l4r2 变化; go.l4r2 变化; 判定 BLOCKER→ED-C01,ED-C02,ED-C03,ED-C04,ED-C05,ED-C06,ED-C08,ED-C09,ED-C10,ED-C11,ED-C12,ED-C13,ED-C15 |
| M5 | 0 / grpc:ok / grpc:fail / 0 / ok / 0 / grpc:ok / grpc:fail / 0 / ok / BLOCKER | 0 / grpc:ok / grpc:ok / 0 / ok / 0 / grpc:ok / grpc:ok / 0 / ok / ED-C01,ED-C02,ED-C03,ED-C04,ED-C05,ED-C06,ED-C08,ED-C09,ED-C10,ED-C11,ED-C12,ED-C13,ED-C15 | bash.l4r2 变化; go.l4r2 变化; 判定 BLOCKER→ED-C01,ED-C02,ED-C03,ED-C04,ED-C05,ED-C06,ED-C08,ED-C09,ED-C10,ED-C11,ED-C12,ED-C13,ED-C15 |
| M6 | 0 / xhttp:ok / xhttp:fail / 0 / ok / 0 / xhttp:ok / xhttp:fail / 0 / ok / BLOCKER | 0 / xhttp:ok / xhttp:ok / 0 / ok / 0 / xhttp:ok / xhttp:ok / 0 / ok / ED-C01,ED-C02,ED-C03,ED-C04,ED-C05,ED-C06,ED-C08,ED-C09,ED-C10,ED-C11,ED-C12,ED-C13,ED-C15 | bash.l4r2 变化; go.l4r2 变化; 判定 BLOCKER→ED-C01,ED-C02,ED-C03,ED-C04,ED-C05,ED-C06,ED-C08,ED-C09,ED-C10,ED-C11,ED-C12,ED-C13,ED-C15 |
| M7 | 0 / grpc:ok,ws:ok,xhttp:ok / grpc:fail,ws:fail,xhttp:fail / 0 / ok / 0 / grpc:ok,ws:ok,xhttp:ok / grpc:fail,ws:fail,xhttp:fail / 0 / ok / BLOCKER | 0 / grpc:ok,ws:ok,xhttp:ok / grpc:ok,ws:ok,xhttp:ok / 0 / ok / 0 / grpc:ok,ws:ok,xhttp:ok / grpc:ok,ws:ok,xhttp:ok / 0 / ok / ED-C01,ED-C02,ED-C03,ED-C04,ED-C05,ED-C06,ED-C08,ED-C09,ED-C10,ED-C11,ED-C12,ED-C13,ED-C15 | bash.l4r2 变化; go.l4r2 变化; 判定 BLOCKER→ED-C01,ED-C02,ED-C03,ED-C04,ED-C05,ED-C06,ED-C08,ED-C09,ED-C10,ED-C11,ED-C12,ED-C13,ED-C15 |
| M8 | - / - / - / - / - / - / - / - / - / - / NOT-RUN | 0 / ws:ok / ws:ok / 0 / ok / 0 / ws:ok / ws:ok / 0 / ok / ED-C14 | bash.rc -→0; bash.l4 变化; bash.l4r2 变化; bash.rc2 -→0; bash.l6 -→True; go.rc -→0; go.l4 变化; go.l4r2 变化; go.rc2 -→0; go.l6 -→True; 判定 NOT-RUN→ED-C14 |
| M9 | 0 / ws:ok / ws:fail / 0 / ok / 0 / ws:ok / ws:ok / 0 / ok / BLOCKER | 0 / ws:ok / ws:ok / 0 / ok / 0 / ws:ok / ws:ok / 0 / ok / ED-C01,ED-C02,ED-C03,ED-C04,ED-C05,ED-C06,ED-C07,ED-C08,ED-C09,ED-C10,ED-C11,ED-C12,ED-C13 | bash.l4r2 变化; 判定 BLOCKER→ED-C01,ED-C02,ED-C03,ED-C04,ED-C05,ED-C06,ED-C07,ED-C08,ED-C09,ED-C10,ED-C11,ED-C12,ED-C13 |
| M10 | 0 / relay:ok / relay:ok / 0 / ok / 0 / relay:ok / relay:ok / 0 / ok / BLOCKER | 0 / relay:ok / relay:ok / 0 / ok / 0 / relay:ok / relay:ok / 0 / ok / ED-C01,ED-C02,ED-C03,ED-C04,ED-C05,ED-C08,ED-C09,ED-C10,ED-C11,ED-C12,ED-C13 | 判定 BLOCKER→ED-C01,ED-C02,ED-C03,ED-C04,ED-C05,ED-C08,ED-C09,ED-C10,ED-C11,ED-C12,ED-C13 |
| E1,E2,E3,E4,E5,E6,E7,E8 | 无 | 已执行 | E1 新增; E2 新增; E3 新增; E4 新增; E5 新增; E6 新增; E7 新增; E8 新增 |

本轮预期变化：G8 → M10 文件集合；G9 → M3/M7 端口；G10 → M4/M7 重启；G11 → E1/E2 新增。

## 三步改动落地证据

| 主题 | 基线 go | 本轮 go | 本轮 bash | 关联 |
|---|---|---|---|---|
| M10 relay nginx 文件 | 00-xray.conf, 03-isolate.conf, nginx.default, relay-stream.conf | nginx.default, relay-stream.conf | nginx.default, relay-stream.conf | G8 |
| M3 附加传输端口 | 444 | 10000 | 10799 | G9 |
| M7 附加传输端口 | 10086, 10087, 10088 | 10000, 10001, 11000 | 10115, 10600, 11622 | G9 |
| M4 TLS 回环端口 | 9000 | 10000（公网 443） | 10520 | G10 |
| E1/E2 配置编辑 | 无 | 2 场景 PASS（见上表） | — | G11 |

## 未覆盖/未验证

- 全部安装场景 eligible；M8 走真实本地 Pebble ACME，ACME 专属产物（cert/、.well-known、schedule/）两侧已对齐。
- L2 仅记录 sanitized config 摘要，未做全字段语义 diff；L3/L5 以采集件为准。
