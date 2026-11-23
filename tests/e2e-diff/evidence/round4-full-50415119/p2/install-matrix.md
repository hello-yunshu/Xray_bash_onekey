# P2 install matrix — p2

Generated 2026-11-24 03:12:31. Round 1 is primary; round 2 is the idempotency round.

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
| OPS-01 查看用户 | bash=- / go=- | bash: - ‖ go: - | - / - | **PASS** | - |
| OPS-02 添加用户 | bash=- / go=- | bash: - ‖ go: - | - / - | **PASS** | - |
| OPS-03 删除用户 | - | - | - | **NOT-RUN** | 未执行，不得视为通过 |
| OPS-04 变更端口 | bash=0 / go=0 | bash: - ‖ go: - | - / - | **PASS** | - |
| OPS-05 变更UUID/映射 | bash=0 / go=0 | bash: - ‖ go: - | - / - | **PASS** | - |
| OPS-06 变更target | bash=0 / go=0 | bash: - ‖ go: - | - / - | **PASS** | - |
| OPS-07 变更TLS版本 | bash=0 / go=0 | bash: - ‖ go: - | - / - | **PASS** | - |
| OPS-08 SNI Guard | bash=0 / go=0 | bash: - ‖ go: - | - / - | **PASS** | - |
| OPS-09 Nginx负载均衡 | bash=0 / go=0 | bash: 10.99.0.7:9447 weight=60,127.0.0.1:10075 weight=50 ‖ go: 10.99.0.7:9447 weight=60,127.0.0.1:10000 weight=50 | bash: 创建 10.99.0.7.wsServers,127.0.0.1.wsServers / 删除后 127.0.0.1.wsServers ‖ go: 创建 10.99.0.7.wsServers,127.0.0.1.wsServers / 删除后 127.0.0.1.wsServers | **PASS** | - |
| OPS-10 serverNames | bash=0 / go=0 | bash: - ‖ go: - | - / - | **PASS** | - |
| OPS-11 查看配置信息 | bash=0 / go=0 | bash: - ‖ go: - | - / - | **PASS** | - |
| OPS-12 实时访问日志 | bash=- / go=- | bash: - ‖ go: - | - / - | **DIFF** | Bash menu entry is an unbounded 'tail -f' stream; Go emits a finite journald snapshot |
| OPS-13 实时错误日志 | bash=- / go=- | bash: - ‖ go: - | - / - | **DIFF** | Bash menu entry is an unbounded 'tail -f' stream; Go emits a finite journald snapshot |
| OPS-14 端口实时流量 | bash=- / go=- | bash: - ‖ go: - | - / - | **DIFF** | Bash entry is the interactive iftop UI; Go is a bounded stats query; bash output bytes=5007; go api enable rc=0; go stats rc=0 |
| OPS-15 服务重启/启动/停止/状态 | bash=0 / go=0 | bash: - ‖ go: - | - / - | **PASS** | - |
| OPS-16 证书状态/有效期/自动更新 | bash=- / go=- | bash: - ‖ go: - | - / - | **DIFF** | Bash menu 4>2>1/4>2>2 shows certificate status/validity; Go 'cert renew --dry-run' is a renewal preflight; bash rc=0; go rc=0; bash certificate present=True; go certificate present=True notExpired=True state=not-due |
| OPS-17a 更新脚本 | bash=- / go=- | bash: - ‖ go: - | - / - | **BLOCKED** | update check requires the public distribution; this job has no pinned manifest; bash rc=124 go rc=0 |
| OPS-17b 更新Nginx | bash=- / go=- | bash: - ‖ go: - | - / - | **BLOCKED** | Nginx update needs the fixed local trusted package used by the real-root job; bash rc=124 go rc=3 |
| OPS-17c 配置自动更新 | bash=0 / go=0 | bash: - ‖ go: - | - / - | **PASS** | - |
| OPS-18 TCP加速 | bash=- / go=- | bash: - ‖ go: - | - / - | **BLOCKED** | Bash entry is an interactive host BBR switch; a container cannot change or prove the host kernel; Go tcp status rc=0 |
| OPS-19 Fail2ban | bash=0 / go=0 | bash: nginx-badbots,nginx-botsearch,nginx-no-host,nginx-tls-error ‖ go: nginx-badbots,nginx-botsearch,nginx-no-host,nginx-tls-error | true / false | **PASS** | - |
| OPS-20 流量统计 | bash=0 / go=0 | bash: - ‖ go: - | - / - | **PASS** | - |
| OPS-21 流量阻断 | bash=- / go=- | bash: - ‖ go: - | - / - | **PASS** | - |
| OPS-22 清除日志 | bash=0 / go=0 | bash: - ‖ go: - | - / - | **PASS** | - |
| OPS-23 服务器网速 | bash=- / go=- | bash: - ‖ go: - | - / - | **BLOCKED** | Bash menu 6>6 delegates to the idleleo Go binary, so this is not an independent Bash implementation; delegation observed=False |
| OPS-24 刷新GeoData | bash=- / go=- | bash: - ‖ go: - | - / - | **BLOCKED** | Bash GeoData menu refreshes from the hard-coded public GitHub release; this isolated job has no public origin; bash output shows the GeoData menu, bytes=394494; go schedule status rc=0; real Go geodata refresh is covered by the ops sweep with a local origin |
| OPS-25 备份管理文件 | bash=- / go=- | bash: - ‖ go: - | - / - | **DIFF** | Bash backup operates on the managed tree (tar archive); Go backup operates on JSON metadata; bash rc=0; go rc=0 |
| OPS-26 恢复管理文件 | bash=- / go=- | bash: - ‖ go: - | - / - | **DIFF** | Bash restore/import operates on the managed tree (tar archive); Go restore/import operates on JSON metadata; bash rc=0; go rc=0; restore canary present=True; go import state=IMPORTED |
| OPS-27 清空证书文件 | - | - | - | **NOT-RUN** | 未执行，不得视为通过 |
| OPS-28 卸载 | bash=0 / go=0 | bash: - ‖ go: - | - / - | **PASS** | - |
| OPS-29 Rill AI 状态 | bash=- / go=- | bash: - ‖ go: - | - / - | **PASS** | both sides returned Rill status |
| OPS-30 修改语言 | bash=0 / go=0 | bash: - ‖ go: - | - / - | **BASH-ONLY** | - |
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
| E1 config-edit-before-after | 0 | ee00debe10e0 → b424eb2e62f9 | editRcZero:ok, configChanged:ok, uuidApplied:ok, shareUriUpdated:ok, serviceActive:ok, backupExists:ok | ok / ok | **PASS** | Go 独有能力，bash 侧无 UUID 非交互入口；判定只看 Go 改前/改后与 L4。 |
| E2 config-edit-restart-rollback | 1 | b4d849bb7694 → b4d849bb7694 | editRcNonZero:ok, rollbackReported:ok, configRestored:ok, serviceActive:ok | ok / ok | **PASS** | 回滚后 SHA 还原 |
| E3 config-edit-target-probe-refused | 2 | f3d3b17eb062 → f3d3b17eb062 | probeRefused:ok, configRestored:ok, serviceActive:ok, noBackup:ok | ok / ok | **PASS** | 回源不可达被拒绝，零落盘 |
| E4 config-edit-target-probe-ok | 0 | 1b0a2779526b → e601c7445f84 | editRcZero:ok, configChanged:ok, targetApplied:ok, probeReported:ok, serviceActive:ok | ok / ok | **PASS** | 回源探测通过后落盘 |
| E5 config-edit-tls-cert-success | 0 | b63645a34743 → b63645a34743 | backupHasOldCert:ok, backupHasOldKey:ok, editRcZero:ok, fragmentUpdated:ok, probeOk:ok, runtimeUnchanged:ok, scheduleUpdated:ok, servicesActive:ok, tlsVersion13:ok, wireCertMatches:ok, xrayNotRestarted:ok | ok / ok | **PASS** | M4 的证书/域名编辑是前端所有，runtime JSON 必须逐字节不变且 Xray 不重启；旧对被备份到 edit-<ts>/。 |
| E6 config-edit-tls-rollback | 1 | 43a1ecf9f647 → 43a1ecf9f647 | backupHasOldPair:ok, configRestored:ok, guardRejected:ok, guardZeroWrites:ok, nginxRestored:ok, probeFailureRecorded:ok, rollbackRcNonZero:ok, scheduleRestored:ok, servedCertRestored:ok, servicesActive:ok | ok / ok | **PASS** | E6a 证明写前守卫零落盘；E6b 由 reload 静默未生效制造真实握手失败，证明写入后探针会触发 runtime/nginx/jobs.json 全量回滚且服务保持 active。 |
| E7 config-edit-shortid-transition | 0 | 9578b1061664 → 496363c87668 | baselineLinkWorks:ok, appendRcZero:ok, appendKeepsOldSid:ok, newLinkUsesNewSid:ok, appendRestartedService:ok, oldLinkWorksAfterAppend:ok, newLinkWorksAfterAppend:ok, removeRcZero:ok, oldSidGone:ok, removeRestartedService:ok, oldLinkFailsAfterRemove:ok, newLinkStillWorks:ok, serviceActive:ok | ok / ok | **PASS** | 推荐流程：追加新 id -> 客户端切换 -> 删除旧 id。追加与删除都会重启 Xray（秒级重连），但旧链接在旧 sid 仍被接受期间必须一直可用；探针用真实 xray 客户端 + 隧道内 TLS 握手 + 认证后的 HTTP 请求，避免 Reality 回退造成握手假通过。 |
| E8 config-edit-privatekey-rotate-rollback | 0 | 79e3fa1aca24 → eb152b4c5b64 | baselineLinkWorks:ok, rotateRcZero:ok, rotationReported:ok, oldLinkCaptured:ok, backupHasOldShareUri:ok, newLinkWorksAfterRotate:ok, oldLinkFailsAfterRotate:ok, faultEditFails:ok, failurePointRecorded:ok, rollbackProbeOk:ok, configRestored:ok, oldLinkWorksAfterRollback:ok, serviceActiveAfterCleanup:ok, serviceActive:ok | ok / ok | **PASS** | 轮换的断线窗口不可避免，输出必须提前打印旧链接。故障注入让重启加载旧配置副本：服务 active 但新 key/sid 未生效，只有真实客户端能发现；回滚后必须用旧链接再探通，这条是断言而不是日志。 |

- E1 SHA：改前 `ee00debe10e0d3ffca514f24335c259b4ff946f9de87a607909ca5eccd495a1f` → 改后 `b424eb2e62f9969884e329fbc0e536f2e5793e27aa99f23073b97b1650d37b27`（已变更）
- E2 SHA：改前 `b4d849bb76942b6fa78bc125ef644bbcb8801d31aaed354761c56c7e10b6dd78` → 改后 `b4d849bb76942b6fa78bc125ef644bbcb8801d31aaed354761c56c7e10b6dd78`（已还原）
- E3 SHA：改前 `f3d3b17eb0626be81ab6d8ce911967cbea5b13ed81b77e75adfc72a2314e405a` → 改后 `f3d3b17eb0626be81ab6d8ce911967cbea5b13ed81b77e75adfc72a2314e405a`（已还原）
- E4 SHA：改前 `1b0a2779526b95f41a4c8d9c78b9ecbc08d48a1d4b2a9ca96b4a84692613bd6b` → 改后 `e601c7445f843c2ee712f6c23bc33b7bb9ef8c537ba3b408666521435bb789c8`（已变更）
- E5 SHA：改前 `b63645a34743adfdc73cb828dc90f69ded3225a7c2e8658117c76a467a3b57c3` → 改后 `b63645a34743adfdc73cb828dc90f69ded3225a7c2e8658117c76a467a3b57c3`（已还原）
- E6 SHA：改前 `43a1ecf9f647f415ff80a138b5b0a9ce0e1b1d063d0e016f071a797b7f31634d` → 改后 `43a1ecf9f647f415ff80a138b5b0a9ce0e1b1d063d0e016f071a797b7f31634d`（已还原）
- E7 SHA：改前 `9578b106166456b4a677a437e701ff9fb09a7e87f75d8dbd136d8c5818ab62da` → 改后 `496363c8766899fc96546334655db61c3d17210710964448490d3909cd5fc365`（已变更）
- E8 SHA：改前 `79e3fa1aca24149825ca0a26588b591eec3ebbc570eb99f54e02d35f8b824bcb` → 改后 `eb152b4c5b6444d175be71d7680895db70584a899970a512db663821e7e92160`（已变更）

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
| M3 附加传输端口 | 444 | 10000 | 10471 | G9 |
| M7 附加传输端口 | 10086, 10087, 10088 | 10000, 10001, 11000 | 10284, 10939, 11801 | G9 |
| M4 TLS 回环端口 | 9000 | 10000（公网 443） | 10180 | G10 |
| E1/E2 配置编辑 | 无 | 2 场景 PASS（见上表） | — | G11 |

## 未覆盖/未验证

- 全部安装场景 eligible；M8 走真实本地 Pebble ACME，ACME 专属产物（cert/、.well-known、schedule/）两侧已对齐。
- L2 仅记录 sanitized config 摘要，未做全字段语义 diff；L3/L5 以采集件为准。
