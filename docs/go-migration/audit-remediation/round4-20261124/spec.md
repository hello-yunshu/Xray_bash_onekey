# 第四轮审计收尾：补齐真实业务事实证据（实施规格）

- 状态：待批准
- 分支：`work/go-hardening-parity-20261119`
- 冻结候选：`5041511998575851eb5cb16533e9fe999d29d5a8`
- 约束：不放松验收口径、不补写退出码、不自行批准差异、不改 rank 规则、不扩展无关功能

## 1. 目标与边界

当前账本 13 DUAL / 3 GO_ONLY / 13 FAIL / 5 BLOCKED。剩余可自主消除的缺口只有两类：

1. OPS-04/08/10/32 运行 PASS 但 `ops.json` 没有 `details.<side>` 业务事实块，被 `build_ledger.py` 判为 BLOCKED。
2. OPS-01/02 没有“新增用户真实连通”的证据，业务事实 `clientConnected` 缺失。

本规格只补齐**已经存在真实观测**但未写入证据的业务事实，不新增产品功能，不改变任何 PASS 判定条件，不触碰产品代码（`cmd/`、`internal/`、`install.sh`）。

13 行差异/单侧证据的重新批准仍是用户决策，保持 `APPROVAL_PENDING`。

## 2. 逐项设计

### WP-1 OPS-10 `details.<side>.serverNames`

- 文件：`tests/e2e-diff/run_p2_matrix.sh` → `ops_generic_verdict()`（约 1244–1309 行）
- 现状：已从 `nginx -T` 的 `after` 快照取到 `b_after` / `g_after`，即真实落盘的 `"<domain> reality;"` 片段。
- 改动：在 OPS-10 分支写入
  `report["details"] = {"bash": {"serverNames": b_after}, "go": {"serverNames": g_after}}`。
- 证据来源：`$EVID/OPS-10/{bash,go}/after.nginx-dump.txt`（`ops_snapshot` 生成）。
- 验收：`details` 两侧 `serverNames` 非空；OPS-10 从 BLOCKED 升为 DUAL（仅当双端 rc=0 且无 reasons）。

### WP-2 OPS-04 `portListening` / `clientConnected` / `shareInfo`

- 文件：`tests/e2e-diff/run_p2_matrix.sh`
  - `ops_simple_job()`（约 1356–1429 行）
  - `ops_generic_verdict()` OPS-04 分支（约 1092–1176 行）
- 现状：
  - `listening(side,"after",8443)` 已由 `listens.txt` 真实测得；
  - `L4-8443.rc` / `connectivity.json` 已由 `ops_l4` 真实产生；
  - Go 分享链接已有 `go/share-8443.json` 的 `shareUri`；
  - Bash 侧没有采集分享链接。
- 改动：
  1. `ops_simple_job` Bash OPS-04 分支：容器销毁前执行
     `docker exec <bserver> bash /etc/idleleo/install.sh -s`，输出存 `$bdir/share-bash.txt`（rc 存 `share-bash.rc`）。
  2. 同一分支用 `grep -oE 'vless://[^[:space:]]+'` 解析出链接存 `$bdir/share-bash.uri`；解析不到就留空，不伪造。
  3. 判定器 OPS-04 分支写
     `details.<side> = {portListening: listening(side,"after",8443), clientConnected: (L4-8443.rc==0 and connectivity ok), shareInfo: <非空 URI 字符串>}`。
     - bash `shareInfo` 读 `share-bash.uri`；go 读 `share-8443.json` 的 `shareUri`。
- 判据不放松：仍要求原有 `nginx listen 8443`、`443 已释放`、`xray active`、重复编辑无副作用、越界端口被拒。
- 验收：两侧 `portListening=true`、`clientConnected=true`、`shareInfo` 非空；否则该侧仍 BLOCKED 并记录原因。

### WP-3 OPS-08 `details.<side>.sniProbe`

- 文件：`tests/e2e-diff/run_p2_matrix.sh`
  - `ops_state_probe()`（约 1436–1456 行）
  - `ops_state_verdict()`（约 1528–1683 行）
- 现状：已采集 `sni-policy.txt`、`sni-files.txt`（含 `ssl_reject_handshake on`）、`nginx-active.txt`，但没有真实 TLS 探测结果。
- 改动：
  1. `ops_state_probe` 在 OPS-08 下对容器内 `127.0.0.1:443` 执行两次真实探测：
     - 已知 SNI：`openssl s_client -connect 127.0.0.1:443 -servername "$TARGET" -brief </dev/null`，输出 `sni-known.txt`、rc `sni-known.rc`；
     - 未知 SNI：`-servername "e2e-unknown.invalid"`，输出 `sni-unknown.txt`、rc `sni-unknown.rc`。
  2. 判定器写
     `details.<side> = {"sniProbe": {"knownSniOk": <known rc==0 且握手成功>, "unknownSniPolicy": <从 sni-unknown 输出提取的可读结论，如 "ssl_reject_handshake" 或 "handshake-failed">, "knownRc":…, "unknownRc":…}}`。
  3. `unknownSniPolicy` 必须来自真实输出；探测缺失时该侧不写 `sniProbe`，保持 BLOCKED。
- 判据不放松：仍校验两侧 policy=isolate、fragment 含 `ssl_reject_handshake on`、nginx active。
- 验收：两侧 `sniProbe` 为 dict、`knownSniOk=true`、`unknownSniPolicy` 非空。

### WP-4 OPS-32 `details.<side>.faultRemoved` / `recovered`

- 文件：`tests/e2e-diff/run_p2_matrix.sh` → `ops32_merge()`
- 现状：上游各自 `ops.json` 已有真实测量：`removedAt.<side>`（有 worker 达到 `max_fails` 且进入 `fail_timeout` 静默）、`stableRecovery.<side>.reached`（完整恢复窗口内的稳定 A 响应链）。
- 改动：`ops32_merge` 读取 ws/reality 两个上游记录后写
  `details.<side> = {"faultRemoved": <两个上游 removedAt[side] 均非空>, "recovered": <两个上游 stableRecovery[side].reached 均为 true>, "removedAt": {...}, "recoveredAt": {...}}`。
- 不改动 `ops32_analyze.py` 的测量规则与 PASS 条件。
- 验收：两侧 `faultRemoved=true`、`recovered=true`；否则保持 BLOCKED，并保留缺失原因。

### WP-5 OPS-01/02 新用户真实 VLESS 连通

- 文件：
  - `tests/e2e-diff/collect/client_config.py`
  - `tests/e2e-diff/collect/l4.sh`
  - `tests/e2e-diff/run_p2_matrix.sh` → `ops_users_job()`、`ops_users_verdict()`
- 现状：`client_config.py` 固定取 `clients[0]`，因此无法证明“刚新增的用户”可连接。
- 改动：
  1. `client_config.py` 新增 `--email` 与 `--uuid`；提供时按 `email`（或 `uuid`）在 `clients` 中精确选中该用户，选中失败以非 0 退出并打印可用 email 列表。不提供时保持 `clients[0]` 旧行为。
  2. `l4.sh` 透传 `E2E_L4_EMAIL` / `E2E_L4_UUID` 到 `client_config.py`。
  3. `ops_users_job` 在新增用户成功后，对 Bash/Go 各自调用 `l4.sh`（同一网络、同端口），产物 `$side/L4-user.rc`、`L4-user/connectivity.json`。
  4. `ops_users_verdict` 在 `details.<side>` 增加
     `clientConnected = (L4-user.rc==0 且 connectivity.json 的 ok 为 true)`，并保留 `addedClients`/`removedClients` 真实计数。
- 判据不放松：新增/删除计数仍由真实 `xray user list`/菜单输出对比得出；删除后仍要求残留检查按现状记录。
- 验收：两侧 `addedClients>0`、`removedClients>0`、`clientConnected=true`；任一缺失仍 BLOCKED。

## 3. 执行与验证

1. 先做静态验证：`python3 -m py_compile client_config.py`；`bash -n run_p2_matrix.sh l4.sh`。
2. 用新运行标识（不复用旧 EVID）在冻结候选上重跑受影响行：
   `E2E_RUN_ID=round4-bizfacts-<候选前8位> E2E_ONLY=OPS-01,OPS-02,OPS-04,OPS-08,OPS-10,OPS-32 bash tests/e2e-diff/run_p2_matrix.sh`
3. 每个 OPS 逐行核对：`ops.json` 的 `verdict`、`reasons`、`details.<side>`；保留真实日志。
4. 重建账本（带 `--allow-repo-write`），确认目标行变为 DUAL 或仍诚实 BLOCKED，且其他行计数不因本次改动而变化。
5. 更新 `FINAL_AUDIT_20261124.md`、`defects.json`、`evidence-index.json`、`TRAE_PROGRESS.md`，提交并 push 当前开发分支。
6. 禁止：合并主线、打 tag、正式发布、操作生产 VPS、自行批准 13 行差异。

## 4. 失败处理

- 若某观测实际不成立（如未知 SNI 未拒绝、分享链接为空、用户无法连接），该行保持 BLOCKED/FAIL，并把真实原因写入 `reasons`，不放宽判据。
- 若 `client_config.py` 选用户失败，记录为 harness 原因而非产品结论。
- 若重跑出现与上一轮不一致，先复现再判断，禁止用旧证据替代本次运行。

## 5. 需要用户批准的事项

- 本规格本身（批准后执行 WP-1…WP-5）。
- 13 行差异/单侧证据的批准不在本规格内，执行结束后仍以 `APPROVAL_PENDING` 交付。
