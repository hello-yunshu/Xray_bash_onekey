# 收尾审计报告 — 迁移 / 安装 / ACME 事务（2026-11-08）

> 分支：`fix/go-parity-install-acme-closeout`（独立修复分支）
> 基线：`audit/bash-go-native-parity` @ `e21e824`（fetch 后核对一致）
> 约束遵守：未改 `main`、未打 tag、未发 Release、未触碰真实 VPS、未修改宿主网络/内核。
> 证据分级：Docker 容器验收（`DOCKER_*` / `ACME_LOCAL_CA` / `REAL_NGINX_REAL_XRAY_E2E`）与生产验收严格分开；F01–F28 未因容器结果升格为「已验证」。

## 1. 四个重点的结论

| 重点 | 结论 | 证据 |
|---|---|---|
| 迁移/管理不得无提示改配置 | 既有 `config.json` 默认拒绝重生成；`--keep-config` 原样接管、`--rewrite-config` 显式替换；`--from-config` 只重排缩进，值逐字段保持不变 | `TestAdoptRuntimePreservesEveryValue`、`TestExistingConfigIsNeverRegeneratedImplicitly`、A2 preserve 12 组 |
| Bash/Go 对照不能假阳性 | 按 tag 匹配 inbound，逐字段比对连接参数；证据全部来自容器内真实 Bash 安装；14 种篡改自检必须全部 GAP | `compare_real_runtime.py --self-test` → `SELFTEST_PASS mutations=14`；A2 12 组 `GAP=0 FAIL=0` |
| Reality 主备真装真连 | 真实 Nginx + 两个真实 Xray Reality 后端 + 真实客户端；轮询、故障承载、恢复重入、未知 SNI 拒绝全部通过；缺 Nginx 时安装直接拒绝 | `tests/go-parity/evidence/balance-e2e-2026-11-08/`，`e2e exit=0` |
| ACME 事务性 | 证书对原子替换；reload/写盘失败回滚旧对且仍可用；token 校验；权限 0644/0600；7 条负面路径全部符合预期 | `tests/go-parity/evidence/acme-2026-11-08-fix/`，`acme_rc=0` |

## 2. 包 A — 迁移对照与安全接管

**修复缺陷**
1. 旧对照器结构相同即 MATCH。新对照器逐 inbound（按 tag）比对：
   `listen/port/protocol/network/security`、ws `path/host`、grpc `serviceName/multiMode/idleTimeout`、
   xhttp `path/mode`、Reality `target/serverNames/shortIds/min/maxClientVer/fingerprint/spiderX`、
   clients 多集、routing `inboundTag`、顶层 `log/dns/policy/outbounds`；任一值不同 → `GAP`。
2. 证据来源改为 systemd 容器内**真实交互式 `install.sh`** 产物；Bash 侧只导出脱敏副本与
   `identity.json`（uuid/publicKey/shortIds 的 SHA-256），不再出现“手写 JSON 当真实产出”。
3. 新增 `idleleo xray generate --from-config`；拒绝不可运行配置（空 inbound、端口越界、
   重复 tag、重复 `listen:port`、非法 UUID、未知 security、非法 Reality key）。
4. 安装路径遇到既有配置默认拒绝，必须显式选择保留或改写。

**结果**
- 6 拓扑 × fresh/preserve = 12 组：`exit=0`，`{"MATCH":0,"MATCH_CORE_FIELDS":1,"MATCH_STRUCTURE_UNCOVERED":11,"GAP":0,"FAIL":0,"UNSUPPORTED":0}`。
  11 组 UNCOVERED 的原因是 Bash 私有字段已脱敏，指纹无法比对，未升格为 MATCH。
- 自检：`SELFTEST_PASS mutations=14 baseline=MATCH`。
- 证据：[`tests/go-parity/evidence/a2-2026-11-08-fix/`](../../tests/go-parity/evidence/a2-2026-11-08-fix/)。

## 3. 包 B — Reality 主备与 Nginx 安装闭环

**修复缺陷**
1. Nginx 必需模式（`tls` / `reality-nginx` / `reality-balance --role primary`）缺前端时
   **在落盘前拒绝**：必须 `--external-nginx-managed` + `--nginx-bin`。
2. `nginx -t` 真实校验生成物；失败触发整体回滚（文件备份 + journal）。
3. 修正 `ssl_reject_handshake` 归属：属于 `ngx_http_ssl_module`，只能从 `http{}` include；
   此前 Go 把它插入 `stream{}`，nginx 直接拒绝。
4. 修正 Reality target 缺端口（归一化为 `host:443`）与 `--backend` 覆盖固定 primary
   `127.0.0.1:9443` 的问题（改为 primary 恒定 + 追加 extras）。
5. 新增容器 e2e：真实 nginx、两个真实 Reality 后端、真实客户端。

**结果（`e2e exit=0`）**
```
PASS nginx -t accepted the generated stream artifacts
INFO round-robin http200=6/6 primary=5 secondary=4
PASS both backends served real Reality traffic
INFO secondary-down http200=8/8 primary=13 secondary=4
PASS traffic continued on the primary after secondary failure
INFO recovered http_ok=13/13 primary=25 secondary=6 rejoined=1
PASS secondary rejoined and served traffic after recovery
PASS unknown SNI refused (openssl exit 1)
```
证据：[`balance-e2e-2026-11-08/`](../../tests/go-parity/evidence/balance-e2e-2026-11-08/)，
`environment.txt` 标注 `REAL_NGINX_REAL_XRAY_E2E / container_only=1 / host_network_modified=0 / kernel_modified=0 / container_egress_required=1`。
**容器结果不等于生产可用**：真实双机 VPS、真实 Nginx 主配置接线、公网端口仍待生产验收。

## 4. 包 C — ACME 证书对事务

**修复缺陷**
1. 证书/私钥分两次独立写。改为：两文件先写临时文件并 `fsync`，证书 rename 后再 rename 私钥；
   私钥失败即回滚旧证书。
2. reload 失败时旧对已被新对覆盖。改为恢复整对旧证书，并在回滚自身失败时如实报告。
3. 回滚语义：旧文件读失败不得导致删除；仅删除确实不存在的文件。
4. HTTP-01 token 只允许 base64url 字母表（长度 1–256），拒绝路径穿越。
5. 权限强制：证书 `0644`、私钥 `0600`。

**结果（Pebble 本地 CA，最终代码重跑 `acme_rc=0`）**
- 签发成功、reload marker 写入；窗口内续期 `skipped=true`；强制续期 serial 变化且新证书验证通过。
- 负面全部符合预期：webroot 失效旧对哈希不变；reload 失败恢复旧对；恢复后的旧对仍通过
  链/SAN/私钥匹配（`old_pair_still_valid=YES`）；只读目标拒绝且不写证书；CA 拒绝域名且不写证书。
- `cert_mode=644`、`key_mode=600`。
- 证据：[`acme-2026-11-08-fix/`](../../tests/go-parity/evidence/acme-2026-11-08-fix/)，
  `repo_commit=3d07613`，标注 `ACME_LOCAL_CA`。

## 5. 包 D — 全量门禁

| 门禁 | 命令 | 结果 | 证据 |
|---|---|---|---|
| 格式/静态/单测 | `gofmt -l .; go vet ./...; go test ./...`（容器 `golang:1.24`） | `gate_rc=0`，gofmt 无输出，全部包 ok | [`closeout-2026-11-08/go-gate.log`](../../tests/go-parity/evidence/closeout-2026-11-08/go-gate.log) |
| Bash 对照矩阵 | `tests/go-parity/matrix/run_matrix_container.sh` | `matrix_rc=0`，104 = 54 MATCH + 40 MATCH_CORE_FIELDS + 4 REFUSED + 6 A1_PASS | [`matrix.log`](../../tests/go-parity/evidence/closeout-2026-11-08/matrix.log)、[`matrix-summary.json`](../../tests/go-parity/evidence/closeout-2026-11-08/matrix-summary.json) |
| A2 真实 runtime | `compare_real_runtime.py --evidence .../a2-2026-11-08-fix --go-bin ...` | `exit=0`，0 GAP/FAIL | [`a2-compare.json`](../../tests/go-parity/evidence/closeout-2026-11-08/a2-compare.json) |
| ACME 正负路径 | `tests/go-parity/acme/run_acme_container.sh` | `acme_rc=0`，7/7 negative true | [`acme.log`](../../tests/go-parity/evidence/closeout-2026-11-08/acme.log) |
| Reality 主备 e2e | `tests/go-parity/balance/run_reality_e2e.sh` | `e2e_rc=0`，5/5 PASS | [`balance-e2e.log`](../../tests/go-parity/evidence/closeout-2026-11-08/balance-e2e.log) |

矩阵环境：`repo_commit=3d07613`、`repo_dirty=2`（仅未跟踪的 `.workbuddy/` 与 `docs/plans/`，
不参与提交）、`docker_arch=arm64`、`test_image=sha256:872befbc…`。

## 6. F01–F28 覆盖变化

本轮只改两个 F 项状态，其余保持原标签：

| ID | 旧 | 新 | 依据 |
|---|---|---|---|
| F04 Reality 主备 | 未实现 | 部分实现（容器级） | 真实 nginx + 双 Xray + 真实客户端 e2e；仍非真实 VPS 双机 |
| F12 证书签发/续期 | 未实现（有到期监控） | 部分实现（本地 CA） | Pebble 真实 ACME 全流程 + 7 条负面；公网 CA/DNS-01/EAB 未验收 |

其余 F01–F28 不变，**没有一项被容器结果升格为「已验证」**。

## 7. 遗留问题

1. Reality 主备未在真实双机 VPS 验收；Nginx 主配置接线（`include`、reload、`chown`/`chmod`）
   仍由运维或 Bash 负责。
2. ACME 只用 Pebble 本地 CA；公网 CA、DNS-01、EAB、真实 DNS 解析、Bash 的
   `idleleo-nginx` 组与联动重启未验证。
3. `--keep-config` 与需要 Nginx 的模式组合会拒绝（必须先 `--rewrite-config`），这是
   保守策略而非缺陷，但会改变既有操作习惯。
4. A2 的 11 组仍为 `MATCH_STRUCTURE_UNCOVERED`（Bash 侧 Reality 私钥/UUID 脱敏，
   无法做身份指纹比对）；需要在受控环境中提供可验证指纹才能升格。
5. 矩阵 `repo_dirty=2` 来自未跟踪辅助目录；提交树本身干净。

## 8. 本轮全部 Commit

| Commit | 内容 |
|---|---|
| `812bb25` | 包 A：逐字段 A2 对照器 + 真实 Bash 证据 + `--from-config` 无损接管 + 安装拒绝静默覆盖 |
| `53b6191` | 包 B：Nginx 必需模式 fail-closed + `nginx -t` 真实验证 + isolate 归 http + target/upstream 修复 + Reality 主备 e2e |
| `3d07613` | 包 C：ACME 证书对原子替换/回滚/权限 + token 校验 + Pebble 正负测试 |
| （本报告提交） | 包 D：全量门禁证据归档、F04/F12 覆盖更新、决策记录 D-016–D-018 |
