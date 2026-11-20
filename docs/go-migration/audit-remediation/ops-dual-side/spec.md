# Spec: OPS 双侧补齐（可执行项）与不可执行项如实记录

状态：待批准（Spec Mode）
分支：`work/go-hardening-parity-20261119`（HEAD `43f87615`，PR #182 保持 draft）
目标：在不新增依赖/框架、不使用 mock、不降低断言的前提下，把 OPS 矩阵中**可执行**的行补齐为双侧证据；对网络/能力受限的行给出明确的 BLOCKED/NOT-RUN，不伪造 PASS。

## 1. 结论边界（不得改变）

以下项在任何情况下都不得声明完成或 PASS，只能记录为 BLOCKED，并在最终报告中单列：

- 生产 VPS/VM 断电恢复
- 公网 CA 真实签发
- 纯 Bash ACME（镜像无 acme.sh，且 runner 不允许联网获取）
- 外部 IPv6 联通
- 正式 release / tag / 合并 / 生产部署授权

同时保留既有结论：
`dockerDevelopmentCandidate=NO_GO_FOR_DOCKER_QUALIFIED_CANDIDATE`、`formalRelease=NO_GO_NOT_AUTHORIZED`。

## 2. 判定语义（所有新增代码必须遵守）

| 结果 | 条件 |
| --- | --- |
| `PASS` | 同一次容器运行内，Bash 与 Go 两侧都有观测；所有断言为真 |
| `BLOCKER` | 两侧都有观测，但至少有 1 条断言为假 |
| `HARNESS-ERROR` | 证据缺失、超时、driver `exit 124`、JSON 不可解析 |
| `BLOCKED` | 前置能力缺失（如无 nginx、无公网、无 cron），且已记录缺失原因 |
| `NOT-RUN` | 没有执行路径（如嵌套 file_manager 菜单未被驱动） |
| `BASH-ONLY` | 仅 Bash 侧观测；不得计入 dualSide |

规则：
1. 断言只能新增，不能降低或删除。
2. 任一侧缺失证据 → `HARNESS-ERROR`，绝不允许另一侧单独读成 `PASS`。
3. `go: null` 的行保持 `go-missing`，不得用 Go 独有命令冒充对应语义。

## 3. 变更清单

### 3.1 新增 `tests/e2e-diff/drivers/bash_ops.exp`

用途：驱动**真实** `install.sh` 的配置变更菜单，为 OPS-04/05/06/07/10/17c/30 产生 Bash 侧观测。

通用约束（复用 `bash_menu.exp` 的既有契约）：
- 每步先匹配 prompt 再发送应答，禁止盲发回车；
- 未匹配 prompt、EOF、超时 → `HARNESS-ERROR` 并 `exit 124`；
- 业务失败 → `exit 1`；
- 前置缺失（如未装 Nginx、无 cron）→ 写 `blocked.json` 并 `exit 3`；
- 成功路径：动作完成后匹配 `回到菜单`，再匹配 `请输入选项` 并发送 `0` 退出。

环境变量：
`E2E_OPS_ID`、`E2E_LOG`、`E2E_TIMEOUT`（默认 900）、`E2E_TARGET`（默认 `www.cloudflare.com`）、`E2E_PORT_ALT`（默认 `8443`）、`E2E_UUID_LABEL`（默认 `e2e-uuid`）。

各 OPS 的精确流程：

| OPS | 菜单路径 | 匹配与应答 |
| --- | --- | --- |
| OPS-04 变更端口 | `2>2>2` | `确定端口` → 回车；`请输入端口` → `8443` |
| OPS-05 变更UUID/映射 | `2>2>1` | `是否需要自定义字符串映射` → `y`；`请输入自定义字符串` → `e2e-uuid`（≤30 字符） |
| OPS-06 变更target | `2>2>3` | `确认域名符合要求后请输入` → `$E2E_TARGET`；`是否仍要设置此域名` → `y`（离线校验分支）；`是否需要自定义 .*serverNames` → `n` |
| OPS-07 变更TLS版本 | `2>2>4` | 前置：`/usr/local/nginx/conf/nginx.conf` 存在且 `reality_add_nginx=on`，否则 `exit 3`；`请选择 TLS 版本` → `请输入[:：]` → `2`（TLSv1.2+） |
| OPS-10 serverNames | `2>3>2` | `是否变更 Nginx serverNames` → `y`；若出现 file_manager 的 `请选择一个选项`，发送 `5` 退出并写 `nested.json`，`exit 3`（不驱动嵌套菜单，不下 PASS） |
| OPS-17c 配置自动更新 | `5>4` | `自动更新|是否启用` → `y`；`(小时|间隔|分钟|cron)` → `1` |
| OPS-30 修改语言 | `8` | `请输入选项` → `1`；观测语言文件变化后 `0` 退出（该行 Go 无对应能力，最终记 `BASH-ONLY`） |

### 3.2 修改 `tests/e2e-diff/run_p2_matrix.sh`

新增函数（放在既有 `ops_bash_cli`/`ops_go_cli` 附近）：

1. `ops_base_install <side> <server> <dir> <profile>`
   - Bash：复用 `run_bash_round`（OPS-04/05/06/07 用 `M2` 以获得 Nginx；OPS-17c/30 用 `M1`）。
   - Go：`ops_go_cli ... 00-install xray install --binary ... --mode reality --domain ... --target ... --port 443 --container --json`。
2. `ops_bash_menu <server> <dir> <ops-id> <profile>`
   - 以 `expect -f /src/tests/e2e-diff/drivers/bash_ops.exp` 执行，记录 `.out/.rc`。
3. `ops_snapshot <server> <dir> <ops-id>`
   - 采集：`config.sorted.json`（`jq -S`，私钥/ID 脱敏）、`inbound-ports.txt`、`client-ids.txt`、`reality-target.txt`、`nginx-tls.txt`（`nginx.conf` 中 `ssl_protocols`）、`cron.txt`、`language.sha256`。
4. `ops_generic_verdict <ops-id>`
   - Python 读取两侧快照与 rc，按第 4 节规则产出 `$EVID/<OPS>/ops.json`。
5. `ops_simple_job <ops-id> <profile>`
   - 起双侧容器（同一 docker network）→ 基线安装 → Bash driver / Go CLI → 快照 → 判定 → 清理。

`ops_job` 增加分支：`OPS-04|OPS-05|OPS-06|OPS-07|OPS-17c|OPS-30` → `ops_simple_job`。
OIDS 调度列表追加上述 ID，保持 `E2E_ONLY` 子集语义不变。

### 3.3 修改 `tests/e2e-diff/matrix.json`

| OPS | 变更 |
| --- | --- |
| OPS-05 | `go` 改为 `["idleleo","xray","config","edit","--uuid","7a4ab30c-b199-4840-a31e-316f4f73a72b","--yes","--container","--json"]`；`verdict` 改为 `allowed-diff`；`notes` 记录“Bash 为 UUIDv5(字符串) 派生，Go 为字面 UUID，派生方式不同但都实现变更” |
| OPS-06 | `go` 改为 `["idleleo","xray","config","edit","--target","www.cloudflare.com:443","--yes","--container","--json"]`；`verdict` 改为 `allowed-diff`；`notes` 记录“回源探测失败时 Go 必须 rc=2 且零落盘，此情形记 BLOCKED，不得记 PASS” |
| OPS-07 | 保留 `go: null`，除非 preflight 实测存在 TLS 版本子命令（见 5.1），否则仍为 `go-missing` |
| OPS-10 | 保留 `go: null`，同上 preflight；嵌套 file_manager 未被驱动时该行最多 `NOT-RUN` |
| OPS-17b | `go` 改为 `["idleleo","update","nginx","--container","--json"]`，仅当 5.1 preflight 确认子命令存在 |
| OPS-30 | 保持 `go: null`（Go 无语言能力），最终记 `BASH-ONLY` |

### 3.4 新增 `tests/e2e-diff/run_soak.sh`

30 分钟浸泡，单容器、M1 Reality 安装完成后每 60 秒一次检查，共 30 次：

- `systemctl is-active xray` == `active`
- `xray -test -config /etc/idleleo/conf/xray/config.json` rc=0
- `ss -lnt` 中存在监听端口 443
- `systemctl show -p NRestarts --value xray` 不增长
- RSS（`systemctl show -p MainPID` + `/proc/<pid>/status` VmRSS）< 512 MiB

输出 `soak.json`：`iterations`、`failedIteration`、`firstFailureReason`、`verdict`。
任一次失败 → `BLOCKER`；超时/容器退出 → `HARNESS-ERROR`。

### 3.5 新增 `tests/e2e-diff/run_xray_versions.sh`

多版本 Xray 验证（真实下载，无 mock）：

- 通过 GitHub Releases API 取最近 3 个稳定版本 + 当前锁定版本 `26.10.31`；
- 按宿主架构下载 `Xray-linux-64.zip`（amd64）/`Xray-linux-arm64-v8a.zip`（arm64）；
- 记录每个版本的 `tag`、`sha256`、`asset`；
- 每个版本：Go 侧 `xray install --mode reality` + Bash 侧 `run_bash_round M1`（二进制用该版本）；
- 断言：两侧 rc=0、`xray -test` rc=0、服务 active、配置可解析；
- 任一下载或校验失败 → 该版本 `BLOCKED`（记录原因），不影响其他版本记录；
- 输出 `xray-versions.json`。

### 3.6 新增 `tests/e2e-diff/image/Dockerfile.debian12`

第二发行版：`FROM debian:12`，安装与 Ubuntu 镜像等价的 systemd/expect/pexpect/nmap/cron/jq/nftables 依赖；构建 tag `idleleo-e2e:debian12`；先只跑 `E2E_ONLY=M1,OPS-19` 双证实装链路，通过后记录到验收文档。依赖名不可用则如实记 BLOCKED，不得用 Ubuntu 结果替代。

### 3.7 文档与看板

更新：
- `docs/go-migration/audit-remediation/DOCKER_ACCEPTANCE_20261120.md`：新增 §6.2 OPS 双侧补齐结果、§6.3 soak/多版本/第二发行版。
- `docs/go-migration/audit-remediation/TRAE_PROGRESS.md`
- `docs/go-migration/audit-remediation/TEST_EVIDENCE.md`
- `docs/go-migration/audit-remediation/PARITY_MATRIX.csv`
- `docs/go-migration/audit-remediation/acceptance.json`

计数口径：只有第 2 节 `PASS` 行计入 `dualSideVerifiedOps`；`BASH-ONLY`、`BLOCKED`、`NOT-RUN` 不计。

## 4. 各 OPS 判定断言（ops_generic_verdict）

| OPS | 断言 |
| --- | --- |
| OPS-04 | bash rc=0；go rc=0；两侧 `inbounds[].port` 均含 8443；两侧服务 active |
| OPS-05 | bash rc=0；go rc=0；两侧 client id 均较基线变化且为合法 UUID；Bash 侧记录 UUIDv5 label |
| OPS-06 | bash rc=0；go rc=0 且两侧 `realitySettings.target`/`serverNames` 一致；go rc=2 → BLOCKED（探测拒绝） |
| OPS-07 | bash rc=0；`nginx.conf` 的 `ssl_protocols` 含 `TLSv1.2`；Go 侧无命令 → `go-missing`，不下 PASS/BLOCKER |
| OPS-17c | bash rc=0；两侧 `crontab -l` 均出现自动更新任务；间隔语义一致（3600s ≈ 每小时） |
| OPS-30 | 仅 bash rc=0 且语言文件发生变化 → `BASH-ONLY` |

## 5. 验证步骤（批准后按序执行）

### 5.1 能力 preflight（先做，决定 3.3 是否生效）

在 e2e 镜像内执行并保存输出到 `$EVID/preflight/`：

```bash
docker run --rm idleleo-e2e:24.04 sh -c 'idleleo xray tls --help; idleleo xray config edit --help; idleleo update --help'
```

- 若 `xray tls` 无版本相关子命令 → OPS-07 维持 `go-missing`。
- 若 `xray config edit` 无 `--server-names` → OPS-10 维持 `go-missing`。
- 若 `update nginx` 不存在 → OPS-17b 维持 `go-missing`。
- 只有实测存在的命令才写入 matrix.json。

### 5.2 分组 E2E（每步都用新的 `E2E_RUN_ID`）

```bash
E2E_ONLY=OPS-04,OPS-05 bash tests/e2e-diff/run_p2_matrix.sh
E2E_ONLY=OPS-06,OPS-07 bash tests/e2e-diff/run_p2_matrix.sh
E2E_ONLY=OPS-17c,OPS-30 bash tests/e2e-diff/run_p2_matrix.sh
```

每组要求：无 `HARNESS-ERROR`；Bash rc 与 Go rc 符合第 4 节；`ops.json` 可解析。

### 5.3 全量 OPS 回归

```bash
E2E_ONLY=OPS-04,OPS-05,OPS-06,OPS-07,OPS-17c,OPS-30,OPS-19,OPS-21,OPS-09,OPS-31,OPS-32 \
  bash tests/e2e-diff/run_p2_matrix.sh
```

要求：既有 OPS-09/19/21/31/32 结论不退化。

### 5.4 子脚本 S4–S9 与 S1–S3 映射

```bash
bash tests/e2e-diff/run_s_scripts.sh
```

- S4–S9 需真实网络；缺网/缺端点 → 该 S 记 `BLOCKED` 并写原因。
- S1–S3 直接引用同批次 OPS-19/21/09/31 证据，不重复造数据。

### 5.5 soak / 多版本 / 第二发行版

```bash
bash tests/e2e-diff/run_soak.sh
bash tests/e2e-diff/run_xray_versions.sh
E2E_IMAGE_TAG=idleleo-e2e:debian12 E2E_ONLY=M1,OPS-19 bash tests/e2e-diff/run_p2_matrix.sh
```

### 5.6 收尾

1. 更新 3.7 全部文档与看板，JSON 用 `python3 -m json.tool` 校验。
2. `git add -A && git commit -m "test(e2e): add dual-side OPS drivers and soak/version gates"`。
3. `git push origin work/go-hardening-parity-20261119`。
4. 观察新 HEAD 的 7 个工作流全部通过；失败则修到通过，不跳过。
5. 输出中文最终报告：dual-side 计数、BLOCKED 清单、三个硬结论不变。
6. PR #182 保持 draft；不合并、不打 tag、不发 release。

## 6. 风险与回退

- 交互 prompt 与实现漂移：driver 只按已核实的正则匹配；未匹配即 124，不猜测。
- 嵌套 file_manager：OPS-10 只取一级观测并记 `NOT-RUN`，不声明 PASS。
- 网络下载抖动：多版本/第二发行版按单项 BLOCKED 记录，可重跑，不影响其他项。
- 回退：所有改动仅在测试与文档目录，`install.sh` 与 `internal/` 业务代码不改；如需回退直接 revert 本批次提交。

## 7. 明确不做

- 不改 `install.sh` 行为、不改 Go CLI 语义；
- 不为通过测试放松任何断言；
- 不使用 mock、不使用睡眠替代真实握手；
- 不把单侧结果计入 `dualSideVerifiedOps`。
