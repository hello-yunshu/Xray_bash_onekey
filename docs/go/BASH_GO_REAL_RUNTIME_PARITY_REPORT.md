# Bash → Go 原生运行时对照与验收报告（2026-11-08）

> 本报告汇总 A/B/C/D 四个工作包的真实执行结果。**证据等级严格分级**，
> Docker 容器级结果不等于生产签收；F01–F28 的正式签收计数仍为 **0 / 28**。

## 0. 结论摘要

**Go 能否正式接管 Bash？**

- **可以接管**：配置生成（含 `ws+gRPC+xHTTP` 多入口）、安装元数据读取、迁移状态机
  （Audit→Prepare→Validate→Activate→Recover/Rollback）、服务原语、GeoData 刷新、
  Stats 读取、systemd timer、跨进程安装事务恢复，以及本轮新增的 TCP 安全子集。
- **尚不能全量接管**：真实 ACME 签发/续期、Xray/Nginx 自动升级执行器、Fail2ban、
  流量阻断、备份/恢复 CLI、Docker 交付路径仍缺实现或真实验证。
- **正式接管门槛未达**：没有任何一项达到 `REAL_VPS_VERIFIED`；
  F01–F28 正式签收 **0/28**。生产替换前必须先补齐第 9 节的阻塞项。

| 工作包 | 结论 | 最高证据等级 |
|---|---|---|
| A：真实 Bash 配置 vs Go 管理器 | 基线 98 项：`MATCH 2 / MATCH_CORE_FIELDS 32 / GAP 60 / REFUSED 4` | `BASH_EXECUTED` + `GO_EXECUTED` |
| A2：真实交互式主安装 runtime | 6 个真实拓扑：`MATCH 2 / MATCH_CORE_FIELDS 4 / GAP 0 / UNSUPPORTED 0`；TLS/reality-nginx 因真实域名/ACME 未捕获 | `BASH_EXECUTED` + `GO_EXECUTED` |
| B：兼容差异与故障恢复 | 修复后 `MATCH 54 / MATCH_CORE_FIELDS 32 / GAP 8 / REFUSED 4`；B3 多入口实现后复跑 `54 / 40 / 0 / 4` | `GO_EXECUTED` |
| C：Docker 真实服务与完整迁移 | Phase 01–04 合计 **330 / 332**，Bridge 状态机与故障注入全部真实执行 | `DOCKER_SERVICE_VERIFIED` / `DOCKER_MIGRATION_VERIFIED` |
| D：TCP 原生 + 辅助脚本审计 | 20 项单测 + 30 项容器断言全绿；14 个脚本迁移判定表完成 | `GO_EXECUTED` + `DOCKER_MOCK_APPLY` |

## 1. 范围、基线与环境

- 基线：`develop/go-native`，本轮从 `dd97eb1` 拉出 `audit/bash-go-native-parity`。
- Bash 行为基线：`install.sh` v3.3.6 pin `0fa7052e`。
- 宿主：macOS arm64，Docker 29.8.2（OrbStack，容器内核 7.2.12）。
- Go 工具链：`go1.24.13`（`idleleo-phase01-test:1.24`）。
- 真实组件：Xray 26.10.31（linux/arm64，SHA-256
  `5939649960deaf535bcd5f7ce0467a2b1d63b72a2758a6f42eade714ae8d5328`，见
  [phase02.log](../../tests/go-parity/evidence/c-2026-11-08/phase02.log)）、
  Nginx 1.24.0（Ubuntu 24.04.5 LTS）。
- 对照夹具 ZIP SHA-256：`20f386a4e5696663ea704f0de818d1d28e3e92aa81cc91f6bf05339e9cc1089a`。
- 矩阵 runner：基线用 ZIP 自带 `run_in_local_docker.sh`；该脚本未传
  `--listen-address/--public-security/--user`，会在修复后把合法调用误判为失败。
  仓库内修正版为 [run_matrix_container.sh](../../tests/go-parity/matrix/run_matrix_container.sh)，
  修复后结果用该 runner 复跑，原版缺陷保留记录。
- **after-fix 证据 provenance 修正（复检发现）**：原证据记录的
  `repo_commit=7b15c83…` 在仓库中不存在。复检在真实 HEAD `ace4a16` 上用仓库修正版
  `run_matrix.py`（bind-mount 覆盖缓存镜像构建时烤入的旧副本）重跑，状态仍为
  `MATCH 54 / MATCH_CORE_FIELDS 32 / GAP 8 / REFUSED 4`，已替换
  [after-fix/environment.txt](../../tests/go-parity/evidence/matrix-2026-11-08/after-fix/environment.txt)
  与 `summary.json`。直接运行缓存镜像得到
  `MATCH 13 / MATCH_CORE_FIELDS 32 / GAP 44 / GO_FAILED 5 / REFUSED 4`
  是镜像内旧脚本所致，**不得作为证据**。
- 未触碰：main、Release、真实 VPS、宿主机网络与内核。

**证据等级定义**

| 等级 | 含义 |
|---|---|
| `SOURCE_REVIEWED` | 仅阅读源码 |
| `BASH_EXECUTED` | 真实执行 Bash/真实 `install.sh` |
| `GO_EXECUTED` | 真实构建并执行 Go 二进制/测试 |
| `DOCKER_SERVICE_VERIFIED` | 容器内真实 systemd + 真实 Xray/Nginx 服务 |
| `DOCKER_MIGRATION_VERIFIED` | 容器内完整迁移状态机与回滚 |
| `DOCKER_MOCK_APPLY` | 容器内执行，但副作用重定向到 sandbox（TCP） |
| `HOST_NOT_VERIFIED` | 本次未做真实 VPS/宿主内核验收 |

## 2. A 包：真实 Bash 生成配置，交给当前 Go 管理器

**做了什么**

1. 在干净克隆中运行真实 Bash 安装元数据生成与 relay 渲染；
2. 用当前 Go `generate` / `relay` 对同一组输入生成配置；
3. 按 case 逐字段比对，状态分为 `MATCH / MATCH_CORE_FIELDS / GAP / REFUSED`。

**结果（98 个 case）**

| 状态 | 基线 |
|---|---|
| `MATCH` | 2 |
| `MATCH_CORE_FIELDS` | 32 |
| `GAP` | 60 |
| `REFUSED` | 4 |

**口径说明**

- `REFUSED` = Go 以非零退出码**正确拒绝**非法输入（空 `serverName`、端口 `0`、
  端口 `65536`、奇数长度 `shortId`），4 个用例即 4 个负例，**不是迁移失败或缺口**。
- `MATCH` / `MATCH_CORE_FIELDS` / `GAP` / `REFUSED` 均以 98 个 case 为分母：
  基线 `2+32+60+4=98`，修复后 `54+32+8+4=98`，统计口径一致。
- 覆盖边界：98 个 case 覆盖 4 种 mode × 5 种 transport、relay、share 与 4 个负例；
  **没有**覆盖 IPv4/IPv6 绑定、hostname 校验、1/4/20 用户与主备负载均衡。
  这些只能由 Phase 02/03 与 Bash 专项测试部分覆盖，不能从本矩阵推断。

基线暴露出三类真实差异：

- relay 监听地址语义不一致（Go 未保留 `127.0.0.1` / IPv6 绑定）；
- relay 片段结构与 Bash 不同（缺少 `proxy_timeout 720m`、
  `proxy_socket_keepalive on`，上游写法不同）；
- `share` 在 loopback + `security=none` 场景下无法判定公网 TLS，输出错误链接。

证据：[matrix-2026-11-08/baseline](../../tests/go-parity/evidence/matrix-2026-11-08/baseline/summary.json)、
[environment.txt](../../tests/go-parity/evidence/matrix-2026-11-08/baseline/environment.txt)。

### 2.1 A2：真实交互式 Bash 主安装 runtime 基线

> 上一轮矩阵的 Bash 侧只调用 `install_config_*`，产出的是**安装元数据**，
> 不是 Xray Runtime。A2 补齐这一层：在一次性 systemd 容器里真实执行
> `install.sh -2`（Reality）与 `install.sh -3`（none/ws、gRPC、xHTTP、
> ws+gRPC+xHTTP），由 `expect` 在出现提示后再作答（合成参数：Reality 目标
> `www.cloudflare.com`，用户/路径/端口全部接受默认或随机值），最后采集
> `/etc/idleleo/conf/xray/config.json` 并跑真实 `xray -test`。

| 真实安装 | 模式/传输 | 真实端口 | `xray -test` | 服务 | 与 Go 真实配置对比 |
|---|---|---|---|---|---|
| reality-raw | Reality raw | 443 | 0 | active | `MATCH` |
| none-ws | none ws | 容器随机 | 0 | active | `MATCH_CORE_FIELDS` |
| none-grpc | none gRPC | 容器随机 | 0 | active | `MATCH_CORE_FIELDS` |
| none-xhttp | none xHTTP | 容器随机 | 0 | active | `MATCH_CORE_FIELDS` |
| none-ws_grpc_xhttp | none ws+gRPC+xHTTP | 3 个随机端口 | 0 | active | `MATCH_CORE_FIELDS`（仅剩 Bash 空 `realitySettings`） |
| reality-ws_grpc_xhttp | Reality + ws+gRPC+xHTTP | 4 个随机端口 | 0 | active | `MATCH`（网络、监听地址、主线语义一致） |

**重跑结果（真实 runtime，6 个可捕获拓扑）**

| 状态 | 数量 | 说明 |
|---|---|---|
| `MATCH` | 2 | Reality raw 与 Reality+三入口的连接语义字段与 Go 一致 |
| `MATCH_CORE_FIELDS` | 4 | none 单/多传输的连接字段一致；差异仅为 Bash 遗留的 `realitySettings` 空块、`geodata` 顶层键、gRPC tag 大小写 |
| `GAP` | 0 | 未发现会导致连接语义不一致的字段 |
| `UNSUPPORTED` | 0 | `ws+gRPC+xHTTP` 已在 B3 中实现并参与对比 |
| `REFUSED` | 0 | 主安装流没有负例用例，不能把矩阵里的 4 个 `REFUSED` 平移到 A2 |

**与旧 54 / 32 / 8 / 4 的差异来源**

- 旧 98 项矩阵的 54 个 `MATCH` 是**安装元数据**对比，不是 Runtime 对比；
  A2 的真实 Runtime 重检**不能**把 54 直接继承为 runtime 签收。
- 真实 Runtime 只覆盖 6 个“模式 + 传输”拓扑；旧矩阵里 32 个节点 case 的
  443/8443/10086/65535 端口组合并没有逐个跑真实安装，不能声称已验证。
- 真实 Runtime 里没有 `GAP`；4 个 `MATCH_CORE_FIELDS` 都是
  非连接语义差异（Bash 模板遗留 `realitySettings`、none-ws 模板的 `geodata`、
  `VLESS-gRPC-in` 大小写），与旧矩阵的“结构不一致”不是同一口径。
- `ws+gRPC+xHTTP` 的 2 个真实拓扑原先为 `UNSUPPORTED`；B3 实现后重跑对比，
  none 多入口仅剩模板遗留键（`MATCH_CORE_FIELDS`），Reality 多入口完全一致
  （`MATCH`）。旧矩阵剩余 8 个 `GAP` 已全部关闭，复跑为
  `MATCH 54 / MATCH_CORE_FIELDS 40 / GAP 0 / REFUSED 4`。
- TLS 与 `reality-nginx` 需要真实域名/ACME 或域名证书，A2 **未捕获**，
  这两类在旧矩阵中的结果仍只是元数据级，不能升级为 runtime 证据。

**证据完整性说明**：为避开重复下载数分钟的 Xray 包，容器内预置了与 pin 一致的
Xray 26.10.31 二进制、标准 unit 与 `/var/log/xray` 目录；复跑多入口时为绕开
`raw.githubusercontent` 的临时 504，预置了仓库内 helper 脚本与
`release-managed.version`（仅跳过启动时的网络 helper 同步，安装/配置/`xray -test`
仍全部真实执行）。`install.sh` 的交互、依赖检查、模板下载、配置生成、
`xray -test`、enable/restart 均真实执行。6 个拓扑全部 `install_exit=0`、
`xray_test_exit=0`、`xray.service=active`。
采集脚本见 [a2/run_bash_real_install_container.sh](../../tests/go-parity/a2/run_bash_real_install_container.sh)、
[drive_install.exp](../../tests/go-parity/a2/drive_install.exp)、
[compare_real_runtime.py](../../tests/go-parity/a2/compare_real_runtime.py)；
证据见 [evidence/a2-2026-11-08](../../tests/go-parity/evidence/a2-2026-11-08)。

## 3. B 包：兼容差异与故障恢复修复

**代码修改（commit `f9df1ea` + `ace4a16`）**

- B4 故障恢复：`deploy.fileState` 快照新增 UID/GID、符号链接目标与缺失父目录链；
  回滚写回属主/mode/内容/符号链接，只删除安装新建的空目录；新装失败时显式
  `stop + disable`，移除 unit 后 `daemon-reload` 并校验 `is-enabled`，避免残留
  `wants/` 链接。真实 root:xray 0640 覆盖后由 `User=xray` 读取的回归见
  [run_deploy_owner_regression.sh](../../tests/go-parity/deploy/run_deploy_owner_regression.sh)。
- `RelaySpec` 新增 `ListenAddress`，显式保留 `127.0.0.1` / IPv4 / IPv6；
  默认 `0.0.0.0`，与 Bash 一致。
- 中转片段改为直连 `proxy_pass`，补齐 `proxy_timeout 720m`、
  `proxy_socket_keepalive on`。
- `xray relay --listen-address`：拒绝主机名与带方括号地址。
- `xray share --public-security` / `--user`：loopback + `none` 时拒绝猜测，
  按安装元数据显式选择公网 `tls/none/reality`，并支持按 email/UUID 选用户。
- 归档修复前后矩阵证据。

**结果**

| 状态 | 基线 | 修复后 | B3 多入口后 |
|---|---|---|---|
| `MATCH` | 2 | 54 | **54** |
| `MATCH_CORE_FIELDS` | 32 | 32 | **40** |
| `GAP` | 60 | 8 | **0** |
| `REFUSED` | 4 | 4 | 4 |

原剩余 8 个 `GAP` 全部是 `tls/none ws+grpc+xhttp` 多传输组合；B3 实现后
`expected_gap=false`，复跑全部转为 `MATCH_CORE_FIELDS`（多入口检查同时要求
三个 inbound、各传输网络与端口互异）。证据：
[after-fix/summary.json](../../tests/go-parity/evidence/matrix-2026-11-08/after-fix/summary.json)、
[b3/summary.json](../../tests/go-parity/evidence/matrix-2026-11-08/b3/summary.json)。

**故障恢复侧**：B 轮还复现并修复了 Go 管理器在 relay/share 上的两个语义缺陷
（见上），未删除任何断言；Phase 03 的故障注入随后在 C 包中真实复跑。
复检阶段又定位到 B4 的属主/符号链接/新装 enable 回滚缺口，已按“先失败测试、
再修代码”的顺序补上；新装回滚与 `root:xray 0640` 读取均真实执行通过。

**B4 跨进程崩溃恢复（本次补齐）**

- 新增持久 journal `var/lib/idleleo/deploy/journal.json` 与快照目录
  `var/lib/idleleo/deploy/snapshot/entry-N`；每次安装先 fsync journal（`PREPARED`）
  才允许改动 live 文件，成功写 `COMMITTED` 后清理。
- `Install` / `Uninstall` / `Recover` 共用 `host.AcquireUpdate(paths.LockFile())`
  排他锁；下一进程持锁后先 `recoverPendingLocked`：`PREPARED` /
  `ROLLING_BACK` / `RECOVERY_REQUIRED` 一律逆序还原快照，失败保留
  `RECOVERY_REQUIRED` 并给出显式 `idleleo xray recover` 指引。
- journal 只存相对路径，`applyRoot` 拒绝绝对路径与 `..` 越界；单测覆盖
  dead-install 回滚、坏快照保留、损坏 journal 拒绝、COMMITTED 清理、越界拒绝、
  锁冲突拒绝，以及 `Install` 自动收敛 pending journal
  [journal_test.go](../../internal/deploy/journal_test.go)。
- **真实注入证据**（`DOCKER_CRASH_INJECTION`，非生产验收）：在容器内以 250MB
  假二进制拖慢 copy，等 journal 出现后 100ms `kill -9`；进度日志记录
  `journal_state="state": "PREPARED"` 且 `partial_mutation=yes`（config 已变、
  binary/unit/meta 未变）。新容器执行 `idleleo xray recover --json` 返回
  `{"journalState":"ROLLED_BACK","action":"rolled_back","converged":true,"restoredFiles":4}`，
  四个文件 SHA 与 kill 前一致，journal 与 `.tmp` 清除；随后正常 install 成功。
  证据见 [evidence/b4-2026-11-08](../../tests/go-parity/evidence/b4-2026-11-08)，
  驱动脚本见 [run_crash_recovery_container.sh](../../tests/go-parity/deploy/run_crash_recovery_container.sh)。
- **边界**：容器返回 `exit 0`/`converged=true` 只证明恢复逻辑在一次性容器成立；
  没有真实 VPS 断电/重启证据，F01–F28 仍为 0/28，不得升格为生产签收。

**B3 `ws+gRPC+xHTTP` 多入口（本次补齐）**

- `internal/xraycfg` 接受 `--transport ws+grpc+xhttp`：单传输模式保持原样，
  多入口在 `spec.Port` 上建主 inbound，其余传输使用相邻端口（65535 附近回绕），
  每个 inbound 独立 tag/client/streamSettings，routing 的 `inboundTag` 覆盖全部入口。
- 主 inbound 规则与 Bash 一致：none/TLS 以 ws 为主、附加 grpc/xhttp 绑定
  `127.0.0.1`；Reality 以 raw 为主、附加入口沿用主监听地址（Bash
  `reality_add_more` 的 0.0.0.0 语义）。TLS 的 Nginx 片段为三个入口各生成
  一个 location/grpc_pass。
- 校验：`ws+grpc+xhttp` 的 tls/none/reality 三份生成配置均通过真实
  Xray 26.10.31 `-test`（`xray_test_exit=0`，日志见
  [b3/xray-test](../../tests/go-parity/evidence/b3-2026-11-08/xray-test)）；
  98 项矩阵复跑 `54 / 40 / 0 / 4`；A2 用真实 Bash 多入口 runtime 重新对比，
  none 多入口 `MATCH_CORE_FIELDS`、Reality 多入口 `MATCH`。
- **边界**：多入口矩阵检查在无 TLS 的模式下只验证结构与端口，不建立真实
  多入口连接；TLS/ACME 侧仍未验收。

## 4. C 包：Docker 真实服务与完整迁移

**实际命令**（干净克隆 `git clone --no-hardlinks`，避免 macOS `.git` xattr EPERM）：

```bash
IDLELEO_XRAY_BIN=/private/tmp/xray-26/xray bash tests/go-parity/phase01/run_phase01_container.sh
IDLELEO_XRAY_BIN=/private/tmp/xray-26/xray IDLELEO_GEO_CACHE=/tmp/geoip-host.dat \
  bash tests/go-parity/phase02/run_phase02_container.sh
IDLELEO_XRAY_BIN=/private/tmp/xray-26/xray bash tests/go-parity/phase03/run_phase03_container.sh
IDLELEO_XRAY_BIN=/private/tmp/xray-26/xray bash tests/go-parity/phase04/run_phase04_container.sh
```

| Phase | 真实结果 | 退出码 | 证据 |
|---|---|---|---|
| 01 CLI / 事务 / 真实 `xray -test` | **33 / 35** | 1（预期红） | [phase01.log](../../tests/go-parity/evidence/c-2026-11-08/phase01.log) |
| 02 安装 / 卸载 / GeoData / 配置矩阵 | **36 / 36** | 0 | [phase02.log](../../tests/go-parity/evidence/c-2026-11-08/phase02.log) |
| 03 Bridge 迁移 E2E | **219 / 219** | 0 | [phase03.log](../../tests/go-parity/evidence/c-2026-11-08/phase03.log) |
| 04 升级 / 服务 / Rill / Stats | **42 / 42** | 0 | [phase04.log](../../tests/go-parity/evidence/c-2026-11-08/phase04.log) |

合计 **330 / 332**。

**Phase 01 两项红色的机制（保留失败，不篡改 pin）**

- `C12.1`：`install.sh` 与已发布 pin `0fa7052e` 字节不一致；
- `C12.2`：产品代码 diff 非空（`install.sh` +26/−1）。

原因：`2d44d98`（logrotate `ReadWritePaths` 修复）在 v3.3.6 发布**之后**修改了
`install.sh`。本轮约束是不改 pin，因此这两项必须红；发版并推进 pin 后自然转绿。
同时修复了 Phase 01 证据夹具缺陷（多行 `git diff` 撑裂 TSV，commit `dac717a`），
失败内容与判定完整保留。

**Bridge 状态机真实证据**

| 阶段 | 实测 |
|---|---|
| Audit | reality/tls/relay/xtls/rill 五类真实审计；xtls 判 `legacy-xtls-removed` + `blocked` |
| Prepare | journal `PREPARED`；运行配置/入口/cron 逐字节不变；未确认自定义片段 exit 6 |
| Validate | 真实 `xray -test` + `nginx -t`；注入漂移 exit 6 |
| Activate | 提交 journal、安装并 enable schedule units、保留 Bash 恢复入口、真实 restart/reload |
| Recover | 三个故障时点均 exit 0，journal → `ROLLED_BACK`，配置逐字节还原 |

故障注入（真实执行）：重复 prepare exit 3；缺 recovery 入口 activate 拒绝；
validate 后漂移 exit 6；Rill 观测漂移 exit 6；世界可读私钥阻止 reload；
XTLS ONLY 只识别 + 阻断，零落盘。

## 5. D 包：Go 原生 TCP 与辅助脚本审计

### 5.1 TCP 原生化

实现：`internal/tcpcfg` + `idleleo tcp status|plan|apply|rollback`。

- 只管理 `/etc/sysctl.d/90-idleleo-tcp.conf`，profile 仅 `bbr-fq`；
- journal `/var/lib/idleleo/tcp/state.json`，先行 pending，再原子写文件、逐 key 写
  `/proc/sys`，回读校验后 committed；
- 锁 `/run/lock/idleleo-tcp.lock`，与配置更新锁分离；
- 漂移、符号链接、无项目标记文件、pending journal 一律拒绝；
- 回退只撤销 journal 记录的 key，恢复旧文件字节/mode/uid/gid。

**测试**

- `go test ./internal/tcpcfg`：**20 / 20 PASS**（`GO_EXECUTED`）；
- `tests/go-parity/tcp/run_tcp_container.sh`：**30 / 30 PASS**（`DOCKER_MOCK_APPLY`），
  apply/rollback 重定向到一次性 sandbox，**未写 Docker VM 内核**；前后对比真实
  `/proc/sys` 值证明未被改动。

集成中发现并修复两个真实缺陷：

1. `sysctl.d` 目录被当作文件走写路径，status/apply 报 `target is not a regular file`；
2. `WriteSysctl` 未截断，sandbox 回读出现 `fq\n_codel`。

证据：[tcp-2026-11-08](../../tests/go-parity/evidence/tcp-2026-11-08)、
[TCP_NATIVE_DESIGN_AND_QA.md](TCP_NATIVE_DESIGN_AND_QA.md)。

### 5.2 辅助脚本审计

14 个 `scripts/*.sh` + `install.sh` 的 TCP 入口完成迁移判定，结论是**本轮不强行迁移**
涉及 ACME、防火墙、权限/epoch、混合升级器与 Rill 安装卸载的脚本；只把已有 Go 原语
标为已迁移/部分迁移。详见 [SCRIPT_NATIVE_MIGRATION_MATRIX.md](SCRIPT_NATIVE_MIGRATION_MATRIX.md)
与 [DECISIONS.md](DECISIONS.md) D-009。

## 6. F01–F28 功能覆盖结果

> 标签定义见 [FUNCTION_PARITY.md](FUNCTION_PARITY.md)。`部分实现` 一律为容器级子集，
> **不等于** Bash 行为等价，也**不是**真实 VPS 验证。

| ID | 功能 | Go 状态 | 最高证据等级 | 关键限制 |
|---|---|---|---|---|
| F01 | Reality（普通 / +Nginx） | 部分实现 | `DOCKER_SERVICE_VERIFIED` | `reality-nginx` 只生成配置 + `-test`，未装 Nginx |
| F02 | TLS ws/gRPC/xHTTP/组合 | 部分实现 | `DOCKER_SERVICE_VERIFIED` | 组合传输已实现并通过 `xray -test`；TLS 多入口需真实域名/证书 |
| F03 | none ws ONLY | 部分实现 | `DOCKER_SERVICE_VERIFIED` | 保留显式非回环确认，实测 exit 2 零落盘 |
| F04 | Reality 主备负载均衡 | 未实现 | — | 无双节点验收 |
| F05 | relay 独立中转 | 部分实现 | `DOCKER_SERVICE_VERIFIED` | 不能创建 Xray/UUID/证书 |
| F06 | 用户增删 / UUIDv5 | 部分实现 | `DOCKER_SERVICE_VERIFIED` | UUID 为随机 v4，未实现 v5 |
| F07 | shortId / spiderX / 用户映射 | 部分实现 | `DOCKER_SERVICE_VERIFIED` | 完整用户映射未实现 |
| F08 | 端口 / target / serverNames / SNI Guard | 部分实现 | `DOCKER_SERVICE_VERIFIED` | SNI Guard 未实现 |
| F09 | `--add-upstream` | 未实现 | — | — |
| F10 | `--tls` 版本变更 | 未实现 | — | Bash 侧为 `sed -i` 后重启 |
| F11 | 服务状态 / 启停 / 日志 | 部分实现 | `DOCKER_SERVICE_VERIFIED` | 仅限项目自有 unit |
| F12 | 证书状态 / 签发 / 续期 / 清理 | 未实现（有到期监控） | `DOCKER_SERVICE_VERIFIED` | 无公网 ACME；只做外部续约契约 |
| F13 | `--update` / `--xray-update` / `--nginx-update` | 未实现 | — | 需哈希/降级/失败注入 |
| F14 | `--auto-update` / cron | 部分实现 | `DOCKER_SERVICE_VERIFIED` | Go 通道只升级自身；Xray/Nginx 执行器仍 Bash |
| F15 | Stats / `--json` / watch / reset | 部分实现 | `DOCKER_SERVICE_VERIFIED` | watch/reset 未实现 |
| F16 | GeoData 热更新 / 旧布局 | 部分实现 | `DOCKER_SERVICE_VERIFIED` | 旧布局迁移未实现 |
| F17 | IPv4/IPv6 / DNS / 防火墙 | 未实现 | — | iptables 直写未纳入统一事务 |
| F18 | 分享链接 / 二维码 / Clash | 部分实现 | `DOCKER_SERVICE_VERIFIED` | 二维码未实现；xHTTP 明确告警 |
| F19 | 备份 / 恢复 / 重配置保留 | 部分实现 | `DOCKER_MIGRATION_VERIFIED` | backup/restore CLI 未实现 |
| F20 | Fail2ban | 未实现 | — | 已批准差异：不得删 `jail.d/*.local` |
| F21 | 流量阻断 / 自定义路由 | 未实现 | — | 规则生成后必须 `xray -test` |
| F22 | Rill 观察 / 诊断 / 授权 / 卸载 | 部分实现 | `DOCKER_SERVICE_VERIFIED` | 卸载仍走 Bash |
| F23 | 六语言 | 部分实现 | `DOCKER_SERVICE_VERIFIED` | zh/en 完整，fr/fa/ru/ko 回退英文 |
| F24 | Docker 交付 | 未实现 | — | 不能假设宿主 systemd DBus |
| F25 | TCP 优化 / 测速 | 部分实现 | `GO_EXECUTED` + `DOCKER_MOCK_APPLY` | 仅 `bbr-fq`；不测速、不执行 `tcp.sh` |
| F26 | XTLS ONLY 旧模式 | 部分实现 | `DOCKER_MIGRATION_VERIFIED` | 只读识别 + 阻断，按设计不迁移 |
| F27 | backup/restore/purge/service-* | 部分实现 | `DOCKER_SERVICE_VERIFIED` | backup/restore/purge CLI 未实现 |
| F28 | 运行态与分享信息展示 | 部分实现 | `DOCKER_SERVICE_VERIFIED` | 未与 Bash 逐字段差分 |

**统计**：部分实现 19 项，未实现 9 项（含 F12 的到期监控分支），
已验证/正式签收 **0 项**。

## 7. 关键测试记录

| 命令 | 结果 | 证据等级 |
|---|---|---|
| `go test ./internal/tcpcfg` | 20 / 20 PASS | `GO_EXECUTED` |
| `bash tests/go-parity/tcp/run_tcp_container.sh` | 30 / 30 PASS | `DOCKER_MOCK_APPLY` |
| Phase 01 容器复跑 | 33 / 35，exit 1（C12.1/C12.2 预期红） | `DOCKER_SERVICE_VERIFIED` |
| Phase 02 容器复跑 | 36 / 36，exit 0 | `DOCKER_SERVICE_VERIFIED` |
| Phase 03 容器复跑 | 219 / 219，exit 0 | `DOCKER_MIGRATION_VERIFIED` |
| Phase 04 容器复跑 | 42 / 42，exit 0 | `DOCKER_SERVICE_VERIFIED` |
| 98 项 Bash/Go 矩阵（B3 多入口后） | MATCH 54 / CORE 40 / GAP 0 / REFUSED 4 | `BASH_EXECUTED` + `GO_EXECUTED` |
| A2 真实安装 6 拓扑（§2.1） | 2 MATCH / 4 CORE / 0 GAP / 0 UNSUPPORTED | `BASH_EXECUTED` |
| B3 多入口 `xray -test`（tls/none/reality） | 3 / 3 exit 0（真实 Xray 26.10.31） | `GO_EXECUTED` |
| B4 真实 SIGKILL 注入（journal 出现后 kill -9） | journal `PREPARED` → 新进程 `ROLLED_BACK`，4 文件 SHA 还原 | `DOCKER_CRASH_INJECTION` |
| B4 单测（含 `Install` 自动收敛 pending journal） | 8 / 8 PASS | `GO_EXECUTED` |
| `gofmt` / `go vet` / `go test` / `go test -race` / `bash -n` | 全部通过（gofmt 无输出） | `GO_EXECUTED` |

## 8. 各阶段提交

| Commit | 内容 |
|---|---|
| `dd97eb1` | A 基线证据 + logrotate 对 Phase 01 C12 的影响说明 |
| `f9df1ea` | B：中转监听地址语义对齐、公网 TLS 分享链接修复、矩阵证据归档 |
| `dac717a` | C：Phase 01 多行 diff 夹具修复（不改变判定） |
| `5cf34d7` | D：`internal/tcpcfg` + `idleleo tcp` CLI + 20 项单测 |
| `7f82d35` | D：TCP 容器 30 项场景与证据 |
| `ace4a16` | 复检修复：B4 回滚恢复 UID/GID/符号链接/父目录，并撤销新装 enable 链接 |
| （本复检报告提交） | docs：合规复检附录、矩阵 provenance 修正、D1 上游审计与门禁证据 |
| `a53dfee` | A2：真实交互式 Bash 主安装 6 拓扑 runtime 基线与重跑统计 |
| （本次 B4 提交） | B4：持久 deploy journal + 排他锁 + `idleleo xray recover` + 真实 SIGKILL 注入证据 |
| （本次 B3 提交） | B3：`ws+gRPC+xHTTP` 多入口生成、Nginx 多 location、矩阵与真实 Xray 校验 |

既有关联提交：`2d44d98`（logrotate drop-in 修复）、`e859724`（install.sh 对齐
v3.3.6 基线）。

## 9. 遗留问题与阻塞

**P0（生产接管前必须解决）**

1. **A2 真实 Bash 主安装已执行，但覆盖不完整**：6 个拓扑在一次性 systemd
   容器内真实跑完 `install.sh -2/-3` 并采集 Runtime（§2.1），
   `xray -test=0`、服务 active。TLS 与 `reality-nginx` 因需要真实域名/ACME
   未捕获；旧 54 个元数据 `MATCH` 不能升级为 Runtime 签收。
2. Xray/Nginx 自动升级执行器仍在 Bash；Go 无降级/失败注入验证。
3. 真实 ACME 签发/续期未验收；F12 只提供外部续约契约。
4. 无任何 `REAL_VPS_VERIFIED` 证据，正式签收 0/28。

> B3 多入口与 B4 跨进程恢复已补齐，并从 P0 的“实现缺口”中移出；但 B3 只做了
> 配置结构 + `xray -test`（未建立多入口真实连接），B4 只是
> `DOCKER_CRASH_INJECTION`（未做真实断电/重启），因此都不构成生产签收。

**P1**

5. **A1 覆盖缺口**：98 case 不含节点级 IPv4/IPv6 绑定、hostname 校验、
   1/4/20 用户与主备负载均衡。这些不能由 Phase 02/03 的局部用例替代。
6. **C4 故障点未全覆盖**：缺 invalid candidate/recovery 二进制、reload 失败、
   cron 修改冲突、写盘失败后的独立注入；其余 disk-full、kill 点、drift、
   corrupt journal、`--yes` 不自动迁移已真实执行。
7. `backup/restore/purge` CLI、Fail2ban、流量阻断、SNI Guard、二维码、watch/reset
   未实现。
8. Phase 01 C12.1/C12.2 会持续红，直到下次发版并推进 pin；不得为此改 pin 或改断言。
9. TCP 未做性能/吞吐验收；未扫描 `/run/sysctl.d`、`/usr/lib/sysctl.d` 的冲突。

**P2**

10. F01–F28 矩阵的 Go 状态仍使用中文标签，仅靠
    [FUNCTION_PARITY.md](FUNCTION_PARITY.md) 的映射表换算到提示词标签；未物理重写列。
11. fr/fa/ru/ko 文案回退英文，未与 Bash 逐条差分。
12. Docker 交付路径未实现（F24）。

## 10. 最终结论

- **流程完成，不等于技术验收通过**：A/B/C/D 四包均完成“复现 → 修复 → 实跑 →
  自审 → 提交”，真实测试记录与失败证据完整保留；但 §9 的 P0 硬缺口仍在，
  相对提示词包约 **82%**（附录 A）。
- **Go 可接管**配置生成（含多入口）、迁移状态机、服务/GeoData/Stats/timer 原语、
  跨进程安装恢复与 TCP 安全子集；**不可宣称**全量生产接管或真实 VPS 签收。
- 下一步建议顺序：A1 覆盖缺口 → 升级执行器 → ACME → P1 功能项；A2、B3、B4
  已在本轮补齐。在此之前保持 Bash 为生产入口。

## 附录 A：提示词包逐条合规复检（2026-11-08）

> 判定口径：**PASS** = 有可核对产物且满足要求；**部分满足** = 做了但覆盖/口径不完整；
> **FAIL** = 要求未完成或证据不成立。共 38 项：PASS 25、部分满足 12、FAIL 1；
> 加权完成度（PASS=1，部分=0.5）≈ **82%**（A2、B3、B4 补齐后）。
> 流程/交付接近 100%；正式签收仍为 0/28（仅真实 VPS 证据才能改口径）。

| # | 检查项（提示词出处） | 判定 | 证据 / 说明 |
|---|---|---|---|
| 1 | 0.1 记录源 SHA、基于最新 `develop/go-native` 建独立分支、不动 main/Release | PASS | `git branch --show-current`=`audit/bash-go-native-parity`；基线 `dd97eb1`；本分支无 main 提交、无 tag/Release |
| 2 | 0.2 先读源码与 `docs/go`，不沿用旧报告结论 | PASS | 复检重新核对 `install.sh` 行号、`internal/deploy`、`internal/legacybridge`、`tests/fixtures/legacy`；B4 与 tcp.sh 均为重新发现 |
| 3 | 0.3 ZIP 外置、编译当前 `cmd/idleleo`、用仓库 `install.sh` | PASS | 矩阵 `go_sha` 由当前 checkout 构建；`environment.txt` 记录 `install.sh` SHA |
| 4 | 0.4 A→D 连续执行，每包先复现再修、独立 commit | PASS | `f9df1ea`、`ace4a16`、`5cf34d7`、`7f82d35`、`8b88b7a`；B4 先加失败测试 |
| 5 | 0.5 破坏性操作仅在可销毁容器，不碰宿主/VPS | PASS | Phase 01–04 均 `--network=none` 或无宿主关键目录绑定；`--privileged` 仅 systemd 探针；TCP sandbox |
| 6 | 0.6 新测试初始失败、不删断言/不改测试状态、测失败路径 | PASS | `git diff develop/go-native..HEAD -- '*_test.go'`：新增 741 行、删除 1 行（仅函数签名替换）；330/332 与 C12 两项红保留 |
| 7 | 0.7 证据等级标注、不把容器写成签收 | PASS | 报告 §1 定义等级；F01–F28 正式签收 **0/28**；无“真实 VPS 已验证”表述 |
| 8 | 0.8 不引入大型框架，复用事务/锁/恢复日志 | PASS | 仅新增 `internal/tcpcfg` 与 deploy 修复；TCP 复用 journal/lock 模式 |
| 9 | A1 执行 ZIP 夹具并记录 commit/dirty/Go/Docker/镜像/夹具 SHA | PASS | [baseline/environment.txt](../../tests/go-parity/evidence/matrix-2026-11-08/baseline/environment.txt)：`dd97eb1`、dirty=0、arm64、digest；报告补 Go/Xray/Nginx/SHA |
| 10 | A1 必需覆盖：IPv4/IPv6、hostname、1/4/20 用户、主备负载均衡 | FAIL | 98 case 无节点级 IPv4/IPv6、hostname、20 用户、balance；仅 relay 覆盖 IPv6/域名后端 |
| 11 | A1 分契约比较、敏感字段保护 | PASS | 矩阵按 metadata/runtime/share 分契约；证据只存哈希与字段，不含私钥 |
| 12 | A2 真实 Bash 主安装生成 Runtime（非静态 JSON） | PASS | `a53dfee`：一次性 systemd 容器内 `install.sh -2/-3` 真实交互安装，采集 `/etc/idleleo/conf/xray/config.json`；6 拓扑 `install_exit=0`、`xray_test_exit=0`、服务 active（§2.1） |
| 13 | A2 模式/传输/角色/网络/用户/自定义组合覆盖 | 部分满足 | 已覆盖 none-ws/grpc/xhttp/三合一、reality-raw/reality-三合一；TLS、reality-nginx 与多用户/自定义 serverNames 未捕获 |
| 14 | A3 Bash→Go 真实 CLI 双向 | 部分满足 | Phase 03 跑 audit/prepare/validate/activate/recover、用户/分享操作；未覆盖全部模式 |
| 15 | A3 Go→运行时真实 `xray -test` 与客户端流量 | 部分满足 | F01 Reality 客户端隧道、F05 relay 真实转发；TLS/多传输无真实客户端 |
| 16 | A3 异常输入全覆盖（UUID/SNI/IPv6/路径遍历/重复/0-20 用户/损坏 JSON/磁盘满等） | 部分满足 | 矩阵 4 个 REFUSED；Phase 03 覆盖 drift/disk-full/corrupt journal/世界可读私钥；其余未逐项 |
| 17 | A3 case ID 对应 F01–F28 的永久夹具 | 部分满足 | 矩阵 case 可执行，但未逐 case 标注 F 编号 |
| 18 | B1 relay 监听地址/片段语义/负例/真实流量 | 部分满足 | `ListenAddress`、`proxy_timeout`、IPv6/域名/端口边界已测；`proxy_connect_timeout`、DNS 更新未单独验证 |
| 19 | B2 分享链接结构化/真实客户端/Clash 降级 | 部分满足 | share 字段断言与 `--user/--public-security` 已修；真实客户端未覆盖 TLS/多传输 |
| 20 | B3 多传输 `ws+gRPC+xHTTP` 多入口 | PASS | 3 个 inbound（Reality 4 个）、多 location、routing 全覆盖；矩阵 8 个 GAP 关闭，真实 `xray -test` 3/3；未做多入口真实连接 |
| 21 | B3 多用户按 inbound+UUID/email 选择、1/4/20 用户 | 部分满足 | `--user` 已支持；Phase 03 覆盖 4 用户，20 用户未测 |
| 22 | B4 文件快照含 UID/GID/mode/exists/symlink/父目录 | PASS | `ace4a16`：`captureFile`/`restore` 全部实现；单测覆盖属主、链接、父目录 |
| 23 | B4 新装失败撤销 unit/enable/daemon 状态 | PASS | `rollbackInstall` stop+disable+daemon-reload；`TestFreshInstallRollbackRemovesNewFiles` |
| 24 | B4 SIGKILL/容器重启的持久检测与回滚 | PASS | 持久 journal + `host.AcquireUpdate` 锁 + `idleleo xray recover`；真实注入 `kill -9` 后新进程 `ROLLED_BACK`、4 文件 SHA 还原（`DOCKER_CRASH_INJECTION`，非生产签收） |
| 25 | B4 Bridge 入口/cron/证书/Rill/幂等回归 | PASS | Phase 03 219 项含入口漂移、cron 保留、私钥权限、Rill 交接、重复 prepare |
| 26 | C1 复用 Phase 脚本、C12 两项红保留、pin 不改 | PASS | `33/35` exit 1；[DOCKER_MIGRATION_ACCEPTANCE.md](DOCKER_MIGRATION_ACCEPTANCE.md) §2.1 明写 FAIL，不软化 |
| 27 | C2 真实拓扑/客户端流量/内部 CA | 部分满足 | F01/F05 有真实客户端与流量；Bridge 迁移后未对每种模式补真实客户端 |
| 28 | C3 迁移前后 SHA/指纹/UID/GID/mode/服务/cron/Rill/路由/链接 | PASS | Phase 03 逐字节与状态断言 219 项 |
| 29 | C4 故障点：磁盘满/非法二进制/入口漂移/kill/第三方/cron 冲突/reload 失败/写盘失败/重复 | 部分满足 | disk-full、三个 kill 点、drift、corrupt journal、缺 recovery、`--yes` 均有；非法二进制/reload 失败/cron 冲突/写盘失败缺独立注入 |
| 30 | C5 F01–F28 使用提示词标签 | 部分满足 | 已加 [FUNCTION_PARITY.md](FUNCTION_PARITY.md) 映射表；原表仍用中文标签 |
| 31 | C6 架构/Xray ELF SHA/privileged 范围/不写 VM 内核 | 部分满足 | Phase 02 日志记录 Xray arm64 SHA；Nginx digest 未汇总；privileged 仅 systemd |
| 32 | D1 审计 `bbr_boost_sh` 与下载 `tcp.sh` 实际行为 | PASS | [SCRIPT_NATIVE_MIGRATION_MATRIX.md](SCRIPT_NATIVE_MIGRATION_MATRIX.md) §1.1 + [tcp-upstream-2026-11-08.txt](../../tests/go-parity/evidence/tcp-upstream-2026-11-08.txt)；固定版本逐行等价 **BLOCKED** |
| 33 | D2 TCP status/plan/apply/rollback 安全实现 | PASS | 20 项单测覆盖部分失败/回滚失败/漂移/只读/符号链接/pending；30 项沙箱断言；不重放 `sysctl --system` |
| 34 | D3 辅助脚本迁移矩阵与后续顺序 | PASS | 14 个脚本 + install.sh TCP/端口/证书/防火墙入口；目标/契约/优先级齐全 |
| 35 | 回归门禁 gofmt/vet/test/race/bash -n | PASS | [gates-2026-11-08.log](../../tests/go-parity/evidence/gates-2026-11-08.log)：`GATES_OK` |
| 36 | 98 矩阵 + Phase 01–04 日志/退出码/镜像 digest | PASS | 矩阵在 `ace4a16` 与 B3 后各重跑一次；Phase 日志与 exit code 齐全 |
| 37 | 脱敏、无真实私钥、资产固定版本与哈希 | PASS | 证据中无 `PRIVATE KEY`；A2 生成 UUID/公钥/shortId/主机 IP/分享链接已二次脱敏；Xray SHA 与夹具/镜像 digest 记录 |
| 38 | 交付物 5 项、F01–F28、commit SHA | PASS | 报告、DOCKER_MIGRATION_ACCEPTANCE、TCP_NATIVE_DESIGN_AND_QA、SCRIPT_NATIVE_MIGRATION_MATRIX、FUNCTION_PARITY 均在仓库 |

## 附录 B：本轮复检直接修复的不实口径与缺陷

| 问题 | 性质 | 处理 |
|---|---|---|
| `REFUSED 4` 未定义，读者可能误读为失败 | 口径 | 报告 §2 明确定义为 4 个非法输入被正确拒绝 |
| after-fix 证据引用不存在的 commit `7b15c83` | 证据 provenance | 在 `ace4a16` 上用修正版 runner 重跑，替换 summary/environment |
| 直接运行缓存镜像得到 `13/32/44/5/4` | 复现陷阱 | 记录为“镜像内旧脚本”，明确不得作证据 |
| B4 回滚丢 UID/GID/符号链接/父目录、新装未 disable | 真缺陷 | commit `ace4a16`；新增 root:xray 0640 与 symlink/父目录回归 |
| B4 “回滚完整”措辞过强 | 不实口径 | 先用“内存快照可回滚，跨进程未实现”限定；后续补齐后改为“容器内 SIGKILL 可收敛，仍非生产签收” |
| D1 只写“审计 scripts/tcp.sh”但无实际行为 | 反向缺口 | 抓取上游快照 SHA-256 并逐类列行为，固定版本判定 BLOCKED |
| C5 标签与提示词不一致 | 口径 | FUNCTION_PARITY 增加逐项映射表 |
| A1 覆盖被暗示为全量 | 不实口径 | 报告明列未覆盖的 IPv4/IPv6/hostname/20 用户/负载均衡 |
| B3 多入口长期挂账为 `expected_gap` | 反向缺口 | 实现 3/4 inbound 生成，矩阵 8 项 GAP 关闭，A2 真实 runtime 重新对比 |

**复检结论**：这一轮相对提示词包约 **82%** 完成（A2/B3/B4 补齐后）。
- **硬缺口（仍未做）**：A1 必需覆盖矩阵。
- **已补齐但非生产签收**：A2 真实 Bash 安装 runtime（6 拓扑，TLS/ACME 与
  reality-nginx 未捕获）；B3 多入口（结构 + `xray -test`，未建立真实多连接）；
  B4 跨进程 journal/lock + 真实 SIGKILL 注入（`DOCKER_CRASH_INJECTION`，
  无真实断电/重启）。
- **措辞/证据口径问题（已修）**：REFUSED 定义、矩阵 provenance、B4 过度表述、
  D1 审计缺实际行为、C5 标签映射、A1 覆盖边界。
- **不算缺口但需保留**：330/332 中的 C12.1/C12.2 红（pin 与 logrotate 修复差异）、
  真实 ACME/REAL_VPS 签收 0/28（本轮明确不纳入）。
