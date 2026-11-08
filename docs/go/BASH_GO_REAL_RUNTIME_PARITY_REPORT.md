# Bash → Go 原生运行时对照与验收报告（2026-11-08）

> 本报告汇总 A/B/C/D 四个工作包的真实执行结果。**证据等级严格分级**，
> Docker 容器级结果不等于生产签收；F01–F28 的正式签收计数仍为 **0 / 28**。

## 0. 结论摘要

**Go 能否正式接管 Bash？**

- **可以接管**：配置生成、安装元数据读取、迁移状态机（Audit→Prepare→Validate→
  Activate→Recover/Rollback）、服务原语、GeoData 刷新、Stats 读取、systemd timer、
  以及本轮新增的 TCP 安全子集。
- **尚不能全量接管**：`ws+gRPC+xHTTP` 多传输组合、真实 ACME 签发/续期、
  Xray/Nginx 自动升级执行器、Fail2ban、流量阻断、备份/恢复 CLI、Docker 交付路径
  仍缺实现或真实验证。
- **正式接管门槛未达**：没有任何一项达到 `REAL_VPS_VERIFIED`；
  F01–F28 正式签收 **0/28**。生产替换前必须先补齐第 9 节的阻塞项。

| 工作包 | 结论 | 最高证据等级 |
|---|---|---|
| A：真实 Bash 配置 vs Go 管理器 | 基线 98 项：`MATCH 2 / MATCH_CORE_FIELDS 32 / GAP 60 / REFUSED 4` | `BASH_EXECUTED` + `GO_EXECUTED` |
| B：兼容差异与故障恢复 | 修复后 `MATCH 54 / MATCH_CORE_FIELDS 32 / GAP 8 / REFUSED 4`；剩余 8 项均为已登记的预期缺口 | `GO_EXECUTED` |
| C：Docker 真实服务与完整迁移 | Phase 01–04 合计 **330 / 332**，Bridge 状态机与故障注入全部真实执行 | `DOCKER_SERVICE_VERIFIED` / `DOCKER_MIGRATION_VERIFIED` |
| D：TCP 原生 + 辅助脚本审计 | 20 项单测 + 30 项容器断言全绿；14 个脚本迁移判定表完成 | `GO_EXECUTED` + `DOCKER_MOCK_APPLY` |

## 1. 范围、基线与环境

- 基线：`develop/go-native`，本轮从 `dd97eb1` 拉出 `audit/bash-go-native-parity`。
- Bash 行为基线：`install.sh` v3.3.6 pin `0fa7052e`。
- 宿主：macOS arm64，Docker 29.8.2（OrbStack，容器内核 7.2.12）。
- 真实组件：Xray 26.10.31（linux/arm64）、Nginx 1.24.0（Ubuntu 24.04.5 LTS）。
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

基线暴露出三类真实差异：

- relay 监听地址语义不一致（Go 未保留 `127.0.0.1` / IPv6 绑定）；
- relay 片段结构与 Bash 不同（缺少 `proxy_timeout 720m`、
  `proxy_socket_keepalive on`，上游写法不同）；
- `share` 在 loopback + `security=none` 场景下无法判定公网 TLS，输出错误链接。

证据：[matrix-2026-11-08/baseline](../../tests/go-parity/evidence/matrix-2026-11-08/baseline/summary.json)、
[environment.txt](../../tests/go-parity/evidence/matrix-2026-11-08/baseline/environment.txt)。

## 3. B 包：兼容差异与故障恢复修复

**代码修改（commit `f9df1ea`）**

- `RelaySpec` 新增 `ListenAddress`，显式保留 `127.0.0.1` / IPv4 / IPv6；
  默认 `0.0.0.0`，与 Bash 一致。
- 中转片段改为直连 `proxy_pass`，补齐 `proxy_timeout 720m`、
  `proxy_socket_keepalive on`。
- `xray relay --listen-address`：拒绝主机名与带方括号地址。
- `xray share --public-security` / `--user`：loopback + `none` 时拒绝猜测，
  按安装元数据显式选择公网 `tls/none/reality`，并支持按 email/UUID 选用户。
- 归档修复前后矩阵证据。

**结果**

| 状态 | 基线 | 修复后 |
|---|---|---|
| `MATCH` | 2 | **54** |
| `MATCH_CORE_FIELDS` | 32 | 32 |
| `GAP` | 60 | **8** |
| `REFUSED` | 4 | 4 |

剩余 8 个 `GAP` 全部是 `tls/none ws+grpc+xhttp` 多传输组合，
且 `expected_gap=true`：Go 当前只支持单传输，P1 未实现，属于**已登记缺口**，
不是本轮回归。证据：
[after-fix/summary.json](../../tests/go-parity/evidence/matrix-2026-11-08/after-fix/summary.json)。

**故障恢复侧**：B 轮还复现并修复了 Go 管理器在 relay/share 上的两个语义缺陷
（见上），未删除任何断言；Phase 03 的故障注入随后在 C 包中真实复跑。

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
| F02 | TLS ws/gRPC/xHTTP/组合 | 部分实现 | `DOCKER_SERVICE_VERIFIED` | 组合传输未实现；TLS 需真实域名/证书 |
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
| 98 项 Bash/Go 矩阵（修复后） | MATCH 54 / CORE 32 / GAP 8 / REFUSED 4 | `BASH_EXECUTED` + `GO_EXECUTED` |

## 8. 各阶段提交

| Commit | 内容 |
|---|---|
| `dd97eb1` | A 基线证据 + logrotate 对 Phase 01 C12 的影响说明 |
| `f9df1ea` | B：中转监听地址语义对齐、公网 TLS 分享链接修复、矩阵证据归档 |
| `dac717a` | C：Phase 01 多行 diff 夹具修复（不改变判定） |
| `5cf34d7` | D：`internal/tcpcfg` + `idleleo tcp` CLI + 20 项单测 |
| `7f82d35` | D：TCP 容器 30 项场景与证据 |
| （本报告） | docs：A–D 汇总报告与三份专项文档 |

既有关联提交：`2d44d98`（logrotate drop-in 修复）、`e859724`（install.sh 对齐
v3.3.6 基线）。

## 9. 遗留问题与阻塞

**P0（生产接管前必须解决）**

1. `ws+gRPC+xHTTP` 多传输组合未实现（剩余 8 个 GAP 的唯一来源）。
2. Xray/Nginx 自动升级执行器仍在 Bash；Go 无降级/失败注入验证。
3. 真实 ACME 签发/续期未验收；F12 只提供外部续约契约。
4. 无任何 `REAL_VPS_VERIFIED` 证据，正式签收 0/28。

**P1**

5. `backup/restore/purge` CLI、Fail2ban、流量阻断、SNI Guard、二维码、watch/reset
   未实现。
6. Phase 01 C12.1/C12.2 会持续红，直到下次发版并推进 pin；不得为此改 pin 或改断言。
7. TCP 未做性能/吞吐验收；未扫描 `/run/sysctl.d`、`/usr/lib/sysctl.d` 的冲突。

**P2**

8. fr/fa/ru/ko 文案回退英文，未与 Bash 逐条差分。
9. Docker 交付路径未实现（F24）。

## 10. 最终结论

- **本轮目标达成**：A/B/C/D 四包均完成“复现 → 修复 → 实跑 → 自审 → 提交”，
  真实测试记录与失败证据完整保留。
- **Go 可接管**配置生成、迁移状态机、服务/GeoData/Stats/timer 原语与 TCP 安全子集；
  **不可宣称**全量生产接管或真实 VPS 签收。
- 下一步建议顺序：多传输组合 → 升级执行器 → ACME → P1 功能项；
  在此之前保持 Bash 为生产入口，Go 为可审计的并行管理器。
