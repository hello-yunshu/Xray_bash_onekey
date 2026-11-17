# Go 原生 TCP 配置：设计、边界与验收

> 证据等级：单元测试 `GO_EXECUTED`；容器集成 `DOCKER_MOCK_APPLY`。
> 容器内 apply/rollback 被重定向到一次性 sandbox，**没有写 Docker VM 内核**，
> 因此这不是宿主内核验收，也不是 TCP 性能验收。

## 1. 目标与非目标

**目标**

- 只管理一个项目自有文件 `/etc/sysctl.d/90-idleleo-tcp.conf`，提供
  `status / plan / apply / rollback`。
- 只切换运行中内核已暴露的能力：`bbr` 拥塞控制 + `fq` qdisc（profile `bbr-fq`）。
- 写前快照、只写指定 key、幂等、可回退、第三方漂移拒绝。
- 不下载第三方脚本、不替换内核、不改 `/etc/sysctl.conf`、不重放 `sysctl --system`。

**非目标（本轮明确不做）**

- 不实现 BBRPlus/SharpSpeed/魔改内核，不做测速，不执行 `tcp.sh` 或任何远程脚本。
- 不自动调优 `net.ipv4.tcp_fastopen`、`rmem/wmem` 等大范围参数（扩大变更面）。
- 不在容器内写真实内核；Docker 只验证 CLI/事务/回退逻辑。

## 2. 设计

### 2.1 文件与状态

| 路径 | 作用 |
|---|---|
| `/etc/sysctl.d/90-idleleo-tcp.conf` | 唯一持久化配置；首行含 `Managed by Xray_bash_onekey` 标记；前缀 90 确保发行版默认值优先被覆盖，但 99-* 与 `/etc/sysctl.conf` 仍可覆盖 |
| `/var/lib/idleleo/tcp/state.json` | 单事务回退日志：旧文件字节/属主/mode、旧运行值、目标值、目标哈希、实际哈希、pending 标记 |
| `/run/lock/idleleo-tcp.lock` | TCP 专用 flock；与配置更新锁分离，互不阻塞 |

配置内容示例：

```text
# Managed by Xray_bash_onekey (Go): idleleo tcp
# Profile: bbr-fq
# Rollback: idleleo tcp rollback
# Do not edit; use the idleleo CLI so rollback stays accurate.
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
```

### 2.2 事务顺序

1. 读运行值、扫描 `/etc/sysctl.conf` + `/etc/sysctl.d/*.conf`，按 procps
   `sysctl --system` 的优先级计算“持久化有效值”和冲突。
2. 拒绝：非 Linux、非 root（sandbox 除外）、内核未列出 `bbr`、目标文件无项目标记、
   更高优先级文件设置了不同值、上次事务 `pending`、文件哈希与日志不符（第三方漂移）。
3. **先写 journal**（pending），再原子写配置文件，再逐 key 写 `/proc/sys`。
4. 每写一个 key 即记录；失败时逆序恢复已写 key + 恢复/删除文件；恢复也失败则保留
   pending journal 并提示人工 `rollback`。
5. 全部回读校验一致后，journal 标记 committed（写入实际哈希）。
6. 幂等：文件哈希与运行值都等于目标时直接返回 `noop`，不写文件、不写内核。

### 2.3 CLI

```bash
idleleo tcp status [--json]
idleleo tcp plan --profile bbr-fq [--json]
idleleo tcp apply --profile bbr-fq --confirm
idleleo tcp rollback
```

- `apply` 在非 TTY 下必须带 `--confirm`；TTY 下也可交互确认。
- 退出码沿用既有分类：`2` 用法/未确认、`6` 权限、`7` 冲突/漂移/锁、`12` 内核不支持。
- `status` 只读；非 Linux 返回 `supported=false` 并说明原因，不伪装成功。

### 2.4 安全门禁

- sandbox root（`--root` 非 `/`）写操作必须存在 `.idleleo-phase01-sandbox` 标记，
  否则 exit 2；防止误把测试路径当生产。
- 目标文件是符号链接、路径含符号链接、目标不是普通文件 → 拒绝。
- 不覆盖没有项目标记的同名文件；不静默接管用户的 sysctl 配置。
- 回退只撤销日志里记录的 key；当前值既不是“我们写的”也不是“旧值”时拒绝覆盖。

## 3. 测试

### 3.1 单元测试（20 项，`GO_EXECUTED`）

`go test ./internal/tcpcfg`，注入式后端（内核读写、文件、锁、权限、故障全部可注入）：

- 非 Linux 只读降级；
- status 扫描源文件、优先级与冲突；
- plan 预览、零写零锁、未知 profile 拒绝；
- apply 创建文件 + 只写两个 key；二次 apply 为 noop；
- 内核不支持 bbr → exit 12 语义；
- 非 root 真实 root 拒绝；
- 只读文件写入失败：内核值不变、journal 清理；
- 部分失败：已写 key 逆序恢复、文件删除、journal 清理；
- 恢复也失败：journal 保留 pending + appliedKeys；
- rollback：恢复旧文件字节/mode/uid/gid、恢复旧内核值、删 journal；
- rollback 拒绝文件漂移、拒绝运行值漂移；
- 无 journal rollback 为 noop；
- pending journal 阻止再次 apply；
- state JSON 损坏 → 数据损坏分类；
- 符号链接目标拒绝。

### 3.2 容器集成（30 项断言，`DOCKER_MOCK_APPLY`）

```bash
bash tests/go-parity/tcp/run_tcp_container.sh \
  "$PWD" "$PWD/tests/go-parity/evidence/tcp-2026-11-08"
```

- `--network=none --read-only`，仓库只读挂载，`/tmp` tmpfs；
- sandbox 内伪造 `/proc/sys`（`cubic bbr` 可用、`cubic` 当前、`fq_codel` 当前）；
- 真实执行 `status/plan/apply/rollback` 与错误路径（未确认、未标记 sandbox、
  外部文件、99-* 覆盖、未知 profile、符号链接）；
- 每次 apply/rollback 后校验 sandbox 的 `/proc/sys` 文件与 journal；
- 对比容器真实 `/proc/sys/net/ipv4/tcp_congestion_control`、
  `/proc/sys/net/core/default_qdisc` 前后值，证明未被改动。

结果：**30 / 30 通过**，证据在
[tests/go-parity/evidence/tcp-2026-11-08](../../tests/go-parity/evidence/tcp-2026-11-08)。

集成过程中发现并修正两个真实问题（均有回归覆盖）：

1. `sysctl.d` 目录被当作“文件”走 write 路径，导致 status/apply 在目录存在时报
   `target is not a regular file`；改为按目录只读解析，目录不存在视为无附加源。
2. `WriteSysctl` 未截断（sandbox 普通文件残留旧字节，回读变成 `fq\n_codel`）。
   改为 `O_WRONLY|O_TRUNC`；真实 procfs 与 shell `>` 行为一致，sandbox 因此可
   准确复现内核写入语义。

## 4. 与 Bash 入口的关系

Bash 的 `-tcp` / 菜单 28 调用 `bbr_boost_sh()`：优先执行 `scripts/tcp.sh`，否则从
`https://raw.githubusercontent.com/ylx2016/Linux-NetSpeed/master/tcp.sh` 下载并执行
（[install.sh 10851–10864](../../install.sh#L10851-L10864)）。该路径无固定哈希、
无回退日志、会改动大量 sysctl 与内核模块。

Go 原生实现**不替换**这个菜单，只提供可审计的安全子集；两者可以共存，
但 Skills 文档与后续迁移应默认走 `idleleo tcp`。详见
[SCRIPT_NATIVE_MIGRATION_MATRIX.md](SCRIPT_NATIVE_MIGRATION_MATRIX.md)。

## 5. 遗留与限制

- 未做 TCP 性能/吞吐验收（需要真实网络与对照实验，且不允许改宿主内核）。
- 未实现 profile 自定义/更多 profile；仅 `bbr-fq`。
- 未处理 `/run/sysctl.d` 与 `/usr/lib/sysctl.d` 的冲突扫描（只在 `/etc` 范围审计；
  这三处优先级低于 `/etc/sysctl.conf`，但可能高于 90-*，后续可按需扩展）。
- 未自动刷新持久化配置到运行态；apply 本身即时写 `/proc/sys`，重启后由 sysctl.d 生效。
- 容器集成是 mock apply，不能替代真实 VPS 内核验收。
