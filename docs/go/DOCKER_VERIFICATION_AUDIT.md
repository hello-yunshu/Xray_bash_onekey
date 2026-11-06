# Docker 真实设备验证能力与边界审计

> Phase 01 前置审计。目的：明确 Docker 容器能提供什么级别的证据、缺什么条件，
> 防止把容器级结果写成“真实 VPS 已验证”。日期：2026-11-06。
> 本机引擎：Docker 29.8.2，`linux/arm64`（Docker Desktop LinuxKit 内核）。

## 0. 用户授权决议（2026-11-06，用户明确授权）

用户明确授权：**真实 VPS 不再作为本轮（Phase 01/02 及后续可执行阶段）的阻塞项，用 Docker 代替即可。**

由此形成以下固定口径，全仓文档必须一致：

1. 出口门槛中原本要求“真实公网 VPS / 真实 ACME / 宿主 systemd”的项，
   改为 **`CONTAINER_VERIFIED` 即视为该门槛满足**。
2. `REAL_VPS_VERIFIED` 仍然保留为**更高等级**（真实公网 VPS、真实 DNS、真实 CA、
   重启后复验），但**不再要求必须达到**；不得因为门槛放宽而删除这一等级定义。
3. **证据等级标签必须如实保留**。容器结果只能写“容器级证据（`CONTAINER_VERIFIED`，
   镜像 digest …）”，**不得写成“真实 VPS 已验证”**。
4. **真实 ACME 签发/续期**在容器内无法完成（无公网域名控制权、无真实 CA、无法完成
   HTTP-01/DNS-01 公网验证），本轮**降级为“不纳入本轮验收”**，并保留原因说明；
   不得伪造签发结果，也不得用 Pebble 结果冒充真实 ACME。
5. 本决议只改变“是否阻塞”，不改变“证据等级”；任何 F 项要从“未实现/部分实现”
   升级为“已验证”，仍必须有可重复的真实运行证据（容器级即可）与行为差分记录。

## 1. 结论

Docker 可以承担 Phase 01 的**逻辑、CLI、文件事务、服务状态语义和构建**验证，
前提是固定镜像 digest、记录特权/网络/挂载条件，并如实标注为 **容器级证据**。
Docker **不能**替代真实公网 VPS、公共 CA 证书签发、宿主内核/硬件与长期稳定性验证。

判定等级固定为四级，任何情况下不得跨级升格：

| 等级 | 含义 | 可用于本轮退出门禁 |
|---|---|---|
| `REAL_VPS_VERIFIED` | 真实公网 VPS、真实 DNS、真实 CA、重启后复验 | 是（更高等级，**不再强制**） |
| `CONTAINER_VERIFIED` | 固定 digest 的 Linux 容器内真实执行，记录条件/命令/输出 | **是**（按 2026-11-06 用户授权，满足门槛） |
| `SIMULATED` | Pebble/假 systemctl/假 CA/合成样本 | 仅限失败注入与负向测试 |
| `UNVERIFIED` | 未执行或无证据 | 必须保持未验证 |

## 2. 能验证什么（容器级）

| 能力 | 镜像（digest 固定） | 必要条件 | 判定与边界 |
|---|---|---|---|
| CLI/纯查询零写入零网络（C01–C04、C10） | `ubuntu:24.04`（`sha256:fe81560990fae86dc4743202b2cb4d3df98d0bcf949173cecef15ce1127ef852`）、`debian:12`（`sha256:268fb24c39bca92d326dd83ea3abebe4a3f7751c804ffef23bb6d857dd343ff8`） | 普通容器即可；断网用 `--network=none`；对 `/etc`、`/var`、HOME 做执行前后 SHA 快照；非 root 用 `--user` | `CONTAINER_VERIFIED`；只证明容器文件系统与进程行为 |
| 安全文件变更/事务/故障注入（C05–C09） | `ubuntu:24.04`、`debian:12` | 可写测试目录；注入校验失败、写失败、服务失败、外部漂移；不需要特权 | `CONTAINER_VERIFIED`；不得把容器内 `/run` 当成宿主锁语义 |
| systemd 单元 `User=`、active/enabled、停止状态尊重 | 自建 `idleleo-phase02-test:24.04`（ubuntu:24.04 + systemd/dbus/python3/curl；本次 image ID `sha256:b2971f8e8a220e23d1b9b36c63def57595144826ae1b4d745368f09754c4b8f4`） | `--privileged`、`--cgroupns=host`、`-v /sys/fs/cgroup:/sys/fs/cgroup:rw`、PID1=`/usr/lib/systemd/systemd`（基础镜像无 `/sbin/init`） | 已实测 `systemctl is-system-running` = `running`；`User=xray`、`is-active`/`is-enabled`、uninstall 后 `inactive` 均通过；`CONTAINER_VERIFIED`（仅容器 systemd）；不证明宿主 init/其它单元 |
| 服务启动失败与回滚 | 同上 + 可注入退出码的服务钩子 | 容器级 systemd 或可注入退出码的假服务 | 已实测 `service-fail` 回滚原字节（exit 9）且 journal = `ROLLED_BACK`；`CONTAINER_VERIFIED`（失败语义） |
| Relay + Nginx Stream 语法 | `nginx:1.27`（`sha256:6784fb0834aa7dbbe12e3d7471e69c290df3e6ba810dc38b34ae33d3c1c05f7d`） | 片段需 `events {}` 包装并在主上下文 `include`；只读挂载；建立 Docker 网络与后端 | 已实测 TLS/stream 片段 `syntax is ok`；并在真实容器网络内把 `PING` 经 stream 转发回显；`CONTAINER_VERIFIED`（语法 + TCP 字节，不含真实落地 VPS 链路） |
| 完整 fresh install E2E | `idleleo-phase02-test:24.04` | root、systemd、真实 Xray 二进制、独立 Docker 网络 | 已实测 Phase 02 E2E **36/36**（install/uninstall/reinstall/purge/事务/生成矩阵/GeoData）；`CONTAINER_VERIFIED`，不是真实 VPS |
| GeoData 原生两次完整刷新 | `idleleo-phase02-test:24.04` + 真实 Xray 26.10.31 + 本地 `nginx:1.27` HTTPS/2 origin | 联网或本地 HTTPS origin；记录两次 SHA/日志/失败恢复 | 已实测两轮“破坏→下载→替换→重载”：`16475156B`（源 `16475153B` + 3B Lua guard），两轮均恢复；`CONTAINER_VERIFIED`；不证明公网 CDN 长期可用 |
| Xray reload/重启与 Stats API | `idleleo-phase02-test:24.04` + 真实 Xray 26.10.31 | 真实二进制、loopback API；systemd | 已实测 Reality 服务重启后客户端经隧道取回 `http://example.com/` 577 字节（含 `Example Domain`）；`CONTAINER_VERIFIED`（容器内真实数据面） |
| 卸载/重装事务 | `idleleo-phase02-test:24.04` | 文件快照与真实容器服务；容器重建用于“重装” | 已实测卸载保留配置、`--keep-config` 重装后自定义 DNS 逐字节保留；`CONTAINER_VERIFIED`；不能证明宿主重启持久性 |
| amd64/arm64 构建（C11） | `golang:1.24` 或宿主 Go | `GOOS=linux GOARCH=amd64/arm64` 交叉编译 | 构建为 `CONTAINER_VERIFIED`/本地构建证据；执行仅在匹配架构，QEMU 结果不计性能 |
| Phase 01 C01–C12 + native L0 | `idleleo-phase01-test:1.24`（base `golang:1.24@sha256:d2d2bc1c84f7e60d7d2438a3836ae7d0c847f4888464e7ec9ba3a1339a1ee804`；本次 image ID `sha256:8af4eaa68338d882c32104e30d347f575f5c23730c6249fb82b78bebd3bab6c5`） | `--network=none`、容器 root、挂载仓库；C06.real 额外只读挂载固定 Xray 二进制；不需要特权 | 已实测 C01–C12 **35/35**（含真实 `xray -test` 校验器）与 native L0 **83/83**；`CONTAINER_VERIFIED` |
| ACME 客户端状态机（非签发） | `ubuntu:24.04` + Pebble 本地测试 CA | 仅本地测试 CA 与 HTTP-01/DNS-01 流程 | `SIMULATED`，不得称为真实 ACME |
| SELinux/limits 写入顺序 | `quay.io/centos/centos:stream10` | 容器内可读写配置；宿主策略不生效 | 只能验证“写了什么、顺序/回滚”，策略效果 `UNVERIFIED` |

## 3. 不能验证什么

> 按 2026-11-06 用户授权，下表的“不能验证”项**不再阻塞本轮验收**；
> 它们的证据等级保持为 `UNVERIFIED` / 容器级，仅在报告中如实标注。
> 真实 ACME 属于**明确降级为“不纳入本轮验收”**的项，理由见第 0 节第 4 条。

| 不能验证 | 原因 | 对应未验证项 |
|---|---|---|
| 真实公网 VPS 网络、DNS 解析/传播、云安全组/防火墙 | Docker 端口与 DNS 由宿主/引擎管理，无公网入口 | F17、F12、发布路径 |
| 公共 CA 真实签发、域名验证、OCSP/CT | 容器内无公网域名控制权；Pebble 只是测试 CA | F12 |
| 真实证书续期与生产 ACME 限流 | 同上 | F12 |
| 目标发行版内核/驱动/硬件差异 | Docker Desktop 共享 LinuxKit 内核，非目标 VPS 内核 | F17、F25 |
| 宿主已有 systemd/cron/iptables/其它软件的资源竞争 | 容器隔离，宿主单元不可见 | F14、F20、F11 |
| 重启持久化、长时间稳定性、内存泄漏 | 容器销毁即丢失；无法等待小时/天级 | 全局 |
| SELinux enforcing / 宿主 AppArmor 实际拒绝 | 容器通常不启用宿主策略 | F20、D2 |
| 真实客户端跨境/审查环境连通性 | 无真实 ISP/审查链路 | F01–F05 |
| 真实磁盘 IO/CPU/内存压力特征 | 宿主虚拟化与共享资源 | F25 |

## 4. 判定口径（写报告时必须遵守）

1. 每条容器证据记录：镜像 **digest**、容器架构、`--privileged`/`--cgroupns`/`--network`/挂载、
   完整命令、退出码、stdout/stderr 摘要、执行前后关键路径 SHA。
2. 只有 `REAL_VPS_VERIFIED` 才能写“真实 VPS 已验证”；容器结果一律写
   “容器级证据（`CONTAINER_VERIFIED`，镜像 digest …）”。按第 0 节授权，
   `CONTAINER_VERIFIED` 满足本轮出口门槛，但不改变上述写法。
3. `SIMULATED` 只能用于失败注入/负向测试，不能计入正向业务验收。
4. 同一能力在多个发行版容器通过，仍只是“多发行版容器级”，不是“全发行版真机”。
5. 未执行、无输出、只有静态推断的项，保持 `UNVERIFIED`。
6. 真实 ACME 签发/续期不纳入本轮验收（原因见第 0 节）；任何“证书续期已通过”的表述
   都不得出现在本轮报告中。

## 5. Phase 01 用例映射

| 用例 | Docker 可验证性 | 计划 |
|---|---|---|
| C01 断网 `--help/version/status` | 是（`--network=none` + 零写入快照） | 容器级 |
| C02 无 TTY/EOF/TERM=dumb | 是（`docker run -i` 关闭 TTY） | 容器级 |
| C03 未安装/损坏 manager.json | 是（挂载样本） | 容器级 |
| C04 自定义 routing/DNS/outbounds | 是（真实 Bash 样本 + SHA 不变） | 容器级 |
| C05 外部漂移 | 是（执行中改写文件） | 容器级 |
| C06 校验器非零 | 是（注入假校验器） | 容器级 |
| C07 写失败/权限失败 | 是（只读目录 / 非 root） | 容器级 |
| C08 服务启动失败 | 是（假服务；可选容器 systemd） | 容器级 |
| C09 并发修改 | 是（两个进程竞争同一锁） | 容器级 |
| C10 非 root 查询/非法命令 | 是（`--user`） | 容器级 |
| C11 amd64/arm64 构建 | 是（交叉编译） | 构建证据 |
| C12 旧 Bash 入口未变 | 是（仓库 diff + 容器内运行旧入口只读命令） | 容器级 + 静态核对 |

## 6. 本次审计已执行的事实

| 检查 | 命令 | 结果 |
|---|---|---|
| 镜像可用性 | `docker pull debian:12`、`ubuntu:24.04`、`nginx:1.27` | 成功；digest 见上表 |
| Relay 片段语法 | `nginx:1.27` + `events {}` + `include /fx/relay-stream.conf` | `syntax is ok`，`test is successful` |
| 基础镜像 systemd | `debian:12`、`centos:stream10` 检查 `/sbin/init` | 不存在；需派生镜像 |
| 派生 systemd 镜像 | `idleleo-systemd-probe:24.04` + `--privileged --cgroupns=host -v /sys/fs/cgroup:/sys/fs/cgroup:rw` | `systemctl is-system-running` = `running` |
| 宿主架构 | `docker version` | `linux/arm64`；amd64 运行依赖模拟，不作性能/稳定性证据 |
| Phase 01 E2E（C01–C12） | `idleleo-phase01-test:1.24` + `--network=none`；`IDLELEO_XRAY_BIN=/tmp/xray-bin/xray bash tests/go-parity/phase01/run_phase01_container.sh` | **35/35**；C09/C10.1/C12.3 修复后通过；含真实 Xray 校验器事务（C06.real） |
| Phase 01 native L0 | 同一镜像 + 干净 `HEAD=3b2671b` checkout + `--require-native-l0` | `LIVE_PINNED_CLEAN: 83/83 MATCH; SOURCE_BUILT_NATIVE_GO_L0; native_l0_only=true` |
| 真实 Xray 校验旧样本 | `Xray 25.9.11`（`sha256:21cfc33f…0908`，linux/arm64）`-test` 对 `reality-direct`、`tls-multi`、`custom-dns-routing` | 三例均 `Configuration OK.`（rc=0）；`CONTAINER_VERIFIED` |
| Phase 02 fresh install E2E | `idleleo-phase02-test:24.04` + `--privileged --cgroupns=host`；`GO=/tmp/gotoolchain/go/bin/go bash tests/go-parity/phase02/run_phase02_container.sh` | **36 passed, 0 failed**；systemd `running`、`User=xray`、Reality 数据面 577B、事务回滚、purge、GeoData 双周期 |
| Phase 02 Relay TCP | `bash tests/go-parity/phase02/run_relay_nginx.sh` | TLS/stream `nginx -t` 通过；`PING` 经 Nginx stream 回显；`CONTAINER_VERIFIED` |
| Phase 02 GeoData 双周期 | 本地 `nginx:1.27` HTTPS/2 origin + Xray 26.10.31 `cron` | 两轮均从 18B 恢复为 `16475156B`（源 + 3B guard） |
| Phase 02 回归 | `IDLELEO_XRAY_BIN=/tmp/xray-26/xray bash tests/go-parity/phase01/run_phase01_container.sh` | **35/35**；metadata 指纹刷新未破坏 Phase 01 |

## 7. 约束

- `--privileged` 仅用于一次性、无宿主敏感挂载的 systemd/iptables 探针；
  普通 CLI/事务测试不得使用特权。
- 不把容器内 `/tmp`、`/run` 的锁行为当成宿主并发语义的完整证明。
- 本审计不改变 Phase 00 的 `CONDITIONAL GO` 结论。
