# Go 迁移线决策记录

## 工作约定（用户授权，2026-11-07）

Go 迁移相关工作中，**不需要用户参与排版与细节决策**。技术选型、命名、目录结构、
文档排版、补丁取舍、测试组织、提交拆分、报告格式等，由执行者自行判断并当场决定，
把决策与理由记录在本文件，不因这些细节回头征询用户。

仅在以下情况暂停并征询用户：

1. 对外发布、打 tag、合并 main；
2. 需要用户提供凭据；
3. 真实设备 / 真实 VPS 的写操作或重启服务；
4. 不可逆且有数据风险的操作。

原有约束不变：不伪造结果、不跳过失败断言、未达成项如实标注。真实 VPS 不可用时，
Docker / 容器级证据即满足验证门槛，但必须标注证据等级。

## D-001 logrotate 沙箱修复方式（2026-11-07）

**决定**：保留 nginx 日志目录 `/usr/local/nginx/logs` 不变，在生成
`/etc/logrotate.d/xray_log_cleanup` 时同时写入
`/etc/systemd/system/logrotate.service.d/10-idleleo-readwrite.conf`，内容为
`ReadWritePaths=-${nginx_dir}/logs`，并执行 `systemctl daemon-reload`。

**理由**：
- 搬迁日志目录属于日志体系重构，会破坏用户已有的 nginx 配置、外部采集与权限；
- `ReadWritePaths` 是 systemd 对 `ProtectSystem=full` 的标准例外，改动最小、可逆；
- 与仓库既有 `geodata_sandbox_allows_write` 的沙箱判定思路一致；
- 前缀 `-` 让目录不存在时（纯 Xray 用户）自动忽略，不引入额外失败。

**代价**：依赖 systemd。非 systemd 主机上 `systemctl daemon-reload` 失败被忽略，
行为退回原状，不产生新的硬失败。

## D-002 xray 侧继续使用 copytruncate（2026-11-07）

**决定**：xray 日志段保留 `copytruncate`，不增加 `postrotate`；nginx 日志段保留
`create` + `postrotate` + `nginx -s reopen`。

**理由**：Xray 没有 reopen 信号（SIGHUP 不会重新打开日志），只能就地截断；
nginx 支持 `-s reopen`，用 `create` + 精确属主比 `copytruncate` 更安全。
两个段分开书写，避免 v3.2.8 那种共享块把 xray 语义强加给 nginx。

**注意**：`copytruncate` 与 `create` 在同一段中不并存，因此不存在“二者冲突”；
`copytruncate` 本就不执行 rename，`create` 只对 rename 路径有意义。

## D-003 存量用户生效条件（2026-11-07）

**决定**：不自动改写用户已有的 logrotate 配置；修复只对“重新生成配置”生效。
存量用户需要升级到包含本修复的版本，并重新执行菜单中的「自动清理日志」设置。

**理由**：该配置文件可能被用户手工调整过，静默覆盖会丢失用户意图；把它改成
“每次升级自动重写”属于扩大变更面，本次不做。

## D-004 回归测试组织（2026-11-07）

**决定**：扩展现有 `.github/test/test_log_rotation.sh`，不新建平行测试体系；
真实 `ProtectSystem=full` 场景用特权 systemd 容器中的 `systemd-run` 复现，
输出保存在 `tests/go-parity/evidence/logrotate/`，不放进默认 CI（需要特权容器）。

**理由**：仓库约束优先复用既有测试；systemd 沙箱行为无法用纯 shell 桩可靠模拟，
但错误信息与修复效果可以用真实 systemd 一次性证明并留证。

## D-005 Phase 01 多行 diff 既保留失败又修夹具（2026-11-08）

**决定**：在 `run_phase01.sh` 的 `record()` 里对 `act` 做换行/制表符折叠，保留
完整 diff 文本但不再撑裂 TSV；C12.1/C12.2 仍为 FAIL。

**理由**：多行 `git diff` 被原样写入单行 TSV，导致一行变多行、通过/失败计数虚增
（首次复跑 33/35 但 TSV 只有 34 行）。这是夹具缺陷，不是产品失败；修复只改证据
编码，不改期望、不隐去差异。

## D-006 C12.1/C12.2 保持红色，不改 pin（2026-11-08）

**决定**：`install.sh` 因 logrotate `ReadWritePaths` 修复（`2d44d98`）比已发布
v3.3.6 pin 多 26 行；Phase 01 的这两项继续 FAIL，pin 指向发布的 `0fa7052e` 不变。

**理由**：改 pin 会把“未发布的产品改动”伪装成“与发布版一致”；C12 的价值正是
暴露这种差异。等下一次正式发版后再同步 pin，届时两项会自然转绿。

## D-007 TCP 原生化实现边界（2026-11-08）

**决定**：
- 只管理 `/etc/sysctl.d/90-idleleo-tcp.conf` 一个文件，只做 `bbr-fq` 一个 profile；
- journal 先写后改，pending 标记阻断半事务再次 apply；
- 只写指定 key 到 `/proc/sys`，不重放 `sysctl --system`；
- `WriteSysctl` 使用 `O_WRONLY|O_TRUNC`（与 shell `>` 一致，sandbox 可复现 procfs 语义）；
- 回退只撤销 journal 记录的 key，第三方漂移一律拒绝；
- 锁使用独立 `run/lock/idleleo-tcp.lock`，与配置更新锁分离。

**理由**：满足“安全、轻量、可回退”，把变更面压到最小；见
[TCP_NATIVE_DESIGN_AND_QA.md](TCP_NATIVE_DESIGN_AND_QA.md)。

## D-008 Docker 只做 sandbox mock apply（2026-11-08）

**决定**：容器内 apply/rollback 通过 `--root <sandbox>` 重定向到一次性目录，
伪造 `/proc/sys` 与 marker；不写 Docker VM 内核。证据标签固定为
`DOCKER_MOCK_APPLY`，不写成宿主内核验收或性能验收。

**理由**：写容器内核会污染共享 VM，且无法证明真实 VPS 行为；sandbox 能完整验证
文件/事务/回退/漂移逻辑，同时用前后哈希证明真实 `/proc/sys` 未变。

## D-009 辅助脚本迁移取舍（2026-11-08）

**决定**：本轮只把已有 Go 原语的部分标注为已迁移/部分迁移；`ssl_update.sh`、
`fail2ban_manager.sh`、`traffic_blocker.sh`、`auto_update.sh` 的 Xray/Nginx 升级器、
Rill 安装/卸载保持 Bash。TCP 的 Bash 菜单不默认接线到 Go，只提供可审计的替代入口。

**理由**：这些脚本涉及 ACME、防火墙、权限/epoch 或混合升级器，缺少真实验证环境时
强行迁移会制造“看起来迁移了”的假象；详见
[SCRIPT_NATIVE_MIGRATION_MATRIX.md](SCRIPT_NATIVE_MIGRATION_MATRIX.md)。

## D-010 部署回滚补齐属主/链接/父目录；跨进程恢复仍不实现（2026-11-08）

**决定**：
- `internal/deploy` 的文件快照扩展为 `uid/gid/link/exists/missingDirs`，回滚恢复
  mode、属主、符号链接与父目录副作用；新装失败显式 `stop + disable`，移除 unit 后
  `daemon-reload` 并校验 `is-enabled`。
- **不**在本轮给 `deploy` 增加持久 journal/lock；`SIGKILL`/容器重启后的跨进程
  安装事务仍不在支持范围，报告与附录明确标为 P0 缺口。

**理由**：属主/链接/父目录是已复现的真实缺陷，可小范围修复并有 root:xray 0640
回归；跨进程恢复需要持久 snapshots 与恢复入口设计，风险与验证成本远高于本轮，
不能在没有真实故障环境的情况下草率加入。

## D-011 `tcp.sh` 只审计入口与风险，不承诺固定版本逐行等价（2026-11-08）

**决定**：`install.sh` 的 `bbr_boost_sh` 会优先执行本地 `scripts/tcp.sh`，否则
下载上游 Linux-NetSpeed 脚本并直接以 root 执行，无 pin、无哈希。本轮取
2026-11-08 快照（SHA-256 `0b7614e7…2ea61c0`）逐类审计内核安装/reboot、
`sysctl.conf` 改写、systemd/PAM/profile、IPv6、远程 lotServer 与内核卸载，
证据落盘 `tests/go-parity/evidence/tcp-upstream-2026-11-08.txt`。

**理由**：上游脚本不在仓库，无法证明“任意时刻下载到的内容”逐行等价；只能审计
入口与已知快照。Go 只实现 `bbr-fq` 安全子集，不移植 `wget | bash`。

## D-012 矩阵 after-fix 证据必须在真实 commit 重跑（2026-11-08）

**决定**：复检发现旧 `after-fix/environment.txt` 记录 `repo_commit=7b15c83…`，
该对象不存在于仓库。改为在真实 HEAD `ace4a16` 上用仓库修正版
`tests/go-parity/matrix/run_matrix.py`（bind-mount 覆盖缓存镜像内构建时烤入的旧
副本）重跑，状态仍为 `54/32/8/4`，替换 summary/environment；缓存镜像旧脚本的
`13/32/44/5/4` 结果明确标注不得作为证据。

**理由**：证据必须可追溯到真实提交；缓存镜像不会自动更新 `COPY` 进去的脚本，
直接运行会得到假阴性。以后矩阵复跑必须显式 bind-mount 仓库脚本或重建镜像。
