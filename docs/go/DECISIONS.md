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
