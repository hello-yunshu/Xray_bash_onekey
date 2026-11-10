# 辅助脚本 Go 原生化迁移矩阵（2026-11-08 审计）

> 范围：仓库内 `scripts/*.sh` 14 个，以及 `install.sh` 的 TCP 入口。
> 结论基于源码审读 + 本轮 Phase 01–04 的真实容器行为，不含真实 VPS 验证。
> 判定标签：**已迁移** / **部分迁移** / **保留 Bash（本轮不迁移）** / **出范围（仓库工具）**。

## 1. 总览

| 脚本 | 行数 | 运行时角色 | Go 现状 | 判定 | 风险 |
|---|---:|---|---|---|---|
| `auto_update.sh` | 515 | cron 自动升级 Xray/Nginx/GeoData/统计 | `idleleo schedule`（GeoData/统计 timer）、Go release 自升级；Xray/Nginx 升级仍走 Bash | 部分迁移 | 高：混合升级器；证书/回滚边界复杂 |
| `xray_stats.sh` | 854 | 只读统计 + watch + reset | `idleleo stats`（只读、真实 `xray api statsquery`）；`stats-collect` | 部分迁移 | 中：watch/reset 未迁移 |
| `geo_update.sh` | 244 | GeoData 下载/校验/替换/重启 | `idleleo geodata-refresh` + systemd timer（真实 Xray 验证） | 已迁移（核心） | 低：旧布局迁移未覆盖 |
| `ssl_update.sh` | 237 | ACME 证书续期 + reload | Phase 04 仅实现“外部续约契约”（指纹变化才 reload、未变不重启、私钥可读拒绝 reload、到期降级） | 保留 Bash（无 ACME） | 高：容器无公网域名/CA，不能伪造成已迁移 |
| `fail2ban_manager.sh` | 1249 | Fail2ban jail/trusted/unban | 无 | 保留 Bash | 中：历史差异“不得 `rm -f jail.d/*.local`” |
| `traffic_blocker.sh` | 1393 | 国家/IP 流量阻断、自定义路由 | 无 | 保留 Bash | 高：需规则生成后 `xray -test` |
| `file_manager.sh` | 370 | serverNames/server 文件管理 | 无独立 CLI（部分能力在 `xray generate`） | 保留 Bash | 低 |
| `rill_xray_agent_bootstrap.sh` | 21 | Rill 引导 | 无 | 保留 Bash | 低 |
| `rill_xray_agent_install.sh` | 375 | Rill agent 安装/升级 | Bridge audit/prepare/validate/activate/recover 与 `rill status` | 部分迁移 | 中：安装命令未迁移 |
| `rill_xray_agent_manager.sh` | 1180 | 执行策略/模式/epoch 管理 | 无 | 保留 Bash | 高：权限相关 |
| `rill_xray_agent_uninstall.sh` | 240 | 两阶段卸载 | 无 | 保留 Bash | 中 |
| `rill_xray_agent_verify.sh` | 64 | 静态 + live contract 校验 | 无独立命令；Bridge 的 validate 有重叠 | 保留 Bash | 低 |
| `checkout_external_repo.sh` | 50 | CI 检出外部仓库 | 无 | 出范围 | 无 |
| `merge_checked_pr.sh` | 47 | CI 合并受检 PR | 无 | 出范围 | 无 |
| `tcp.sh`（运行时下载，不在仓库） | — | BBR/加速菜单 | `idleleo tcp status/plan/apply/rollback`（仅 bbr-fq） | 部分迁移（安全子集） | 高：远程无哈希脚本 |

`install.sh` TCP 入口：

| 位置 | 行为 | Go 现状 | 判定 |
|---|---|---|---|
| `install.sh:10851-10864` `bbr_boost_sh` | 有 `scripts/tcp.sh` 就执行；否则从 `raw.githubusercontent.com/ylx2016/Linux-NetSpeed` 下载后执行 | `idleleo tcp ...` 只管理 `/etc/sysctl.d/90-idleleo-tcp.conf`，支持回退与漂移拒绝 | 部分迁移（安全子集，未替换菜单） |
| `install.sh:13384-13387` `-tcp/--tcp` | 调 `bbr_boost_sh` | 同上 | 未接线 |
| `install.sh:15493-15496` 菜单 28 | 调 `bbr_boost_sh` | 同上 | 未接线 |
| `install.sh:13337` `-pt/--port-traffic` | 实时端口流量（iftop） | 无 | 保留 Bash（只读工具） |
| `install.sh:13294-13296` `-c/--clean-logs` | 日志清理 | 无 | 保留 Bash（日志体系不重构） |
| `install.sh:13297-13304` `-cs/-cu/-cau` | 证书状态/手动续期/acme cron | 外部续约契约（F12） | 保留 Bash（无 ACME） |
| `install.sh:3696-3728` 防火墙提示 | 安装时可选 iptables/ip6tables 持久化 | 无 | 保留 Bash（F17/F21 未实现） |
| `install.sh:5925` 起 `network_mode` | IPv4/IPv6/dual 校验与后端选择 | `xray generate` 部分字段 | 部分迁移（无完整双栈事务） |

### 1.1 `tcp.sh` 实际行为审计（D1）

`install.sh` 不携带 `tcp.sh`：`bbr_boost_sh` 优先执行本地 `scripts/tcp.sh`，否则从
`raw.githubusercontent.com/ylx2016/Linux-NetSpeed` 下载并**直接以 root 执行**，
既没有 pin 也没有哈希校验。因此**运行内容不可复现**，这是本项最高风险。

本轮取 2026-11-08 上游快照（SHA-256
`0b7614e7f5b0de93d7bfd790be672c26c54b223b47ec1b1ae5fa2884e2ea61c0`）逐段审读，
证据见 [tcp-upstream-2026-11-08.txt](../../tests/go-parity/evidence/tcp-upstream-2026-11-08.txt)：

| 类别 | 实际行为 | 归属 | 影响面 | 项目级回退 |
|---|---|---|---|---|
| 内核安装 | 下载并 `yum/apt install` BBR/BBRplus/Lotserver/cloud 内核，提示或直接 `reboot` | 上游脚本 | 可能更换引导内核、导致无法启动；无签名/哈希 | 无 |
| 加速切换 | 写 `/etc/sysctl.d/bbr.conf`、`99-sysctl.conf`，`sed -i` 修改 `/etc/sysctl.conf`，执行 `sysctl -p`、`sysctl --system` | 上游脚本 | 覆盖整机 TCP/qdisc/ECN，影响所有服务 | 无 |
| 系统优化 | 重写 `/etc/systemd/system.conf`、`/etc/security/limits.conf`、`/etc/profile`、`/etc/pam.d/common-session`，改透明大页 | 上游脚本 | 登录/服务资源限制、PAM 行为 | 无 |
| 双栈 | 菜单提供禁用/开启 IPv6 | 上游脚本 | 主机网络可达性 | 无 |
| 第三方执行 | `wget \| bash` 安装/卸载 Lotserver，菜单 60 切换到外部 IP 质量脚本 | 上游第三方 | 任意 root 代码执行 | 无 |
| 卸载 | `remove_all`/`remove_bbr_lotserver` 删除加速配置，可能卸载多余内核 | 上游脚本 | 删除系统内核有失联风险 | 无 |

**结论**：Bash 入口是“下载即执行 + 无回退 + 可重启/换内核”的高风险路径；
Go `idleleo tcp` 只覆盖 `bbr-fq` 的单文件、可回退安全子集，**不是行为等价替代**。
D1 的判定为：入口与风险已审计（PASS），但“逐行复现上游行为”因脚本未入库而
**BLOCKED**，不能声明已完整审计某个固定版本。

## 1.2 迁移目标、保留契约与验收

| 脚本 | 目标 Go 入口 | 必须保留的契约 | 优先级 / 验收 |
|---|---|---|---|
| `auto_update.sh` | `idleleo schedule` + 自升级 | 只移除已接管的 cron；Xray/Nginx/证书保留 Bash；失败不删 cron | P1；Phase 04 定时升级 + 失败注入 |
| `xray_stats.sh` | `idleleo stats` | 只读 API、`--json` 原样、非 root exit 5、API down exit 8 | P1；watch/reset 需新增 |
| `geo_update.sh` | `idleleo geodata-refresh` | 双文件校验、原子替换、失败不覆盖旧文件 | P2；真实 Xray 已验证 |
| `ssl_update.sh` | 无（保留 Bash） | 证书指纹变化才 reload；私钥可读拒绝 reload；到期降级 | P0 外部续约契约已验；ACME 仍 BLOCKED |
| `fail2ban_manager.sh` | 无 | 不得 `rm -f jail.d/*.local`；unban/trusted 语义 | P2；需真实 jail 环境 |
| `traffic_blocker.sh` | 无 | 生成规则后必须 `xray -test` | P2；需规则回归 |
| `file_manager.sh` | `xray generate` 子集 | 只改项目自有 serverNames/server 片段 | P2；当前未拆分 |
| `rill_*` | Bridge 状态机 | audit/prepare/validate/activate/recover 可回退；权限/epoch 不变 | P1；install/uninstall 未迁移 |
| `tcp.sh` | `idleleo tcp` | 只写自有文件、只改指定 key、漂移拒绝、可回退 | P1；安全子集已验，菜单未接线 |
| `checkout_external_repo.sh` / `merge_checked_pr.sh` | 无 | CI 工具链不进入运行时 | 出范围；不迁移 |

## 2. 建议的迁移顺序（下一轮）

1. **低风险、已有 Go 原语**：把 `geo_update.sh` 的旧布局迁移补齐，替换 cron 中的
   `geo_update.sh`（`idleleo schedule` 已可用）。
2. **只读补齐**：`xray_stats.sh` 的 `watch` 作为 `idleleo stats --watch`；`reset`
   增加二次确认与事务记录。仍然只读配置。
3. **TCP 接线（可选）**：给 Bash 菜单增加“优先调用 `idleleo tcp`，失败再回退旧路径”
   的显式开关；不得默认执行远程 `tcp.sh`。
4. **Rill**：把 install/uninstall/verify 收敛到 Bridge 状态机；manager 的权限/epoch
   部分最后做，需专门威胁模型。
5. **高复杂、低收益**：`fail2ban_manager.sh`、`traffic_blocker.sh`、
   `auto_update.sh` 的 Xray/Nginx 升级器。建议保持 Bash 直到有真实 VPS 回归环境。

## 3. 共性风险

- **远程脚本无哈希**：`tcp.sh` 是最高风险项；Go 原生实现替代路径已给出，但未默认接线。
- **`/usr` 只读沙箱**：logrotate 的 nginx 日志目录位于 `/usr/local/nginx/logs`，
  受 `ProtectSystem=full` 限制（已由 `ReadWritePaths` drop-in 修复，见
  [DECISIONS.md](DECISIONS.md) D-001）。迁移脚本到 Go 时不得重新引入对 `/usr` 的写。
- **混合升级器**：`auto_update.sh` 同时升级 Xray/Nginx/GeoData/统计；Go 只接管了
  GeoData/统计/自升级，任何“全量接管”都需要先解决证书与回滚。
- **ACME**：`ssl_update.sh` 无法在容器内真实验收，保持 Bash 是当前唯一诚实选择。

## 4. 明确不迁移

- `checkout_external_repo.sh`、`merge_checked_pr.sh`、`scripts/*.py`（release/CI 工具）
  不属于运行时路径，保留在仓库工具链。
